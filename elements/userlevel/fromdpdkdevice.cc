// -*- c-basic-offset: 4; related-file-name: "fromdpdkdevice.hh" -*-
/*
 * fromdpdkdevice.{cc,hh} -- element reads packets live from network via
 * the DPDK. Configures DPDK-based NICs via DPDK's Flow API.
 *
 * Copyright (c) 2014-2015 Cyril Soldani, University of Liège
 * Copyright (c) 2016-2017 Tom Barbette, University of Liège
 * Copyright (c) 2017 Georgios Katsikas, RISE SICS
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.

 */

#include <unistd.h>
#include <click/config.h>

#include <click/args.hh>
#include <click/error.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/etheraddress.hh>
#include <click/straccum.hh>
#include <click/dpdk_glue.hh>

#include "fromdpdkdevice.hh"
#include "tscclock.hh"
#include "todpdkdevice.hh"
#include <click/dpdk_glue.hh>
#include <click/json.hh>

#include <sys/ioctl.h>

#define RX_BATCH_LATENCY_HISTORY_LENGTH 100
#define RX_BATCH_LATENCY_USED 10
#define RX_BATCH_LATENCY_INTERVAL 100

#define RX_CYCLES_STATS 1

//#define debug(...) click_chatter(__VA_ARGS__)
#define debug(...)

struct rx_batch_latency_counter {
    /* Latencies history, used as a ringbuffer*/
    uint64_t latencies[RX_BATCH_LATENCY_HISTORY_LENGTH];
    /* Index of last item in buffer */
    uint32_t lat_index;
    /* Polling counter, reset to 0 each RX_BATCH_LATENCY_INTERVAL.*/
    uint32_t poll_counter;
    /* Tells wether the core should receive packets from RSS or not*/
    int8_t activated;

    uint32_t over_burst;
    uint64_t consecutive_over_burst; //Using shifting to avoid a special case going below zero
    uint64_t last_packet_epoch;

    /* Measure idleness for Duneish*/
    uint64_t idle_pollings_since_woke_up;
    uint64_t polling_since_woke_up;
} __rte_cache_aligned;

#define RX_STATS_MEASUREMENTS_INTERVAL 1000
#define RX_STATS_BURST_SIZES 128
#if RX_CYCLES_STATS > 1
#define RX_STATS_RDTSC_BIT_OFFSET 12
#define RX_STATS_RDTSC_VALUES 10000000
#endif

struct rx_batch_latency_stats_counter {
    /* Variable telling wether the warmed up is finished */
    uint8_t warmed_up;
    /* Total number of pollings*/
    uint64_t warmup_pollings;
    /* Polling counter after warmup*/
    uint64_t pollings;
    /* Busy polling counter*/
    uint64_t busy_pollings;
    /** Polling history */
    #if RX_CYCLES_STATS > 1
    uint64_t rdtsc_values[RX_STATS_RDTSC_VALUES];
    #endif
    uint64_t last_rdtsc;

    /** Burst history */
    uint64_t burst_sizes[128];
} __rte_cache_aligned;

double decay = 0.25;
double weights[RX_BATCH_LATENCY_INTERVAL];
double current_throughput;
uint16_t disabled_queues_sleeping_time_ms = 5;
uint8_t applying_penalty = 0;
double penalty = 1;
double lat_penalty = 0;
uint64_t sloth_epoch = 0;
double sloth_last_mpps = 0;

Semaphore wait_cores;

#if HAVE_FLOW_API
    #include <click/flowrulemanager.hh>
#endif

#if RTE_VERSION >= RTE_VERSION_NUM(22,07,0,0)
#define DEV_RX_OFFLOAD_IPV4_CKSUM RTE_ETH_RX_OFFLOAD_IPV4_CKSUM
#define DEV_RX_OFFLOAD_TCP_CKSUM RTE_ETH_RX_OFFLOAD_TCP_CKSUM
#define DEV_RX_OFFLOAD_UDP_CKSUM RTE_ETH_RX_OFFLOAD_UDP_CKSUM
#define DEV_RX_OFFLOAD_TIMESTAMP RTE_ETH_RX_OFFLOAD_TIMESTAMP
#define ETH_LINK_FULL_DUPLEX RTE_ETH_LINK_FULL_DUPLEX
#endif

CLICK_DECLS

#define LOAD_UNIT 10

static inline void hr_sleep(long time){
	asm("mov %%rbx, %%rdi ; syscall " :  : "a" ((unsigned long)(134)) , "b" (time));
}



static inline int trylock(void * uadr){
        unsigned long r =0 ;
        asm volatile(
                        "xor %%rax,%%rax\n"
                        "mov $1,%%rbx\n"
                        "lock cmpxchg %%rbx,(%1)\n"
                        "sete (%0)\n"
                        : : "r"(&r),"r" (uadr)
                        : "%rax","%rbx"
                    );
        asm volatile("" ::: "memory");
        return (r) ? 1 : 0;
}


uint64_t last_packets = 0;
uint64_t last_missed = 0;
uint64_t last_bytes = 0;
uint64_t last_mpps = 0;
Timer* sloth_timer;
uint16_t sloth_port;
int expected_latency_us;
String sloth_optimums_filename;
uint16_t sloth_min_freq;
double sloth_scale;
uint8_t sloth_enable_penalty;
uint8_t sloth_penalty_warmup;
uint64_t sloth_max_consecutive;
int current_latency_us;
uint16_t start_core;
uint16_t end_core;
uint16_t queue_start;
uint16_t queue_end;
struct rte_eth_rss_conf _rss_conf;
int number_of_queues;
uint16_t current_cores = 0;
uint64_t current_freq=1000;
uint16_t current_priority;
unsigned duneish_cores_threshold;
unsigned duneish_frequency_threshold;
unsigned duneish_frequency_step;
unsigned max_frequency;
unsigned min_frequency;
uint8_t apply_prctl;
struct rte_flow *current_flow;


FromDPDKDevice::FromDPDKDevice() :
    _dev(0), _tco(false), _uco(false), _ipco(false)
{
#if HAVE_BATCH
    in_batch_mode = BATCH_MODE_YES;
#endif
    _burst = 32;
    ndesc = 0;
}


void** rx_batch_latency_counters;
uint8_t* queues_set_up;
int max_throughput = 0;

FromDPDKDevice::~FromDPDKDevice()
{
}

int FromDPDKDevice::configure(Vector<String> &conf, ErrorHandler *errh) {
    //Default parameters
    int numa_node = 0;
    int minqueues = 1;
    int maxqueues = 128;
    String dev;
    EtherAddress mac;
    uint16_t mtu = 0;
    bool has_mac = false;
    bool has_mtu = false;
    bool set_timestamp = false;
    FlowControlMode fc_mode(FC_UNSET);
    String mode = "";
    int num_pools = 0;
    Vector<int> vf_vlan;
    int max_rss = 0;
    int reta_size = 0;
    bool has_rss = false;
    bool has_reta_size;
    bool flow_isolate = false;
    unsigned sleep_delta;
    unsigned sleep_max;
    unsigned suspend_threshold;
    String sleep_mode;
    int sloth_max_consecutive_packets;
    uint16_t power_pause_duration = 0;
    uint16_t power_max_empty_poll = 0;
#if HAVE_FLOW_API
    String flow_rules_filename;
#endif
    if (Args(this, errh).bind(conf)
        .read_mp("PORT", dev)
        .consume() < 0)
        return -1;

    if (parse(conf, errh) != 0)
        return -1;

    if (Args(conf, this, errh)
        .read("NDESC", ndesc)
        .read("MAC", mac).read_status(has_mac)
        .read("MTU", mtu).read_status(has_mtu)
        .read("MODE", mode)
        .read("FLOW_ISOLATE", flow_isolate)
    #if HAVE_FLOW_API
        .read("FLOW_RULES_FILE", flow_rules_filename)
    #endif
        .read("VF_POOLS", num_pools)
        .read_all("VF_VLAN", vf_vlan)
        .read("MINQUEUES",minqueues)
        .read("MAXQUEUES",maxqueues)
        .read("MAX_RSS", max_rss).read_status(has_rss)
        .read("RETA_SIZE", reta_size).read_status(has_reta_size)
        .read("TIMESTAMP", set_timestamp)
        .read_or_set("RSS_AGGREGATE", _set_rss_aggregate, false)
        .read_or_set("PAINT_QUEUE", _set_paint_anno, false)
        .read_or_set("BURST", _burst, 32)
        .read_or_set("CLEAR", _clear, false)
        .read_or_set("SLEEP_MODE", sleep_mode, "no_sleep")
	.read_or_set("SLEEP_DELTA", sleep_delta, 2)
        .read_or_set("SLEEP_MAX", sleep_max, 256)
        .read_or_set("SUSPEND_THRESHOLD", suspend_threshold, 256)
        .read_or_set("SLOTH_LAT",expected_latency_us,40)
        .read_or_set("SLOTH_OPTIMUMS", sloth_optimums_filename, "/root/fastclick-sleepmodes/throughput_table.csv")
        .read_or_set("SLOTH_SCALE", sloth_scale, 1.0)
        .read_or_set("SLOTH_PENALTY", sloth_enable_penalty, 1)
	.read_or_set("SLOTH_MAX_CONSECUTIVE", sloth_max_consecutive_packets, 1024)
        .read_or_set("SLOTH_MIN_MHZ", sloth_min_freq, 1000)
	.read_or_set("SLOTH_PENALTY_WARMUP", sloth_penalty_warmup, 10)
        .read_or_set("DUNEISH_CORE_THRESHOLD", duneish_cores_threshold, 100000)
        .read_or_set("DUNEISH_FREQ_THRESHOLD", duneish_frequency_threshold, 500000)
        .read_or_set("DUNEISH_FREQ_STEP", duneish_frequency_step, 500)
        .read_or_set("MAX_FREQUENCY", max_frequency, 3000)
        .read_or_set("MIN_FREQUENCY", min_frequency, 800)
        .read_or_set("POWER_PAUSE_DURATION", power_pause_duration, 1000)
        .read_or_set("POWER_MAX_EMPTY_POLL", power_max_empty_poll, 10)
	.read_or_set("PRCTL", apply_prctl, 1)
        .read("PAUSE", fc_mode)
#if RTE_VERSION >= RTE_VERSION_NUM(18,02,0,0)
        .read("IPCO", _ipco)
        .read("TCO", _tco)
        .read("UCO", _uco)
#endif
        .complete() < 0)
        return -1;

    if (!DPDKDeviceArg::parse(dev, _dev)) {
        if (allow_nonexistent)
            return 0;
        else
            return errh->error("%s: Unknown or invalid PORT", dev.c_str());
    }
	int ret;
	if (apply_prctl){
	    click_chatter("Reducing PRCTL to minimal value\n");
	    // Minimal value is 1, 0 sets to default
	    ret = prctl(PR_SET_TIMERSLACK, 1, 0, 0, 0);
	} else {
	    click_chatter("Setting PRCTL to default value\n");
	    ret = prctl(PR_SET_TIMERSLACK, 0, 0, 0, 0);
	}

    if (ret < 0) {
	click_chatter("Error setting PRCTL : %d\n", ret);
        return -1;
    } else {
	ret = prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0);
        if (ret == -1) {
            perror("prctl(PR_GET_TIMERSLACK) failed");
            return -1;
        }
        unsigned long timerslack_ns = (unsigned long)ret;
        printf("Current timer slack: %lu ns\n", timerslack_ns);
    }
    sloth_max_consecutive = ((uint64_t)1) << (sloth_max_consecutive_packets / _burst);
    click_chatter("Max consecutive is %d -> mask %lu", sloth_max_consecutive_packets / _burst, sloth_max_consecutive);
    number_of_queues = maxqueues;
    click_chatter("Max queues %d", number_of_queues);
    _sleep_mode = 0;
    _sleep_delta = sleep_delta;
    _sloth_optimums_path = sloth_optimums_filename;
    current_freq = min_frequency;
    _sleep_reset = 1;
    _sleep_max = sleep_max;
    _suspend_threshold = suspend_threshold;
    if (_suspend_threshold > sleep_max)
        return errh->error("Suspend threshold must be <= sleep max");

    click_chatter("Sleep max %d/threshold %d", _sleep_max, _suspend_threshold);
    if (sleep_mode != "no_sleep") {
        if (sleep_mode.find_left("mult") != -1) {
            _sleep_mode |= SLEEP_MULT;
            if (_sleep_delta <= 1)
                return errh->error("Mult does not make sense with a sleep_delta smaller than 2");
            click_chatter("Sleep mode : Mult");
        } else if (sleep_mode.find_left("add") != -1) {
            _sleep_mode |= SLEEP_ADD;
            if (_sleep_delta <= 0)
                return errh->error("Add sleep mode must have a delta bigger than 0, else it's constant.");
            click_chatter("Sleep mode : Add");
        } else if (sleep_mode.find_left("constant") != -1 || sleep_mode.find_left("const") != -1) {
            _sleep_mode |= SLEEP_CST;
            click_chatter("Sleep mode : constant");
        } else if(sleep_mode != "actuallypower" && sleep_mode != "tupe" && sleep_mode != "sloth" && sleep_mode != "duneish") {
            printf("Fucker\n");
            return errh->error("Unknown mode %s", sleep_mode.c_str());
        }


        if (sleep_mode.find_left("hrsleep") != -1) {
            _sleep_mode |= SLEEP_HR;
            click_chatter("Sleep mode of sleep : hrsleep");
        }
        if (sleep_mode.find_left("rtepause") != -1) {
            _sleep_mode |= SLEEP_RTE_PAUSE;
            click_chatter("Sleep mode of sleep : rte_pause");
            if (!(_sleep_mode & SLEEP_CST)){
                return errh->error("RTE Pause does not support anything else than constant");
            }
        }
        if (sleep_mode.find_left("hr2") != -1) {
            _sleep_mode |= SLEEP_HR2;
            click_chatter("Sleep mode of sleep : hr2");
            hr2fd = open("/dev/hrsleep", 0);
            if (hr2fd < 0)
                return errh->error("Could not open /dev/hrsleep");
        }
        if (sleep_mode.find_left("nanosleep") != -1 || sleep_mode.find_left("usleep") != -1) {
            _sleep_mode |= SLEEP_U;
            click_chatter("Sleep mode of sleep : nanosleep");
        }
        if (sleep_mode.find_left("rtesleep") != -1) {
            _sleep_mode |= SLEEP_RTE;
            click_chatter("Sleep mode of sleep : rtesleep");
        }
        if (sleep_mode.find_left("intr") != -1) {
            _sleep_mode |= SLEEP_INTR;
            if (!sleep_mode.find_left("power") && (_sleep_mode & SLEEP_CST))
                return errh->error("Interrupt cannot be constant, we need to hit the threshold. Use add (or mult).");
            click_chatter("Sleep mode of sleep : interrupt");
        }
        if (sleep_mode.find_left("metronome") != -1) {
            _sleep_mode |= SLEEP_POLICY_METRONOME;
            click_chatter("Sleep policy : metronome");
        } else if (sleep_mode.find_left("actuallypower") != -1) {
            _sleep_mode |= SLEEP_POLICY_ACTUALLYPOWER;
            // Surprisingly, this mode doesn't implement any sleep policy,
            // It simply relies on DPDK's power management
            click_chatter("Sleep policy : actuallypower");
       } else if (sleep_mode.find_left("sloth") != -1) {
            _sleep_mode |= SLEEP_POLICY_SLOTH;
            click_chatter("Sleep policy : sloth");
        } else if (sleep_mode.find_left("monitor") != -1) {
            _sleep_mode |= SLEEP_POLICY_MONITOR;
            click_chatter("Sleep policy : monitor");
        } else if (sleep_mode.find_left("tupe") != -1) {
            _sleep_mode |= SLEEP_POLICY_TUPE;
            click_chatter("Sleep policy : tupe");
        } else if (sleep_mode.find_left("power") != -1) {
            _sleep_mode |= SLEEP_POLICY_POWER;
            if (!(_sleep_mode & SLEEP_CST))
                return errh->error("Power does not support anything else than constant");
            click_chatter("Sleep policy : power");
        } else if (sleep_mode.find_left("simple") != -1) {
            _sleep_mode |= SLEEP_POLICY_SIMPLE;
            click_chatter("Sleep policy : simple");
        } else if (sleep_mode.find_left("duneish") != -1) {
            _sleep_mode |= SLEEP_POLICY_DUNEISH;
            click_chatter("Sleep policy : duneish");
        } else {
            return errh->error("Unknown policy %s", sleep_mode.c_str());
        }

        _dev->info.sleep_mode = _sleep_mode;
        _dev->info.power_max_empty_poll = power_max_empty_poll;
        _dev->info.power_pause_duration = power_pause_duration;

        // If a sleep mode is set, maxqueues and minqueues must be equal
        if (minqueues != maxqueues) {
            return errh->error("When using a sleep mode, MINQUEUES and MAXQUEUES must be equal. Metronome synchronisation technique must know exactly how many queues are used.");
        }
        // If interrupts are enabled but no sleep mode is set, trigger an error
        if (_sleep_mode & SLEEP_INTR && !(_sleep_mode & SLEEP_INTR)) {
            return errh->error("Interrupts are enabled but no sleep mode is set. Please set a sleep mode.");
        }
        _nb_queues = minqueues;
        _rx_queue = (struct lcore_rx_queue*)malloc(sizeof(struct lcore_rx_queue) * _nb_queues);
        for (int i = 0; i < _nb_queues; i++) {
            _rx_queue[i].zero_rx_packet_count = 0;
            _rx_queue[i].idle_hint = 0;
            _rx_queue[i].lock = UNLOCKED;
            _rx_queue[i].n_irq_wakeups = 0;
        }
        rte_spinlock_init(&_dev_lock);
        click_chatter("RESULT-SLEEP_VERIFY_MODE %u", _sleep_mode);
    } else {
        _rx_queue = 0;
        click_chatter("No sleep mode");
    }
    if (_use_numa) {
        numa_node = DPDKDevice::get_port_numa_node(_dev->port_id);
        if (_numa_node_override > -1)
            numa_node = _numa_node_override;
    }
    #if RX_CYCLES_STATS
    rx_batch_latency_counters = (void**)rte_zmalloc("rx_batch_latency_counters", sizeof(struct rx_batch_latency_stats_counter*) * number_of_queues, 0);
    queues_set_up = (uint8_t*)rte_zmalloc("queues_set_up", sizeof(uint8_t) * number_of_queues, 0);
    for (int i = 0; i < maxqueues; i++) {
        rx_batch_latency_counters[i] = rte_zmalloc("rx_batch_latency_counter", sizeof(struct rx_batch_latency_stats_counter), 0);
        queues_set_up[i] = 0;
    }
    #endif
    int r;
    if (n_queues == -1) {
        if (firstqueue == -1) {
            firstqueue = 0;
            // With DPDK we'll take as many queues as available threads
            r = configure_rx(numa_node, minqueues, maxqueues, errh);
        } else {
            // If a queue number is set, user probably wants only one queue
            r = configure_rx(numa_node, 1, 1, errh);
        }
    } else {
        if (firstqueue == -1)
            firstqueue = 0;
        r = configure_rx(numa_node, n_queues, n_queues, errh);
    }
    if (r != 0)
        return r;

    if (_sleep_mode & SLEEP_INTR) {
        click_chatter("Enabling interrupts");
        _dev->info.rx_intr_enabled = 1;
    } else {
        click_chatter("Interrupts disabled");
    }

    if (has_mac)
        _dev->set_init_mac(mac);

    if (has_mtu)
        _dev->set_init_mtu(mtu);

    if (fc_mode != FC_UNSET)
        _dev->set_init_fc_mode(fc_mode);

    if (_ipco || _tco || _uco)
        _dev->set_rx_offload(DEV_RX_OFFLOAD_IPV4_CKSUM);
    if (_tco)
        _dev->set_rx_offload(DEV_RX_OFFLOAD_TCP_CKSUM);
    if (_uco)
        _dev->set_rx_offload(DEV_RX_OFFLOAD_UDP_CKSUM);

    if (set_timestamp) {
#if RTE_VERSION >= RTE_VERSION_NUM(18,02,0,0)
        _dev->set_rx_offload(DEV_RX_OFFLOAD_TIMESTAMP);
        _set_timestamp = true;
#else
        errh->error("Hardware timestamping is not supported before DPDK 18.02");
#endif
    } else {
        _set_timestamp = false;
    }

    if (has_rss)
        _dev->set_init_rss_max(max_rss);

    if (has_reta_size)
        _dev->set_init_reta_size(reta_size);

#if RTE_VERSION >= RTE_VERSION_NUM(18,05,0,0)
    _dev->set_init_flow_isolate(flow_isolate);
#else
    if (flow_isolate)
        return errh->error("Flow isolation needs DPDK >= 18.05. Set FLOW_ISOLATE to false");
#endif
#if HAVE_FLOW_API
    if ((mode == FlowRuleManager::DISPATCHING_MODE) && (flow_rules_filename.empty())) {
        errh->warning(
            "DPDK Flow Rule Manager (port %s): FLOW_RULES_FILE is not set, "
            "hence this NIC can only be configured by the handlers",
            dev.c_str()
        );
    }

    r = _dev->set_mode(mode, num_pools, vf_vlan, flow_rules_filename, errh);
#else
    r = _dev->set_mode(mode, num_pools, vf_vlan, errh);
#endif
    click_chatter("Configuration finished\n");
    return r;
}

#if HAVE_DPDK_READ_CLOCK
uint64_t FromDPDKDevice::read_clock(void* thunk) {
    FromDPDKDevice* fd = (FromDPDKDevice*)thunk;
    uint64_t clock;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    if (rte_eth_read_clock(fd->_dev->port_id, &clock) == 0)
        return clock;
#pragma GCC diagnostic pop
    return -1;
}

struct UserClockSource dpdk_clock {
    .get_current_tick = &FromDPDKDevice::read_clock,
    .get_tick_hz = 0,
};
#endif

void* FromDPDKDevice::cast(const char* name) {
	printf("CAST");
#if HAVE_DPDK_READ_CLOCK
    if (String(name) == "UserClockSource")
        return &dpdk_clock;
#endif
    if (String(name) == "EthernetDevice")
        return get_eth_device();
    if (String(name) == "DPDKDevice")
        return _dev;
    return RXQueueDevice::cast(name);
    click_chatter("Configuration finished\n");
}

#define ENABLE_SLOTH_ITERATIVE_INFO 1

struct rte_hash *optimums;
int sloth_hz = 10;
#ifdef ENABLE_SLOTH_ITERATIVE_INFO
int sloth_iterative_counter = 0;
int sloth_elapsed_time = 0;
#endif
#include <rte_hash.h>

struct cpufreq_available_frequencies {
	unsigned long frequency;
	struct cpufreq_available_frequencies *next;
	struct cpufreq_available_frequencies *first;
};

extern "C" {
    int cpufreq_modify_policy_max(unsigned int cpu, unsigned long max_freq);
    struct cpufreq_available_frequencies *cpufreq_get_available_frequencies(unsigned int cpu);
    struct cpufreq_available_frequencies *cpufreq_get_boost_frequencies(unsigned int cpu);
}

struct sloth_optimal_entry {
    uint64_t freq;
    uint8_t cores;
    //enum sleep_mode sleep_mode;
    uint16_t sleep_delta;
    uint8_t watt;
    uint32_t burst;
    float load;
};

inline rte_flow* flow_add_redirect(int port_id, int from, int to, bool validate, int priority = 0) {
    struct rte_flow_attr attr;
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    attr.group = from;
    attr.priority =  priority;

    struct rte_flow_action action[2];
    struct rte_flow_action_jump jump;


    memset(action, 0, sizeof(struct rte_flow_action) * 2);
    action[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
    action[0].conf = &jump;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;
    jump.group=to;

    std::vector<rte_flow_item> pattern;
    rte_flow_item pat;
    pat.type = RTE_FLOW_ITEM_TYPE_ETH;
    pat.spec = 0;
    pat.mask = 0;
    pat.last = 0;
    pattern.push_back(pat);
    rte_flow_item end;
    memset(&end, 0, sizeof(struct rte_flow_item));
    end.type =  RTE_FLOW_ITEM_TYPE_END;
    pattern.push_back(end);

    struct rte_flow_error error;
    int res = 0;
    if (validate)
        res = rte_flow_validate(port_id, &attr, pattern.data(), action, &error);
    if (res == 0) {

        struct rte_flow *flow = rte_flow_create(port_id, &attr, pattern.data(), action, &error);

        click_chatter("Redirect from %d to %d success",from,to);
        return flow;
    } else {
        if (validate) {
            click_chatter("Rule did not validate.");
        }
        return 0;
    }
}

void sloth_create_group_zero() {
    click_chatter("Creating group 0");
    int res;
    // setup group to redirect trafic to group 1
    struct rte_flow_attr attr;
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    attr.group = 0;
    attr.priority = 0;

    struct rte_flow_action action[2];
    struct rte_flow_action_jump jump;

    memset(action, 0, sizeof(action));
    memset(&jump, 0, sizeof(jump));

    // Jump action
    action[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
    jump.group = 1;
    // End action
    action[1].type = RTE_FLOW_ACTION_TYPE_END;


    std::vector<struct rte_flow_item> pattern;
    //Ethernet

    struct rte_flow_item pat;
    pat.type = RTE_FLOW_ITEM_TYPE_ETH;
    pat.spec = 0;
    pat.mask = 0;
    pat.last = 0;
    pattern.push_back(pat);

    pat.type = RTE_FLOW_ITEM_TYPE_IPV4;

    pat.spec = 0;
    pat.mask = 0;

    pat.last = 0;
    pattern.push_back(pat);

    struct rte_flow_item end;
    memset(&end, 0, sizeof(struct rte_flow_item));
    end.type =  RTE_FLOW_ITEM_TYPE_END;
    pattern.push_back(end);
    struct rte_flow_error error;
    res = rte_flow_validate(sloth_port, &attr, pattern.data(), action, &error);
    if (res != 0) {
        click_chatter("ERROR: Could not validate flow err %d, %d, %s", res, rte_errno, rte_strerror(rte_errno));
    }
    // Print error message if validation failed

    current_flow = rte_flow_create(sloth_port, &attr, pattern.data(), action, &error);
    if (current_flow)
        click_chatter("Main group rule added!");
    else {
        click_chatter("ERROR: Could not add main rule err %d, %d, %s", res, rte_errno, rte_strerror(rte_errno));
    }
}

void sloth_add_flow(uint16_t nb_queues){
    // setup RSS to redirect trafic
    struct rte_flow_attr attr;
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    attr.group = 1;
    attr.priority = current_priority;
    
    struct rte_flow_action action[3];
    struct rte_flow_action_mark mark;
    struct rte_flow_action_rss rss;

    memset(action, 0, sizeof(action));
    memset(&rss, 0, sizeof(rss));

    uint16_t queues[128];
    for(uint16_t i=0;i<nb_queues;i++){
        queues[i] = i;
    }
    // Mark action
    action[0].type = RTE_FLOW_ACTION_TYPE_MARK;
    mark.id = 0;
    action[0].conf = &mark;
    // RSS action
    action[1].type = RTE_FLOW_ACTION_TYPE_RSS;
    rss.types = _rss_conf.rss_hf;
    rss.key_len = _rss_conf.rss_key_len;
    rss.queue_num = nb_queues;
    rss.key = _rss_conf.rss_key;
    rss.queue = queues;
    rss.level = 0;
    rss.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
    action[1].conf = &rss;
    // End action
    action[2].type = RTE_FLOW_ACTION_TYPE_END;


    std::vector<struct rte_flow_item> pattern;
    //Ethernet

    struct rte_flow_item pat;
    pat.type = RTE_FLOW_ITEM_TYPE_ETH;
    pat.spec = 0;
    pat.mask = 0;
    pat.last = 0;
    pattern.push_back(pat);

    pat.type = RTE_FLOW_ITEM_TYPE_IPV4;

    pat.spec = 0;
    pat.mask = 0;

    pat.last = 0;
    pattern.push_back(pat);

    struct rte_flow_item end;
    memset(&end, 0, sizeof(struct rte_flow_item));
    end.type =  RTE_FLOW_ITEM_TYPE_END;
    pattern.push_back(end);

    // res = rte_flow_validate(sloth_port, &attr, pattern.data(), action, &error);
    // Print error message if validation failed
    struct rte_flow_error error;
    current_flow = rte_flow_create(sloth_port, &attr, pattern.data(), action, &error);
    if (!current_flow) {
        click_chatter("ERROR Could not add flow %p %d!", current_flow, rte_errno);
       // return 0;
    }
}

void sloth_init_queues_rss(uint16_t nb_queues){
    // Flush flow rules
    struct rte_flow_error error;
    int res = rte_flow_flush(sloth_port, &error);
    if (res < 0) {
        rte_exit(EXIT_FAILURE, error.message);
    }

    click_chatter("Initializing queues RSS with %u on port %u", nb_queues, sloth_port);

    printf("RSS struct init configuration\n");
    _rss_conf.rss_key = (uint8_t*)CLICK_LALLOC(128);
    _rss_conf.rss_key_len = 128; //This is only a max
    if (rte_eth_dev_rss_hash_conf_get(sloth_port, &_rss_conf) != 0) {
        click_chatter("Could not get RSS configuration. Will use a default one.");
        _rss_conf.rss_key_len = 40;
        _rss_conf.rss_hf = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV4_UDP;
        for (int i = 0; i < 40; i++)
            _rss_conf.rss_key[i] = click_random();
    } else {
        printf("Retrieved current RSS configuration\n");
        printf("RSS key length: %u\n", _rss_conf.rss_key_len);
        printf("RSS key: %p\n", _rss_conf.rss_key);
    }
    current_priority = 0;

    click_chatter("Creating flow redirections");
    //current_cores = nb_queues;
    if (flow_add_redirect(sloth_port, 0, 1, true)) {
        click_chatter("Flow group 0 created");
    }
    sloth_add_flow(nb_queues);
    if (current_flow) {
        click_chatter("Rule 1 created!");
    }
   // sloth_create_group_zero();
}
void sloth_do_update_cores() {
    debug("Actual update core");
    // Keep a copy of current flow
    struct rte_flow* flow = current_flow;
    // Update priority for new rule
    current_priority = (current_priority + 1) % 2;
    // Insert new rule
    sloth_add_flow(current_cores);
    // Delete old rule
    rte_flow_destroy(sloth_port, flow, NULL);

}

void sloth_update_nb_cores(uint16_t nb_cores){
    if (nb_cores != current_cores) {
        // click_chatter("Changing number of cores from %u to %u\n", current_cores, nb_cores);
        int diff = nb_cores - current_cores;
        // click_chatter("Updating of %d cores\n", diff);
        debug("Enabling %d cores",diff);
        if (wait_cores.count() != 0) {
            debug("Pending core update!");
            return;
        }
        if (diff > 0)
            wait_cores.put(diff);
        current_cores = nb_cores; //set by rss
        // Re-activate cores
        for (uint16_t core = 0; core < number_of_queues; core++){
            auto *s = ((struct rx_batch_latency_counter*)rx_batch_latency_counters[core]);
            if (s->activated == -1)
                debug("Core %d is in activation!", core);
            assert(s->activated != -1);
            if (core < nb_cores) {

                if (s->activated == 0) {
                    debug("Enabling core %d", core);
                    s->activated = -1; //Enabling
                }
            } else
            {
                s->last_packet_epoch = sloth_epoch;
                s->activated = 0;
            }
        }
        if (diff <= 0)
            sloth_do_update_cores();
    }
}

uint8_t queue_initialized = 0;
uint64_t last_current_mpps_s;

#define DROP_THRESHOLD 1000

#define THROUGHPUT_RINGBUFFER_SIZE 10 // If changed, also change the weights vector
struct throughput_ringbuffer {
    float values[THROUGHPUT_RINGBUFFER_SIZE];
    uint16_t index;
};

struct throughput_ringbuffer throughput_rb;

double get_current_mpps(uint8_t* has_drops){
    struct rte_eth_stats stats;
    // Get ether stats
    rte_eth_stats_get(sloth_port, &stats);
    // Register throughput into ringbuffer
    uint64_t now = rte_get_tsc_cycles();
    double diff_s = (double)(now - last_current_mpps_s) / (double)rte_get_tsc_hz();
    last_current_mpps_s = now;
    if (diff_s == 0)
        return 0;
    unsigned long th_now = ((stats.ipackets + stats.imissed) - last_packets)/diff_s;
    throughput_rb.values[throughput_rb.index] = th_now;
    // click_chatter("Throughput: %f Mpps including %u missed\n", throughput_rb.values[throughput_rb.index]/1000000.0, stats.imissed);
    throughput_rb.index = (throughput_rb.index + 1) % THROUGHPUT_RINGBUFFER_SIZE;
    // Compute weighted average
    current_throughput = current_throughput * (1-decay) + decay * th_now;
    /*for (uint16_t i = 0; i < THROUGHPUT_RINGBUFFER_SIZE; i++) {
        weighted_throughput += ((double)throughput_rb.values[i])*weights[i];
    }*/
    if ( th_now > 1.25 * current_throughput)
        current_throughput = th_now;

    // click_chatter("Weighted throughput: %f Mpps\n", weighted_throughput/1000000.0);
    double instantaneous_mpps = current_throughput / 1000000.0;
    last_packets += (stats.ipackets+stats.imissed) - last_packets;
    uint64_t drops = (stats.imissed - last_missed); ///diff_s;
    if (drops > DROP_THRESHOLD) {
        *has_drops = 1;
    } else {
        *has_drops = 0;
    }
    last_missed = stats.imissed;
    //click_chatter("Throughput: %f Mpps including %u missed\n", instantaneous_mpps, stats.imissed);
    // for (uint16_t queue = 0; queue < RTE_ETHDEV_QUEUE_STAT_CNTRS; queue++){
    //     click_chatter("\t Queue %u : %lu\n", queue, stats.q_ipackets[queue]);
    // }
    return instantaneous_mpps;
}

void set_frequency(uint64_t required_freq){
    for (uint32_t i = start_core; i <= 47; i++) {
        cpufreq_modify_policy_max(i,required_freq);
    }
}

uint16_t rx_callback(uint16_t port_id, uint16_t queue_id, struct rte_mbuf *pkts[], uint16_t nb_pkts, uint16_t max_pkts, void *user_param) {
    //Reminder: callback seems to be called only when there are packets
    struct rx_batch_latency_counter* counter = (struct rx_batch_latency_counter*)user_param;
    //If deactivated and didn't received any packets
    if (unlikely(counter->activated != 1)) {
        if (counter->activated == 0) { //0 if deactivating
            // click_chatter("Deactivated core %u\n", queue_id);
            if (nb_pkts == 0) {
                if (sloth_epoch >= counter->last_packet_epoch + (sloth_hz/2) ) {
                //click_chatter("Core %d sleeping",queue_id);
                //usleep(disabled_queues_sleeping_time_ms*1000);
                }
            } else {
                counter->last_packet_epoch = sloth_epoch;
            }
        } else if (counter->activated == -1) { //-1 if enabling
            click_chatter("Enabled core %d, sem %d", queue_id,wait_cores.count());
            if (wait_cores.get(1)) {
                counter->activated = 1;
                counter->polling_since_woke_up = 0;
                counter->idle_pollings_since_woke_up = 0;
                sloth_do_update_cores();
            }
            counter->activated = 1;
            click_chatter("Enabled core (after) %d, sem %d", queue_id,wait_cores.count());
        }

        return nb_pkts;
    }
    if (unlikely(nb_pkts > 30)) {
        counter->over_burst++;
        counter->consecutive_over_burst = (1 + counter->consecutive_over_burst) << 1;
        if (counter->consecutive_over_burst > sloth_max_consecutive) {
            debug("over_burst %d, consecutive %lu %lu  %d", counter->over_burst,counter->consecutive_over_burst,sloth_max_consecutive, log2(counter->consecutive_over_burst));
            if (applying_penalty == 0 && sloth_enable_penalty && sloth_penalty_warmup == 0) {
                penalty += 0.05;
                applying_penalty = 1 * sloth_hz;
                sloth_timer->schedule_now();
            }
        }
    } else {
        counter->consecutive_over_burst = counter->consecutive_over_burst >> 2; //Does not go below zero
    }
    counter->polling_since_woke_up++;
    counter->idle_pollings_since_woke_up += (nb_pkts == 0);
   /* counter->poll_counter++;
    // Only poll latency every RX_BATCH_LATENCY_INTERVAL packets
    if (counter->poll_counter >= RX_BATCH_LATENCY_INTERVAL){
        counter->poll_counter = 0;
        counter->lat_index = (counter->lat_index + 1) % RX_BATCH_LATENCY_HISTORY_LENGTH;
        counter->latencies[counter->lat_index] = rte_get_tsc_cycles();
    }*/
    return nb_pkts;
}

uint64_t available_freqs[64];
uint8_t freqs_count;
uint8_t current_frequency_index;
uint64_t last_up;
uint64_t lat_down;
uint64_t tsc_hz;

#define DUNEISH_IDLE_THRESHOLD 0.5

void duneish_main(Timer* t, void*arg) {
    // Basically do like Sloth and retrieve data
    if (unlikely(queue_initialized == 0)) {
        min_frequency = 800;
        queue_initialized = 1;
        sloth_init_queues_rss(1);
        current_freq = min_frequency;
        set_frequency(min_frequency*1000);
        click_chatter("Initialized freqency %u\n", current_freq);
        // Compute weights vector
        double sum = 0;
        for (uint16_t i = RX_BATCH_LATENCY_USED; i > 0; i--) {
            weights[RX_BATCH_LATENCY_USED - i] = exp(-decay*i);
            sum += weights[RX_BATCH_LATENCY_USED - i];
        }
        for (uint16_t i = 0; i < RX_BATCH_LATENCY_USED; i++) {
            weights[i] /= sum;
        }
        rx_batch_latency_counters = (void**)rte_zmalloc("rx_batch_latency_counters", sizeof(struct rx_batch_latency_counter*) * number_of_queues, 0);
        // Set up RX callbacks
        for (uint16_t i = 0; i < number_of_queues; i++) {
            click_chatter("Adding callback for queue %u\n", i);
            rx_batch_latency_counters[i] = rte_zmalloc("rx_batch_latency_counter", sizeof(struct rx_batch_latency_counter), 0);
            //((struct rx_batch_latency_counter*)rx_batch_latency_counters[i])->activated = 0;
            rte_eth_add_rx_callback(sloth_port, i, rx_callback, rx_batch_latency_counters[i]);
        }
        // Parse available frequencies
        freqs_count = 0;
        struct cpufreq_available_frequencies* freqs = cpufreq_get_available_frequencies(0);
        click_chatter("Available frequencies: ");
        while(freqs != NULL) {
            available_freqs[freqs_count] = freqs->frequency;
            click_chatter("%lu ", available_freqs[freqs_count]);
            freqs = freqs->next;
            freqs_count++;
        }
        freqs = cpufreq_get_boost_frequencies(0);
        click_chatter("Boost frequencies: ");
        while (freqs != NULL) {
            available_freqs[freqs_count] = freqs->frequency;
            click_chatter("%lu ", available_freqs[freqs_count]);
            freqs = freqs->next;
            freqs_count++;
        }
        click_chatter("\n");
        if (freqs_count == 0) {
            rte_exit(EXIT_FAILURE, "No frequencies available! Cannot run Duneish ! Do you have proper frequency control ?\n");
        }
        // Order available frequencies from lowest to highest
        for (uint8_t i = 0; i < freqs_count; i++) {
            for (uint8_t j = i + 1; j < freqs_count; j++) {
                if (available_freqs[i] > available_freqs[j]) {
                    uint64_t tmp = available_freqs[i];
                    available_freqs[i] = available_freqs[j];
                    available_freqs[j] = tmp;
                }
            }
        }
        current_frequency_index = 0;
        last_up = 0;
        lat_down = 0;
        tsc_hz = rte_get_tsc_hz();
        // At first, only one core at lowest frequency
        sloth_update_nb_cores(1);
        set_frequency(available_freqs[0]);
    }
    #ifdef ENABLE_SLOTH_ITERATIVE_INFO
    // Once every second
    if (sloth_iterative_counter == sloth_hz){
        sloth_iterative_counter = 0;
        sloth_elapsed_time++;
        // Print current status of freq and cores
        click_chatter("SLOTH-%d-RESULT-ICPU %u\n", sloth_elapsed_time, current_cores);
        click_chatter("SLOTH-%d-RESULT-IFREQ %u\n", sloth_elapsed_time, current_freq);
    } else {
        sloth_iterative_counter++;
    }
    #endif

    int max_queue_size = 0;
    int min_queue_size = INT_MAX;
    uint64_t now = rte_rdtsc();
    // Compute time based on elapsed cycles in microseconds
    uint64_t delay_since_last_up = (now - last_up) / (tsc_hz / 1000000);
    uint64_t delay_since_last_down = (now - lat_down) / (tsc_hz / 1000000);
    // Gather cores information
    float average_idle = 0;
    struct rx_batch_latency_counter ** rx_counters = (struct rx_batch_latency_counter **)rx_batch_latency_counters;
    for (uint8_t i = 0; i < current_cores; i++){
        if (rx_counters[i]->polling_since_woke_up > 0)
            average_idle += rx_counters[i]->idle_pollings_since_woke_up/
                (float)(rx_counters[i]->polling_since_woke_up);
        int queue_size = rte_eth_rx_queue_count(sloth_port, i);
        if (queue_size > max_queue_size)
            max_queue_size = queue_size;
        if (queue_size < min_queue_size)
            min_queue_size = queue_size;

    }
    click_chatter("Max queue size: %u\n", max_queue_size);
    click_chatter("Min queue size: %u\n", min_queue_size);
    average_idle /= current_cores;
    click_chatter("Idle ratio : %f\n", average_idle);
    // If we reach a particular queue size and we are not at the highest frequency, we can move up
    if (max_queue_size > 32 && current_frequency_index < freqs_count - 1 && delay_since_last_up >= 200000 && delay_since_last_down >= 200000) {
        // First increase CPU if possible
        if (current_cores < number_of_queues){
            sloth_update_nb_cores(current_cores + 1);
            click_chatter("Increasing CPU to %u\n", current_cores);
        } else {
        // If all CPU are running, scale frequency up
            current_frequency_index++;
            set_frequency(available_freqs[current_frequency_index]);
            click_chatter("Increasing frequency from %lu to %lu\n", available_freqs[current_frequency_index-1], available_freqs[current_frequency_index]);
        }
        last_up = now;
    // Same for scaling down + Some idleness threshold too
    } else if (max_queue_size < 8 && current_cores > 1 && average_idle > DUNEISH_IDLE_THRESHOLD && delay_since_last_up >= 400000 && delay_since_last_down >= 400000) { // TODO add idle threshold
        // First decrease FREQUENCY if possible
        if (current_frequency_index > 0) {
            current_frequency_index--;
            set_frequency(available_freqs[current_frequency_index]);
            click_chatter("Decreasing frequency from %lu to %lu\n", available_freqs[current_frequency_index+1], available_freqs[current_frequency_index]);
        } else {
            // If we are at the lowest frequency, scale down CPU
            sloth_update_nb_cores(current_cores - 1);
            click_chatter("Decreasing CPU to %u\n", current_cores);
        }
        lat_down = now;
    }
    resched:
        t->reschedule_after_msec(1000 / sloth_hz);
}

inline uint64_t weighted_latency(struct rx_batch_latency_counter* counter){
    uint64_t latency = 0;
    int first_item = ((int)counter->lat_index - (int)RX_BATCH_LATENCY_USED);
    // Apply modulo on negative numbers
    if (first_item < 0){
        first_item += RX_BATCH_LATENCY_HISTORY_LENGTH;
    }
    for (uint16_t i = 1 ; i < RX_BATCH_LATENCY_USED; i++) {
        int index = (first_item + i) % RX_BATCH_LATENCY_HISTORY_LENGTH;
        int previous_index = index - 1;
        if (previous_index < 0){
            previous_index += RX_BATCH_LATENCY_HISTORY_LENGTH;
        }
        uint64_t item = counter->latencies[index];
        uint64_t previous_item = counter->latencies[previous_index];
        if (item > previous_item){
            latency += (uint64_t)((double)(item - previous_item) * weights[i]);
        }
    }
    // Latency is in cycles, convert to microseconds
    return (uint64_t)(((double)latency / rte_get_tsc_hz())*1000000);
}



uint8_t overprovisioned = 0;
uint8_t scaling_down_cooldown = 0;
#define SCALINGDOWN_COOLDOWN 20

void sloth_main(Timer* t, void* arg) {
    debug("Sloth main %d",sloth_epoch);
    FromDPDKDevice* dev = (FromDPDKDevice*)arg; //TODO : have an internal load
    sloth_epoch++;
        if (unlikely(queue_initialized == 0)) {
            click_chatter("Initializing!");
            queue_initialized = 1;
            sloth_init_queues_rss(1);
            set_frequency(min_frequency*1000);

            rx_batch_latency_counters = (void**)rte_zmalloc("rx_batch_latency_counters", sizeof(struct rx_batch_latency_counter*) * number_of_queues, 0);
            // Compute weights vector
            double sum = 0;
            for (uint16_t i = RX_BATCH_LATENCY_USED; i > 0; i--) {
                weights[RX_BATCH_LATENCY_USED - i] = exp(-decay*i);
                sum += weights[RX_BATCH_LATENCY_USED - i];
            }
            for (uint16_t i = 0; i < RX_BATCH_LATENCY_USED; i++) {
                weights[i] /= sum;
            }
            // Set up RX callbacks
            for (uint16_t i = 0; i < number_of_queues; i++) {
                click_chatter("Adding callback for queue %u\n", i);
                rx_batch_latency_counters[i] = rte_zmalloc("rx_batch_latency_counter", sizeof(struct rx_batch_latency_counter), 0);
                //((struct rx_batch_latency_counter*)rx_batch_latency_counters[i])->activated = 0;
                rte_eth_add_rx_callback(sloth_port, i, rx_callback, rx_batch_latency_counters[i]);
            }
            // Initialize throughput ringbuffer
            throughput_rb.index = 0;
            for (uint16_t i = 0; i < THROUGHPUT_RINGBUFFER_SIZE; i++) {
                throughput_rb.values[i] = 0;
            }
            current_cores = 0; // RSS set this to 1, but we have to let know various internal tracking that the core 1 is to be activated
            sloth_update_nb_cores(1);
          //  current_cores = 0;
            current_freq = 0;
            scaling_down_cooldown = 0;
            goto resched;
        } else {
        // Retrieve latencies
       // uint64_t measured_latency = weighted_latency((struct rx_batch_latency_counter*)rx_batch_latency_counters[0]);
        //   for (uint16_t core = 0; core < current_cores; core++){
            //       click_chatter("[Core %u] Current latency %lu\n",core, weighted_latency((struct rx_batch_latency_counter*)rx_batch_latency_counters[core]));
            //   }
            // Get ether stats
            uint8_t has_drops;
            double measured_mpps = get_current_mpps(&has_drops);
	    if (sloth_enable_penalty && sloth_penalty_warmup == 0){
	    	measured_mpps*=penalty;
    		if (applying_penalty > 0)
	    		applying_penalty --;
	    }
        // Retrieve the optimal frequency for the given latency and observed throughput
        double scaled_mpps = measured_mpps * sloth_scale;
        uint16_t rounded_mpps = (uint8_t)(min((double)max_throughput,ceil(scaled_mpps)));
        
        #ifdef ENABLE_SLOTH_ITERATIVE_INFO
            unsigned over_burst = 0;
            for (uint16_t i = 0; i < number_of_queues; i++) {

                over_burst += ((struct rx_batch_latency_counter*)rx_batch_latency_counters[i])->over_burst;

            }
            // Once every second
            if (sloth_iterative_counter == sloth_hz){
                sloth_iterative_counter = 0;
                sloth_elapsed_time++;
                // Print current status of freq and cores
                click_chatter("SLOTH-%d-RESULT-ICPU %u\n", sloth_elapsed_time, current_cores);
                click_chatter("SLOTH-%d-RESULT-IFREQ %u\n", sloth_elapsed_time, current_freq);
            //    click_chatter("SLOTH-%d-RESULT-IESTIMATEDLAT %u\n", sloth_elapsed_time, measured_latency);
                click_chatter("SLOTH-%d-RESULT-IESTIMATEDMPPS %f\n", sloth_elapsed_time, measured_mpps);
                click_chatter("SLOTH-%d-RESULT-LOOKUPVALUEMPPS %u\n", sloth_elapsed_time, rounded_mpps);
                click_chatter("SLOTH-%d-RESULT-IOVERBURST %u\n", sloth_elapsed_time, over_burst);
                click_chatter("SLOTH-%d-RESULT-PENALTY %f\n", sloth_elapsed_time, penalty);
		click_chatter("SLOTH-%d-RESULT-CONTROLCORE %u\n", sloth_elapsed_time, rte_lcore_id());


		sloth_penalty_warmup = max(0,sloth_penalty_warmup - 1);
            } else {
                sloth_iterative_counter++;
            }
        #endif

        //rounded_mpps+=1; no : use the table
        uint16_t lat = expected_latency_us;

        // Ignore iteration if no packets were received
        if (scaled_mpps >= 1) { // We do run the loop if there is a change in MPPS because we want to verif the load, burst, cooldown etc
            if (lat == 0) {
                uint16_t key = (rounded_mpps << 8) | current_latency_us + 5;
                struct sloth_optimal_entry *entry;
                int next_watt = 999;
                int prev_watt = 999;
                int cur_watt = 999;
                int ret = rte_hash_lookup_data(optimums, &key, (void**)&entry);
                if (ret > 0) {
                    next_watt = entry->watt;
                }


                key = (rounded_mpps << 8) | current_latency_us - 5;
                ret = rte_hash_lookup_data(optimums, &key, (void**)&entry);

                if (ret > 0) {
                    prev_watt = entry->watt;
                }

                key = (rounded_mpps << 8) | current_latency_us;
                ret = rte_hash_lookup_data(optimums, &key, (void**)&entry);
                if (ret > 0) {
                        if (cur_watt - next_watt >= 5 && current_latency_us < 60) {
                        lat = current_latency_us + 5;
                    } else if (prev_watt - cur_watt < 3) {
                        lat = current_latency_us - 5;
                    }
                } else
                    lat = 20;


            }
            uint32_t key = (rounded_mpps << 16) | lat; // Overprovision a bit
            current_latency_us = lat;
            struct sloth_optimal_entry *entry;
            int ret = rte_hash_lookup_data(optimums, &key, (void**)&entry);
            uint8_t updated_config = 0;
            if (ret < 0) {
                click_chatter("Couldn't find any matching entry (%d,%d), won't change frequency (measured %f, scaled %f, penalty %f)\n", rounded_mpps, lat, measured_mpps, scaled_mpps, penalty);
                for (; lat < 200; lat++) {
                    key = (rounded_mpps << 8) | lat; // Overprovision a bit
                        if (rte_hash_lookup_data(optimums, &key, (void**)&entry) >= 0)
                            break;
                }
                if (key == lat) {
                        click_chatter("No latency at this speed!");
                        goto resched;
                } else {
                    click_chatter("Found a latency at %d",lat);
                }
            }
            {
                debug("last %d %d scaled %f", last_mpps,rounded_mpps,scaled_mpps);
                last_mpps = rounded_mpps;
		if (scaled_mpps > sloth_last_mpps && entry->cores < current_cores && entry->freq < current_freq){
//			click_chatter("Do not allow a downsizing if throughput actually increases !\n");
			goto resched;
		} 
		sloth_last_mpps = scaled_mpps;
                //         printf("New number of cores %u\n", entry->cores);
                // Depending on the configuration, it is better to scale the cores or the frequency
                // in a particular order to avoid underprovisioned intervals
               	if (current_cores != entry->cores || current_freq != entry->cores) {
//			click_chatter("Moving from %u/%u to %u/%u \n", current_cores,current_freq, entry->cores, entry->freq);
		} 
                // If the number of cores increases, apply core scaling before changing frequency
                if (entry->cores > current_cores) {
                    debug("Requiring %u cores while only %u cores are allocated(%u, %u)\n", entry->cores, current_cores, rounded_mpps, lat);
                    //Overprovision with 1 core to anticipate throughput increase
                    //entry->cores += 1;
                    //overprovisioned = 1;
                    if (entry->cores > number_of_queues){
                        entry->cores = number_of_queues;
                    }
                    sloth_update_nb_cores(entry->cores);
                    //sloth_update_nb_cores(12);
		    updated_config = 1;
                    scaling_down_cooldown = SCALINGDOWN_COOLDOWN;
                }
                // Adjust frequency based on stats
                if (current_freq != entry->freq) {
		    //click_chatter("Moving from %uMHz to %uMHz\n", current_freq, entry->freq);
                    if (current_freq < entry->freq || (current_freq > entry->freq && scaling_down_cooldown == 0)) {
                        current_freq = entry->freq;
                        updated_config = 1;
                        set_frequency(entry->freq);
                        //set_frequency(3000000);
			scaling_down_cooldown = SCALINGDOWN_COOLDOWN*(current_freq > entry->freq);
                    } else {
                        scaling_down_cooldown = max(scaling_down_cooldown-1, 0);
                    }
                } else
                    scaling_down_cooldown = max(scaling_down_cooldown-1, 0);
                // If the number of cores decreases, apply core scaling after changing frequency
                if (entry->cores < current_cores - overprovisioned){
                    debug("Should cooldown %d",scaling_down_cooldown );
                    if (scaling_down_cooldown == 0){
                        // overprovisioned = 0;
                        // entry->cores += 1;
                        sloth_update_nb_cores(entry->cores);
                        //sloth_update_nb_cores(12);
			updated_config = 1;
                    } else {
                        scaling_down_cooldown--;
                    }
                }
                debug("config %d %d %d %d %d",updated_config , entry->cores,current_cores, entry->freq, current_freq);
                if (updated_config == 0 && entry->cores == current_cores && entry->freq == current_freq && sloth_enable_penalty && sloth_penalty_warmup == 0) {
                    float avg_load = 0;
                    for (int i = 0; i < dev->master()->nthreads(); i++)
                        avg_load += dev->master()->thread(i)->load();
                    avg_load /= current_cores;
                    //avg_load_decay = avg_load * (1-)decay  + avg_load
                    if (avg_load > 0.1 && (0.05+(avg_load *1.1)) < entry->load) {
                        click_chatter("overprovision of throughput detected, load e %f, avg %f. ICPU %d, FREQ %d, penalty %f", entry->load, avg_load, current_cores, current_freq, penalty);
                        if (applying_penalty == 0 && penalty > 0.8) {
                            penalty -= 0.1;
                            applying_penalty = sloth_hz;
                        } else
                            debug("Not applied, applying penalty %d",applying_penalty );
                    } else if (avg_load > 0.9 || (avg_load * 0.9 > entry->load)) {
                        click_chatter("underprovision of throughput detected, load e %f, avg %f. ICPU %d, FREQ %d, penalty %f", entry->load, avg_load, current_cores, current_freq, penalty);
                        if (applying_penalty == 0 && penalty < 2) {
                            penalty += 0.1;
                            applying_penalty = sloth_hz;
                        } else
                            debug("Not applied, applying penalty %d",applying_penalty );
                    } else {
                        debug("Good overprovision, load e %f > avg %f but not too much", entry->load, avg_load);
                    }
                }

            }

        } else if (rounded_mpps == 0) {
            debug("Sleeping because of low MPPS");
            // If no packets were received, scale down to minimum frequency
            if (current_freq != min_frequency*1000){
                current_freq = min_frequency*1000;
                set_frequency(current_freq);
            }
            if (current_cores != 1){
                sloth_update_nb_cores(1);

            }
        }
    }
    resched:
        t->schedule_after_msec(1000 / sloth_hz);
}

struct rte_hash* sloth_parse_csv(char *csvfile){
    // Create hashmap that will be returned
    struct rte_hash_parameters params = {
        .name = "optimums",
        .entries = 1 << 16,
        .key_len = sizeof(uint32_t), // 2 bytes for throughput in MPPS (1-30), 2 bytes for latency (1-65535)
        .hash_func = rte_hash_crc,
        .hash_func_init_val = 0
    };
    struct rte_hash *optimums = rte_hash_create(&params);
    if (optimums == NULL) {
        printf("Error creating hash table: %s\n", rte_strerror(rte_errno));
        return NULL;
    }

    // Open file
    FILE *file = fopen(csvfile, "r");
    if (file == NULL) {
        printf("Error opening file %s: %s\n", csvfile, strerror(errno));
        return NULL;
    }

    // Read file line by line
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    uint16_t line_count = 0;
    while ((read = getline(&line, &len, file)) != -1) {
        // Skip the first line that contains headers
        if (line_count == 0) {
            line_count++;
            continue;
        }
        // Parse line
        char *latency_str = strtok(line, ",");
        char *throughput_str = strtok(NULL, ",");
        char *cpu_str = strtok(NULL, ",");
        char *freq_str = strtok(NULL, ",");
        char *watt_str = strtok(NULL, ",");
        char *burst_str = strtok(NULL, ",");
        char *load_str = strtok(NULL, ",");
        // char *sleep_mode = strtok(NULL, ",");
        // char *sleep_delta_str = strtok(NULL, ",");

        if (throughput_str == NULL || latency_str == NULL || freq_str == NULL || burst_str == NULL || load_str == NULL) {
            printf("Error parsing line: %s\n", line);
            continue;
        }
        struct sloth_optimal_entry *entry = (struct sloth_optimal_entry*)malloc(sizeof(struct sloth_optimal_entry));
        uint16_t throughput = atoi(throughput_str);
        if (throughput > max_throughput)
            max_throughput = throughput;
        uint16_t latency = atoi(latency_str);
        entry->freq = atoll(freq_str)*1000;
        // entry->watt = atoi(watt_str);
        entry->cores = atoi(cpu_str); 
        entry->burst = atoi(burst_str);
        entry->load = atof(load_str) / 100.0;
        // Insert into hashmap
        uint32_t key = (throughput << 16) | latency;
        int ret = rte_hash_add_key_data(optimums, &key, (void*)entry);
        if (ret < 0) {
            printf("Error inserting key %u: %s\n", key, strerror(-ret));
        }
    }
    printf("Max throughput %u\n", max_throughput);
    return optimums;
}

bool FromDPDKDevice::enable_interrupt(Task* t, void* data) {
    FromDPDKDevice* fd = (FromDPDKDevice*)data;
    ErrorHandler* errh = ErrorHandler::default_handler();



    for (int i = fd->queue_for_thread_begin(click_current_cpu_id());  i <= fd->queue_for_thread_end(click_current_cpu_id());i++) {
        uint32_t data = fd->_dev->port_id << CHAR_BIT | i;

            click_chatter("Initializing interrupt %d on thread %d", i, click_current_cpu_id());
            //int efd = rte_eth_dev_rx_intr_ctl_q_get_fd(port_id,i);
            int ret = rte_eth_dev_rx_intr_ctl_q( fd->_dev->port_id, i, RTE_EPOLL_PER_THREAD, RTE_INTR_EVENT_ADD,
                (void *)((uintptr_t)data));
            if (ret)
                return errh->error("Could not initialize interrupt : %d %d (%s)",ret, rte_errno, rte_strerror(rte_errno));
    }
    return 0;
}


#define TEST_POWER_FREQS_NUM_MAX ((unsigned)RTE_MAX_LCORE_FREQS)
static uint32_t total_freq_num;
static uint32_t freqs[TEST_POWER_FREQS_NUM_MAX];
static uint64_t timer_resolution_cycles;
static int timer_per_second = 10;
uint64_t timerhz;

int FromDPDKDevice::initialize(ErrorHandler *errh) {
    int ret;
    if (!_dev)
        return 0;

    ret = initialize_rx(errh);
    if (ret != 0)
        return ret;

    for (unsigned i = (unsigned)firstqueue; i <= (unsigned)lastqueue; i++) {
        ret = _dev->add_rx_queue(i , _promisc, _vlan_filter, _vlan_strip, _vlan_extend, _lro, _jumbo, ndesc, errh);

        if (ret != 0) return ret;
    }

    for (int i = 0; i < _fdstate.weight(); i++) {
         _fdstate.get_value(i).time_sleep  = _sleep_reset;
    }

    if (queue_per_threads > 1)
        ret = initialize_tasks(_active, errh, multi_run_task);
    else {
        ret = initialize_tasks(_active, errh);
    }
        
    if (ret != 0)
        return ret;

    if (_sleep_mode & SLEEP_INTR) {
        for (int th_id = 0; th_id < master()->nthreads(); th_id++) {
            if (!usable_threads[th_id])
                continue;
                Task* irq_task = new Task(enable_interrupt, this, th_id);

                irq_task->initialize(this, true);
        }
    }

    if (queue_share > 1 && !(_sleep_mode & SLEEP_POLICY_METRONOME))
        return errh->error(
            "Sharing queue between multiple threads is only supported with Metronome policy"
            "Raise the number using N_QUEUES of queues or "
            "limit the number of threads using MAXTHREADS"
        );

    if (all_initialized()) {
        ret = DPDKDevice::initialize(errh);
        if (ret != 0) return ret;
        printf("All tasks initialized\n");
    } else {
        printf("Not all tasks initialized\n");
    }

    if (_set_timestamp) {
#if HAVE_DPDK_READ_CLOCK
        uint64_t t;
        int err;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        if ((err = rte_eth_read_clock(_dev->port_id, &t)) != 0) {
            return errh->error("Device does not support queryig internal time ! Disable hardware timestamping. Error %d", err);
        }
#pragma GCC diagnostic pop
#endif
    }

    if ((_sleep_mode & SLEEP_POLICY_SLOTH) || (_sleep_mode & SLEEP_POLICY_DUNEISH)) {
            printf("Running with an expected latency of %u us\n", expected_latency_us);
            sloth_port = _dev->port_id;
            // init _rss_conf
            start_core = 0;
            // Get number of cores
            end_core = rte_lcore_count() - 1;
            printf("Initializing optimums\n");
            if (_sleep_mode & SLEEP_POLICY_SLOTH)
                optimums = sloth_parse_csv((char*)_sloth_optimums_path.c_str());

            // In an infinite loop, get ethernet stats and adjust frequency
            struct rte_eth_stats stats;
            click_chatter("Sloth Port %d\n",sloth_port);
            rte_eth_stats_get(sloth_port, &stats);
            last_packets=stats.ipackets;
            last_mpps=0;
            last_bytes=stats.ibytes;
                            //click_chatter("Initializing maintain timer %d", core);
            if (_sleep_mode & SLEEP_POLICY_SLOTH)
                sloth_timer = new Timer(sloth_main, this);
            else
                sloth_timer = new Timer(duneish_main, this);
            sloth_timer->initialize(this, true);

            //  t.maintain_timer->move_thread(core);
            sloth_timer->schedule_after_msec(1000 / sloth_hz);
            sloth_timer->move_thread(end_core);
            printf("Sloth setup finished\n");

    }
    // if (_sleep_mode & SLEEP_POLICY_DUNEISH) {
    //         sloth_port = _dev->port_id;
    //         // init _rss_conf

    //         start_core = 0;
    //         end_core = rte_lcore_count() - 1;
    //         printf("Initializing optimums\n");
    //         // optimums = sloth_parse_csv((char*)_sloth_optimums_path.c_str());

    //         // In an infinite loop, get ethernet stats and adjust frequency
    //         struct rte_eth_stats stats;
    //         click_chatter("Sloth Port %d\n",sloth_port);
    //         rte_eth_stats_get(sloth_port, &stats);
    //         last_packets=stats.ipackets;
    //         last_mpps=0;
    //         last_bytes=stats.ibytes;
    //         //click_chatter("Initializing maintain timer %d", core);
    //         sloth_timer = new Timer(duneish_main, this);
    //         sloth_timer->initialize(this, true);

    //         //  t.maintain_timer->move_thread(core);
    //         sloth_timer->schedule_after_msec(1000 / sloth_hz);
    //         sloth_timer->move_thread(end_core);
    //         printf("Duneish setup finished\n");
    // }
    if (_sleep_mode & SLEEP_POLICY_TUPE) {
        rte_timer_subsystem_init();
        int lcore_id;
        timerhz = rte_get_timer_hz();
        memset(freqs,0,sizeof(freqs));
        timer_resolution_cycles = (uint64_t)(timerhz/timer_per_second);
        click_chatter("Resolution cycles : %lu",timer_resolution_cycles);

        click_chatter("Hardware Timer Resolution: %lu \n",timerhz);
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;
                ret = rte_power_init(lcore_id);
            if (ret)
                RTE_LOG(ERR, POWER,
                        "Library initialization failed on core %u\n", lcore_id);

            if (rte_power_freqs){
                total_freq_num = rte_power_freqs(lcore_id,freqs,TEST_POWER_FREQS_NUM_MAX);
                click_chatter("Got %d freqs",total_freq_num);
                for(int i = 0; i < total_freq_num; i++){
                    click_chatter("Freq %u: %u\n",i,freqs[i] );
                }
            } else {
                click_chatter("No Freq num");
                return errh->error("Does not support freq");
            }
        }
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;
            /* init timer structures for each enabled lcore */
            int et = 0;
            rte_timer_init(&_fdstate.get_value_for_thread(lcore_id).power_timer);
            if (et != 0) {
                return errh->error("Error in timer init: %d", et);
            }
            et = rte_timer_reset(&_fdstate.get_value_for_thread(lcore_id).power_timer,
                            timerhz/timer_per_second, SINGLE, lcore_id,
                            power_timer_cb, &_fdstate.get_value_for_thread(lcore_id));
            if (et != 0)
                return errh->error("Error in timer init: %d %d (%s)", et,rte_errno,rte_strerror(rte_errno));
        }
        rte_timer_manage();
    }

    return ret;
}

void FromDPDKDevice::cleanup(CleanupStage)
{
    click_chatter("Cleaning up");

    double avg_cycles_per_polling = 0;
    double avg_burst_size = 0;
    uint32_t avg_cycles_per_polling_items = 0;
    uint32_t avg_burst_size_items = 0;
    double average_total_pollings = 0;
    double average_busy_pollings = 0;
    struct rx_batch_latency_stats_counter* summed_counter = (struct rx_batch_latency_stats_counter*)rte_zmalloc("rx_batch_latency_stats_counter", sizeof(struct rx_batch_latency_stats_counter), 0);
    for (uint16_t i = 0; i < number_of_queues; i++) {
        average_busy_pollings += ((struct rx_batch_latency_stats_counter*)rx_batch_latency_counters[i])->busy_pollings;
        average_total_pollings += ((struct rx_batch_latency_stats_counter*)rx_batch_latency_counters[i])->pollings;
        #if RX_CYCLES_STATS > 1
            // Iterate on rdtsc values
            for (uint32_t j = 1; j < RX_STATS_RDTSC_VALUES ; j++){
                // retrieve actual value
                uint64_t value = j << RX_STATS_RDTSC_BIT_OFFSET;
                // Iterate over RDTSC
                avg_cycles_per_polling +=  (value/RX_STATS_MEASUREMENTS_INTERVAL)*((struct rx_batch_latency_stats_counter*)rx_batch_latency_counters[i])->rdtsc_values[j];
                avg_cycles_per_polling_items += ((struct rx_batch_latency_stats_counter*)rx_batch_latency_counters[i])->rdtsc_values[j];
                // Create global counter for later decile computation
                summed_counter->rdtsc_values[j] += ((struct rx_batch_latency_stats_counter*)rx_batch_latency_counters[i])->rdtsc_values[j];
            }
        #endif
        // Iterate over burst size
        for (uint32_t j = 1; j < RX_STATS_BURST_SIZES ; j++){
            avg_burst_size += ((struct rx_batch_latency_stats_counter*)rx_batch_latency_counters[i])->burst_sizes[j]*j;
            avg_burst_size_items += ((struct rx_batch_latency_stats_counter*)rx_batch_latency_counters[i])->burst_sizes[j];
            summed_counter->burst_sizes[j] += ((struct rx_batch_latency_stats_counter*)rx_batch_latency_counters[i])->burst_sizes[j];
        }
    }
    printf("RESULT-AVG_TOTAL_POLLINGS %f\n", average_total_pollings/number_of_queues);
    printf("RESULT-AVG_BUSY_POLLINGS %f\n", average_busy_pollings/number_of_queues);
#if RX_CYCLES_STATS > 1
    double average_cycles_per_polling = 0;
    if (avg_cycles_per_polling_items > 0){
        average_cycles_per_polling = avg_cycles_per_polling/avg_cycles_per_polling_items;
    }
    // printf("Total cycles pollings %f\n", avg_cycles_per_polling);
    // printf("Total items %u\n", avg_cycles_per_polling_items);

    printf("RESULT-AVG_CYCLES_PER_POLLING %f\n", average_cycles_per_polling);
#endif
    double average_burst_size = 0;
    if (avg_burst_size_items > 0){
        average_burst_size = avg_burst_size/avg_burst_size_items;
    }
    printf("RESULT-AVG_BURST_SIZE %f\n", average_burst_size);

    // Compute deciles
    double deciles[10];
    for (uint16_t i = 0; i < 10; i++) {
        deciles[i] = 0;
    }
    double decile_threshold = (double)avg_cycles_per_polling_items*0.1;
    uint16_t current_decile = 0;
    uint32_t total_item_counter = 0;

#if RX_CYCLES_STATS > 1
    // Iterate on rdtsc values
    for (uint32_t j = 1; j < RX_STATS_RDTSC_VALUES ; j++){
        uint64_t actual_rdtsc = j << RX_STATS_RDTSC_BIT_OFFSET;
        double value = (actual_rdtsc/RX_STATS_MEASUREMENTS_INTERVAL);
        uint64_t nb_values = summed_counter->rdtsc_values[j];
        for (uint32_t k = 0; k < nb_values; k++){
            if (total_item_counter > decile_threshold){
                current_decile++;
                decile_threshold += (double)avg_cycles_per_polling_items*0.1;
            }
            deciles[current_decile] += value;
            total_item_counter++;
        }
    }

    decile_threshold = (double)(avg_cycles_per_polling_items*0.1);
    for (uint16_t i = 0; i < 10; i++) {
        printf("RESULT-PACKETS_PER_POLLING_DECILE_%u %f\n", i+1, deciles[i]/decile_threshold);
    }
    

    // Now that we have averages, compute standard deviation
    double std_cycles_per_polling = 0;
    uint32_t std_cycles_per_polling_items = 0;
    for (uint32_t j = 1; j < RX_STATS_RDTSC_VALUES ; j++){
        uint64_t deviation = 0;
        uint64_t actual_rdtsc = j << RX_STATS_RDTSC_BIT_OFFSET;
        double value = actual_rdtsc/RX_STATS_MEASUREMENTS_INTERVAL;
        // Dirty wayaround to compute absolute value
        if (value > average_cycles_per_polling){
            deviation = value - average_cycles_per_polling;
        } else {
            deviation = average_cycles_per_polling - value;
        }
        std_cycles_per_polling += deviation*summed_counter->rdtsc_values[j];
        std_cycles_per_polling_items+=summed_counter->rdtsc_values[j];
    }

    double final_std_cycles_per_polling = 0;
    if (std_cycles_per_polling_items > 0){
        final_std_cycles_per_polling = std_cycles_per_polling/std_cycles_per_polling_items;
    }
    printf("RESULT-STD_CYCLES_PER_POLLING %f\n", final_std_cycles_per_polling);
#endif


    // Iterate over burst size
    double std_burst_size = 0;
    uint32_t std_burst_size_items = 0;
    for (uint32_t j = 1; j < RX_STATS_BURST_SIZES ; j++){
        uint64_t deviation = 0;
        // Dirty wayaround to compute absolute value
        if (j > average_burst_size){
            deviation = j - average_burst_size;
        } else {
            deviation = average_burst_size - j;
        }
        std_burst_size += deviation*summed_counter->burst_sizes[j];
        std_burst_size_items+= summed_counter->burst_sizes[j];
    }
    double final_std_burst_size = 0;
    if (std_burst_size_items > 0){
        final_std_burst_size = std_burst_size/std_burst_size_items;
    }
    printf("RESULT-STD_BURST_SIZE %f\n", final_std_burst_size);

    fflush(stdout);
    DPDKDevice::cleanup(ErrorHandler::default_handler());
    cleanup_tasks();
}

void FromDPDKDevice::clear_buffers() {
    rte_mbuf* pkts[32];
    for (int q = firstqueue; q <= lastqueue; q++) {
        unsigned n;
        unsigned tot = 0;
        do {
            n = rte_eth_rx_burst(_dev->port_id, q, pkts, 32);
            tot += n;
            for (unsigned i = 0; i < n; i ++) {
                 rte_pktmbuf_free(pkts[i]);
            }
            if (tot > _dev->get_nb_rxdesc()) {
                click_chatter("WARNING : Called clear_buffers while receiving packets !");
                break;
            }
        } while (n > 0);
        click_chatter("Cleared %d buffers for queue %d",tot,q);
    }
}
#ifdef DPDK_USE_XCHG
extern "C" {
#include <mlx5_xchg.h>
}
#endif

inline CLICK_ALWAYS_INLINE bool
FromDPDKDevice::_run_task(int iqueue, unsigned long *lock)
{
    struct rte_mbuf *pkts[_burst];

#if HAVE_BATCH
  PacketBatch *head = 0;
  WritablePacket *last;
#endif

#ifdef DPDK_USE_XCHG
		unsigned n = rte_mlx5_rx_burst_xchg(_dev->port_id, iqueue, (struct xchg**)pkts, _burst);
#else
        unsigned n = rte_eth_rx_burst(_dev->port_id, iqueue, pkts, _burst);
#endif

    if (n > _burst){ // I don't know why this happens
        return 0;
    }

    // If a lock was provided, unlock it after receiving packets
    if (lock != NULL) {
        *lock = UNLOCKED;
    }

	for (unsigned i = 0; i < n; ++i) {
        if (pkts == NULL || pkts[i]->buf_addr == NULL)
            continue;
		unsigned char *data = rte_pktmbuf_mtod(pkts[i], unsigned char *);
		rte_prefetch0(data);
#if CLICK_PACKET_USE_DPDK
    	WritablePacket *p = static_cast<WritablePacket *>(Packet::make(pkts[i], _clear));
#elif HAVE_ZEROCOPY

# if CLICK_PACKET_INSIDE_DPDK
		WritablePacket *p =(WritablePacket*)( pkts[i] + 1);
		new (p) WritablePacket();

		p->initialize(_clear);
		p->set_buffer((unsigned char*)(pkts[i]->buf_addr), DPDKDevice::MBUF_DATA_SIZE);
		p->set_data(data);
		p->set_data_length(rte_pktmbuf_data_len(pkts[i]));
		p->set_buffer_destructor(DPDKDevice::free_pkt);

		p->set_destructor_argument(pkts[i]);
# else
		WritablePacket *p = Packet::make(
		    data, rte_pktmbuf_data_len(pkts[i]), DPDKDevice::free_pkt, pkts[i],
		    rte_pktmbuf_headroom(pkts[i]), rte_pktmbuf_tailroom(pkts[i]), _clear);
# endif
#else //!HAVE_ZEROCOPY && !CLICK_PACKET_USE_DPDK
            WritablePacket *p = Packet::make(data,
                                     (uint32_t)rte_pktmbuf_pkt_len(pkts[i]));
            rte_pktmbuf_free(pkts[i]);
            data = p->data();
#endif
            p->set_packet_type_anno(Packet::HOST);
            p->set_mac_header(data);
            if (_set_rss_aggregate)
#if RTE_VERSION > RTE_VERSION_NUM(1,7,0,0)
                SET_AGGREGATE_ANNO(p,pkts[i]->hash.rss);
#else
                SET_AGGREGATE_ANNO(p,pkts[i]->pkt.hash.rss);
#endif
            if (_set_paint_anno) {
                SET_PAINT_ANNO(p, iqueue);
            }

#if RTE_VERSION >= RTE_VERSION_NUM(18,02,0,0)
            if (_set_timestamp && HAS_TIMESTAMP(pkts[i])) {
                p->timestamp_anno().assignlong(TIMESTAMP_FIELD(pkts[i]));
            }
#endif
#if HAVE_BATCH
            if (head == NULL)
                head = PacketBatch::start_head(p);
            else
                last->set_next(p);
            last = p;
#else
            output(0).push(p);
#endif
    }

#if HAVE_BATCH
    if (head) {
        head->make_tail(last,n);
        output_push_batch(0,head);
    }
#endif
    if (n) {
        add_count(n);
    }
    return n;
}


void FromDPDKDevice::turn_on_off_intr(bool on, uint8_t start_queue, uint8_t end_queue)
{
    //click_chatter("Enable interrupt on %d -> %d", start_queue, end_queue);
	for (uint8_t i = start_queue; i <= end_queue; ++i) {
        //click_chatter("%d interrupt core %d",on,thread_for_queue_offset(i));
		rte_spinlock_lock(&_dev_lock);
        int err;
		if (on)
			err = rte_eth_dev_rx_intr_enable(_dev->port_id, i);
		else
			err = rte_eth_dev_rx_intr_disable(_dev->port_id, i);
        if (unlikely(err)) {
            //click_chatter("Could not enable/disable(%d) interrupt !!! %d %d : %s", on,err, rte_errno, rte_strerror(rte_errno));
            //assert(false);
        }
		rte_spinlock_unlock(&_dev_lock);
	}
}

static int sleep_until_rx_interrupt(int num, int lcore) {

	struct rte_epoll_event event[num];
	int n, i;
	uint16_t port_id;
	uint8_t queue_id;
	void *data;


    //click_chatter("Waiting on core %d, num %d", lcore, num);
    //click_chatter("FD %d",rte_eth_dev_rx_intr_ctl_q_get_fd(0,lcore));
	n = rte_epoll_wait(RTE_EPOLL_PER_THREAD, event, num, 10);
    //click_chatter("Returned %d", n);
	for (i = 0; i < n; i++) {
		data = event[i].epdata.data;
		port_id = ((uintptr_t)data) >> CHAR_BIT;
		queue_id = ((uintptr_t)data) &
			RTE_LEN2MASK(CHAR_BIT, uint8_t);
		/*click_chatter(
			"lcore %u is waked up from rx interrupt on"
			" port %d queue %d\n",
			rte_lcore_id(), port_id, queue_id);*/
	}


	return 0;
}

/*  Freqency scale down timer callback */
 void
FromDPDKDevice::power_timer_cb(__attribute__((unused)) struct rte_timer *tim,
               void *arg)
{

    FDState* s = (FDState*)arg;
    unsigned lcore_id = rte_lcore_id();
    //click_chatter("Timer on %d",lcore_id);
    rte_timer_reset(&s->power_timer, timerhz/timer_per_second-5000,
                    SINGLE, lcore_id, power_timer_cb, arg);

    uint32_t cpuhzindex = rte_power_get_freq(lcore_id);

    /* The unit of values in freqs is in KHz  */
    double cpuhz = freqs[cpuhzindex]*1e3; /* info */
    double rho = 1 - s->nb_idle_looped*((CV + s->time_sleep*(cpuhz/timerhz))/cpuhz)*timer_per_second;
    if (rho < 0)
        rho = 0;

    /*  cpuhz*rho = target_freq*CLIFF ==> target_freq = ceil((cpuhz*rho/CLIFF)/1e8*/
    //double target_Freq = cpuhz*rho/CLIFF;
    /*  (target_freq - cpuhz)/1e8: diff in index */
    int target_index = lround((cpuhz*rho/CLIFF)/1e8);
    // click_chatter("The thing:%d\n", ceil((cpuhz*rho/CLIFF)/1e8));
    // click_chatter("CPUhz %f, rho %f, target %d, timerhz %lu, timer_per_second %d\n", cpuhz, rho, target_index, timerhz, timer_per_second);
    set_frequency(freqs[target_index]);

    if( target_index < 0 )
        target_index = 0;
    else if( target_index > total_freq_num - 1 )
        target_index = total_freq_num - 1;

    /* The Freq needed to be adjusted */
    if( target_index != cpuhzindex ){
        s->time_sleep = 0;
        // click_chatter("Set freq %d",target_index);
        rte_power_set_freq(lcore_id,target_index);
    }
    /* Already the lowest frequency and rho still less than CLIFF */
    if( cpuhzindex == (total_freq_num-1) && rho < CLIFF ){
        uint32_t cycles = (uint16_t)((CIO+CCALL)*(1-rho)/rho*(timerhz/cpuhz));
        cycles = (cycles > timerhz/1e6)?timerhz/1e6:cycles;
    }

    s->nb_rx_processed = 0;
    s->nb_idle_looped = 0;
}




/* __SSE2__ may be supported or not; deceided by __SSE2__ defined in gcc */
static inline void nap(void){
#ifdef __SSE2__
    __asm__ __volatile__("pause\n\t" ::: "memory");
#else
    __asm__ __volatile__("rep;nop\n\t": : : "memory");
#endif
}

static inline void
nap_cycles(uint64_t cycles)
{
    while( cycles-- > 0 ){
        nap();
    }
}


void
FromDPDKDevice::do_sleep(int t) {
    if (_sleep_mode & SLEEP_U) {
        // Utilisation du sleep de linux
        //click_chatter("Going to sleep for %d seconds\n", t);
	usleep(t);
    } else if (_sleep_mode & SLEEP_HR) {
        // Utilisation du sleep de Metronome
        hr_sleep(t * 1000);
    } else if (_sleep_mode & SLEEP_HR2) {
        // Utilisation du sleep de Metronome en mode module
        ioctl(hr2fd, 0, t * 1000);
    } else if (_sleep_mode & SLEEP_RTE) {
        rte_delay_us(t);
    } else if (_sleep_mode & SLEEP_RTE_PAUSE){
        rte_pause();
    }
    //click_chatter("Slept for %d -> %d %ul %ul", t, (rte_rdtsc() - b), rte_get_tsc_hz(), (rte_rdtsc() - b) / (rte_get_tsc_hz() / 1000000) );
}

inline uint32_t
FromDPDKDevice::power_idle_heuristic(uint32_t zero_rx_packet_count)
{
	/* If zero count is less than 100,  sleep 1us */
	if (zero_rx_packet_count < _suspend_threshold)
		return MINIMUM_SLEEP_TIME;
	/* If zero count is less than 1000, sleep 100 us which is the
		minimum latency switching from C3/C6 to C0
	*/
	else
		return _suspend_threshold;
}

static void intel_umwait(const uint64_t timeout)
{
#if defined(RTE_TOOLCHAIN_MSVC) || defined(__WAITPKG__)
	_umwait(0, timeout);
#else
	const uint32_t tsc_l = (uint32_t)timeout;
	const uint32_t tsc_h = (uint32_t)(timeout >> 32);

	asm volatile(".byte 0xf2, 0x0f, 0xae, 0xf7;"
			: /* ignore rflags */
			: "D"(0), /* enter C0.2 */
			  "a"(tsc_l), "d"(tsc_h));
#endif
}


/*
 * This function uses UMONITOR/UMWAIT instructions and will enter C0.2 state.
 * For more information about usage of these instructions, please refer to
 * Intel(R) 64 and IA-32 Architectures Software Developer's Manual.
 */
static void intel_umonitor(volatile void *addr)
{
#if defined(RTE_TOOLCHAIN_MSVC) || defined(__WAITPKG__)
	/* cast away "volatile" when using the intrinsic */
	_umonitor((void *)(uintptr_t)addr);
#else
	/*
	 * we're using raw byte codes for compiler versions which
	 * don't support this instruction natively.
	 */
	asm volatile(".byte 0xf3, 0x0f, 0xae, 0xf7;"
			:
			: "D"(addr));
#endif
}

#define RX_CALLBACK_STATS_WARMUP 200000

uint16_t rx_callback_stats(uint16_t port_id, uint16_t queue_id, struct rte_mbuf *pkts[], uint16_t nb_pkts, uint16_t max_pkts, void *user_param){
    struct rx_batch_latency_stats_counter* counter = (struct rx_batch_latency_stats_counter*)user_param;
    counter->pollings++;
    // Add 1*boolean to busy_pollings to avoid branch misprediction
    counter->busy_pollings += (1*(nb_pkts > 0));
    counter->burst_sizes[nb_pkts]++;


    // Add entry to latency history
    /*if (unlikely(counter->pollings % RX_STATS_MEASUREMENTS_INTERVAL == 0)){
        // printf("Pollings %u\n", counter->pollings);
        if (!counter->warmed_up && counter->pollings > RX_CALLBACK_STATS_WARMUP) {
            // click_chatter("Warmup finished\n");
            counter->warmed_up = 1;
            counter->warmup_pollings = counter->pollings;
        }
        if (counter->warmed_up && counter->last_rdtsc != 0) {
            // click_chatter("Doing some RDTSC stuff\n");
            uint64_t current_rdtsc = rte_get_tsc_cycles();
            #if RX_CYCLES_STATS > 1
            uint64_t elapsed = (current_rdtsc - counter->last_rdtsc) >> RX_STATS_RDTSC_BIT_OFFSET;

                if (elapsed >= RX_STATS_RDTSC_VALUES){
                    printf("Warning: overflow %lu > %lu\n", elapsed, RX_STATS_RDTSC_VALUES);
                    elapsed = RX_STATS_RDTSC_VALUES-1;
                }

                counter->rdtsc_values[elapsed]++;
            #endif
            counter->last_rdtsc = current_rdtsc;
        } else {
            counter->last_rdtsc = rte_get_tsc_cycles();
        }
    }*/
    return nb_pkts;
}

inline
bool FromDPDKDevice::_process_packets(uint8_t iqueue) {
    #if RX_CYCLES_STATS
    if (!queues_set_up[iqueue]) {
        queues_set_up[iqueue] = 1;
        printf("Initializing queue %d\n", iqueue);
        rte_eth_add_rx_callback(sloth_port, iqueue, rx_callback_stats, rx_batch_latency_counters[iqueue]);
	int ret;
        if (apply_prctl){
            click_chatter("Reducing PRCTL to minimal value\n");
            // Minimal value is 1, 0 sets to default
            ret = prctl(PR_SET_TIMERSLACK, 1, 0, 0, 0);
        } else {
            click_chatter("Setting PRCTL to default value\n");
            ret = prctl(PR_SET_TIMERSLACK, 0, 0, 0, 0);
        }

	    if (ret < 0) {
	        click_chatter("Error setting PRCTL : %d\n", ret);
	        return -1;
	    } else {
             ret = prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0);
             if (ret == -1) {
              perror("prctl(PR_GET_TIMERSLACK) failed");
              return -1;
             }
             unsigned long timerslack_ns = (unsigned long)ret;
             printf("Current timer slack: %lu ns\n", timerslack_ns);
           }
    }
    #endif
    // By default, iterate on a single queue given by iqueue
    uint8_t start_queue = iqueue;
    uint8_t end_queue = iqueue;
    uint8_t lcore_id = rte_lcore_id();
    // Metronome supposes that all queues are shared by all threads
    if ((_sleep_mode & (SLEEP_HR | SLEEP_HR2) || _sleep_mode & SLEEP_U) && _sleep_mode & SLEEP_POLICY_METRONOME) {
        start_queue = 0;
        end_queue = _nb_queues - 1;
    } else if (iqueue == NO_ASSIGNED_QUEUE){
    // If no specific queue was assigned, run on dev interval
        start_queue = queue_for_thisthread_begin();
        end_queue = queue_for_thisthread_end();
    }

    // If no sleep mode was set, do classical processing
    // Also, actuallypower entirely relies on DPDK's power management
    // and only performs classical processing
    if (!_sleep_mode || _sleep_mode & (SLEEP_POLICY_ACTUALLYPOWER | SLEEP_POLICY_SLOTH | SLEEP_POLICY_DUNEISH)) {
        bool ret = false;
        for (int queue = start_queue; queue <= end_queue; queue++) {
            ret |= _run_task(queue, NULL);
        }
        return ret;
    } else if (_sleep_mode & SLEEP_POLICY_TUPE) {

        //Copied from https://github.com/bigstone09/green-dpdk/blob/314388277d37a7ab77855616893af92b92cf0c52/l3fwd-acl-tupe/main3_acltupe.c#L1475
        if( unlikely( _fdstate->recv >= _fdstate->mini_period  || _fdstate->nb_idle_looped > _fdstate->idle_num_for_timer )){

            _fdstate->new_mini_period += _fdstate->recv;
            _fdstate->cur_tsc_power = rte_rdtsc();
            _fdstate->diff_tsc_power =  _fdstate->cur_tsc_power -  _fdstate->prev_tsc_power;
            // click_chatter("diff %lu, cur %lu, last %lu, res %lu",_fdstate->diff_tsc_power, _fdstate->cur_tsc_power ,_fdstate->prev_tsc_power,timer_resolution_cycles);
            if (_fdstate->diff_tsc_power >  timer_resolution_cycles ) {
                _fdstate->mini_period = _fdstate->new_mini_period/20;
                _fdstate->new_mini_period = 0;
                _fdstate->idle_num_for_timer = _fdstate->nb_idle_looped*0.7;
                rte_timer_manage();
                _fdstate->prev_tsc_power = _fdstate->cur_tsc_power;
            }
            _fdstate->idle_num_for_timer = _fdstate->nb_idle_looped + 10000;
            _fdstate->recv = 0;
        }
        uint8_t n = 0;
        for(uint8_t i = start_queue; i <= end_queue; i++) {
            n += _run_task(i, &_rx_queue[end_queue - start_queue].lock);
        }

        if (unlikely(n == 0)){
            /**
             * no packet received from rx queue, try to nap
             */
            _fdstate->nb_idle_looped++;
            if( _fdstate->time_sleep > 0 )
                nap_cycles( _fdstate->time_sleep );
            return 0;
        }
        return n;

    } else if (_sleep_mode & SLEEP_POLICY_MONITOR) {
        uint8_t n = 0;
        for(uint8_t i = start_queue; i <= end_queue; i++) {
            n += _run_task(i, &_rx_queue[end_queue - start_queue].lock);
        }

        assert(end_queue- start_queue == 0);
        if (unlikely(n == 0))
        {


            struct rte_power_monitor_cond pmc;
            int err = rte_eth_get_monitor_addr(_dev->port_id, start_queue,
					&pmc);
            if (err != 0) {
                click_chatter("Could not get monitor address ! Err %d : %d (%s)", err, rte_errno, rte_strerror(rte_errno));
                return false;
            }

            /* set address for memory monitor */
            intel_umonitor(pmc.addr);
            uint64_t tsc_timestamp = rte_get_tsc_cycles();
            intel_umwait(tsc_timestamp + _fdstate->time_sleep * (rte_get_tsc_hz()/ 1000000));

            if (_sleep_mode & SLEEP_MULT) {
                // Gestion du facteur multiplicatif
                _fdstate->time_sleep = _fdstate->time_sleep * _sleep_delta;
                if (_fdstate->time_sleep > _sleep_max)
                    _fdstate->time_sleep = _sleep_max;
            } else if (_sleep_mode & SLEEP_ADD) {
                _fdstate->time_sleep = _fdstate->time_sleep + _sleep_delta;
                if (_fdstate->time_sleep > _sleep_max)
                    _fdstate->time_sleep = _sleep_max;
            }
        } else {
            // Remise à zéro du temps de sleep
            _fdstate->time_sleep=_sleep_reset;
        }
        return n;
    } else if (_sleep_mode & SLEEP_POLICY_METRONOME) {
        // Metronome default processing
        uint8_t n = 0;
        for(uint8_t i = start_queue; i <= end_queue; i++) {
            if (!trylock(&_rx_queue[end_queue - start_queue].lock)){
                continue;
            }
            // _run_task will release the lock
            n += _run_task(i, &_rx_queue[end_queue - start_queue].lock);
            // Release the lock
            // _rx_queue[end_queue - start_queue].lock = UNLOCKED;
        }

        if (unlikely(n == 0))
        {
            if (_sleep_mode & SLEEP_MULT) {
            // Gestion du facteur multiplicatif
                _fdstate->time_sleep = _fdstate->time_sleep * _sleep_delta;
                if (_fdstate->time_sleep > _sleep_max)
                    _fdstate->time_sleep = _sleep_max;
            } else if (_sleep_mode & SLEEP_ADD) {
                _fdstate->time_sleep = _fdstate->time_sleep + _sleep_delta;
                if (_fdstate->time_sleep > _sleep_max)
                    _fdstate->time_sleep = _sleep_max;
            }

            // When the sleep time reaches a threshold, switch to interrupt mode
            if (_sleep_mode & SLEEP_INTR && _fdstate->time_sleep >= _suspend_threshold) {
                    // Triggers interrupts waiting
                    turn_on_off_intr(true, start_queue, end_queue);
                    sleep_until_rx_interrupt(end_queue - start_queue + 1, lcore_id);
                    _rx_queue[lcore_id].n_irq_wakeups++;
                    turn_on_off_intr(false, start_queue, end_queue);
            } else do_sleep(_fdstate->time_sleep);
        } else {
            // Remise à zéro du temps de sleep
            _fdstate->time_sleep=_sleep_reset;
	    }
        return n;
    } else if (_sleep_mode & SLEEP_POLICY_SIMPLE) {
        // Simple default processing
        uint8_t n = 0;

        for (int queue = start_queue; queue <= end_queue; queue++) {
            n |= _run_task(queue, NULL);
        }
        if (unlikely(n == 0))
        {
            // When the sleep time reaches a threshold, switch to interrupt mode
            if (_sleep_mode & SLEEP_INTR && ((_sleep_mode & SLEEP_CST) || _fdstate->time_sleep >= _suspend_threshold)) {
                // Triggers interrupts waiting
                turn_on_off_intr(true, start_queue, end_queue);
                sleep_until_rx_interrupt(end_queue - start_queue + 1, lcore_id);
                _rx_queue[lcore_id].n_irq_wakeups++;
                turn_on_off_intr(false, start_queue, end_queue);
            } else
                do_sleep(_fdstate->time_sleep);

            if (_sleep_mode & SLEEP_MULT) {
            // Gestion du facteur multiplicatif
                _fdstate->time_sleep = _fdstate->time_sleep * _sleep_delta;
                if (_fdstate->time_sleep > _sleep_max)
                    _fdstate->time_sleep = _sleep_max;
            } else if (_sleep_mode & SLEEP_ADD) {
                _fdstate->time_sleep = _fdstate->time_sleep + _sleep_delta;
                if (_fdstate->time_sleep > _sleep_max)
                    _fdstate->time_sleep = _sleep_max;
            }
        } else {
            // Remise à zéro du temps de sleep
            _fdstate->time_sleep=_sleep_reset;
	    }
        return n;
    } else if (_sleep_mode & SLEEP_POLICY_POWER){
        // Implements DPDK l3fwd-power example heuristics
        uint8_t total_rx = 0;
        for(uint8_t i = start_queue; i <= end_queue; i++) {
            uint8_t n = _run_task(i, NULL);
            _rx_queue[end_queue - start_queue].idle_hint = 0;
            total_rx += n;
            if (unlikely(n == 0)){
                _rx_queue[end_queue - start_queue].zero_rx_packet_count+= _sleep_delta;
                if (_rx_queue[end_queue - start_queue].zero_rx_packet_count <=
						MIN_ZERO_POLL_COUNT)
					continue;
                _rx_queue[end_queue - start_queue].idle_hint = power_idle_heuristic(
						_rx_queue[end_queue - start_queue].zero_rx_packet_count);
            } else {
                // printf("Packets received and sucessfully processed !\n");
                _rx_queue[end_queue - start_queue].zero_rx_packet_count = 0;
            }
        }
        // If there weren't any packets on any queue
        if(unlikely(total_rx == 0)) {
            // Collect minimal waiting time for conservative sleeping
            uint32_t min_idle_hint = UINT32_MAX;
            for(uint8_t i = start_queue; i <= end_queue; i++) {
                if (_rx_queue[end_queue - start_queue].idle_hint < min_idle_hint)
                    min_idle_hint = _rx_queue[end_queue - start_queue].idle_hint;
            }
            // Over a threshold, rely on interrupts instead of sleeping
            if (_sleep_mode & SLEEP_INTR && (min_idle_hint >= _suspend_threshold)) {
                    turn_on_off_intr(true, start_queue, end_queue);
                    sleep_until_rx_interrupt(end_queue - start_queue + 1, lcore_id);
                    _rx_queue[lcore_id].n_irq_wakeups++;
                    turn_on_off_intr(false, start_queue, end_queue);
            } else
                do_sleep(min_idle_hint);
        }
        return total_rx;
    } else {
        // This should not happened
        click_chatter("Unknown policy for sleep mode");
        return false;
    }
}

bool FromDPDKDevice::multi_run_task(Task *t, void* e) {
    FromDPDKDevice* fd = static_cast<FromDPDKDevice*>(e);
    bool ret = false;

    ret = fd->_process_packets(NO_ASSIGNED_QUEUE);

    t->fast_reschedule();
    return ret;
}

bool FromDPDKDevice::run_task(Task *t) {
    int iqueue = queue_for_thisthread_begin();
    bool ret = _process_packets(iqueue);

    t->fast_reschedule();
    return ret;
}

ToDPDKDevice *
FromDPDKDevice::find_output_element() {
    for (auto e : router()->elements()) {
        ToDPDKDevice *td = dynamic_cast<ToDPDKDevice *>(e);
        if (td != 0 && (td->_dev->port_id == _dev->port_id)) {
            return td;
        }
    }
    return 0;
}

enum {
    h_vendor, h_driver, h_carrier, h_duplex, h_autoneg, h_speed, h_type,
    h_ipackets, h_ibytes, h_imissed, h_ierrors, h_nombufs,
    h_stats_packets, h_stats_bytes,
    h_active, h_safe_active,
    h_irq,
    h_xstats, h_queue_count,
    h_nb_rx_queues, h_nb_tx_queues, h_nb_vf_pools,
    h_rss, h_rss_reta, h_rss_reta_size,
    h_mac, h_add_mac, h_remove_mac, h_vf_mac,
    h_mtu,
    h_device, h_isolate,
#if HAVE_FLOW_API
    h_rule_add, h_rules_del, h_rules_flush,
    h_rules_list, h_rules_list_with_hits, h_rules_ids_global, h_rules_ids_internal,
    h_rules_count, h_rules_count_with_hits, h_rule_packet_hits, h_rule_byte_count,
    h_rules_aggr_stats
#endif
};



String FromDPDKDevice::read_handler(Element *e, void * thunk)
{
    FromDPDKDevice *fd = static_cast<FromDPDKDevice *>(e);

    switch((uintptr_t) thunk) {
        case h_active:
              if (!fd->_dev)
                  return "false";
              else
                  return String(fd->_active);
        case h_device:
              if (!fd->_dev)
                  return "undefined";
              else
                  return String((int) fd->_dev->port_id);
        case h_irq:  {
            unsigned long tot = 0;
            if (fd->_rx_queue) {
                for (int i = 0; i < fd->_nb_queues; i++) {
                    tot += fd->_rx_queue[i].n_irq_wakeups;
                }
            }
            return String(tot);
        }
        case h_nb_rx_queues:
            return String(fd->_dev->nb_rx_queues());
        case h_nb_tx_queues:
            return String(fd->_dev->nb_tx_queues());
        case h_nb_vf_pools:
            return String(fd->_dev->nb_vf_pools());
        case h_mtu: {
            uint16_t mtu;
            if (rte_eth_dev_get_mtu(fd->_dev->port_id, &mtu) != 0)
                return String("<error>");
            return String(mtu);
                    }
        case h_mac: {
            if (!fd->_dev)
                return String::make_empty();
            struct rte_ether_addr mac_addr;
            rte_eth_macaddr_get(fd->_dev->port_id, &mac_addr);
            return EtherAddress((unsigned char*)&mac_addr).unparse_colon();
        }
        case h_vf_mac: {
#if HAVE_JSON
            Json jaddr = Json::make_array();
            for (int i = 0; i < fd->_dev->nb_vf_pools(); i++) {
                struct rte_ether_addr mac = fd->_dev->gen_mac(fd->_dev->port_id, i);
                jaddr.push_back(
                    EtherAddress(
                        reinterpret_cast<unsigned char *>(&mac)
                    ).unparse_colon());
            }
            return jaddr.unparse();
#else
            String s = "";
            for (int i = 0; i < fd->_dev->nb_vf_pools(); i++) {
                struct rte_ether_addr mac = fd->_dev->gen_mac(fd->_dev->port_id, i);
                s += EtherAddress(
                        reinterpret_cast<unsigned char *>(&mac)
                    ).unparse_colon() + ";";
            }
            return s;
#endif
        }
        case h_vendor:
            return fd->_dev->get_device_vendor_name();
        case h_driver:
            return String(fd->_dev->get_device_driver());
        case h_rss_reta_size:
		    return String(fd->_dev->dpdk_get_rss_reta_size());
        case h_rss_reta:
            StringAccum acc;
            Vector<unsigned> list = fd->_dev->dpdk_get_rss_reta();
            for (int i= 0; i < list.size(); i++) {
                acc << list[i] << " ";
            }
            return acc.take_string();
    }

    return 0;
}

String FromDPDKDevice::status_handler(Element *e, void * thunk)
{
    FromDPDKDevice *fd = static_cast<FromDPDKDevice *>(e);
    struct rte_eth_link link;
    if (!fd->_dev) {
        return "0";
    }

    rte_eth_link_get_nowait(fd->_dev->port_id, &link);
#ifndef ETH_LINK_UP
    #define ETH_LINK_UP 1
#endif
    switch((uintptr_t) thunk) {
      case h_carrier:
          return (link.link_status == ETH_LINK_UP ? "1" : "0");
      case h_duplex:
          return (link.link_status == ETH_LINK_UP ?
            (link.link_duplex == ETH_LINK_FULL_DUPLEX ? "1" : "0") : "-1");
#if RTE_VERSION >= RTE_VERSION_NUM(16,04,0,0)
      case h_autoneg:
          return String(link.link_autoneg);
#endif
      case h_speed:
          return String(link.link_speed);
      case h_type:
          //TODO
          return String("fiber");
    }
    return 0;
}

String FromDPDKDevice::statistics_handler(Element *e, void *thunk)
{
    FromDPDKDevice *fd = static_cast<FromDPDKDevice *>(e);
    struct rte_eth_stats stats;
    if (!fd->_dev) {
        return "0";
    }

    if (rte_eth_stats_get(fd->_dev->port_id, &stats))
        return String::make_empty();

    switch((uintptr_t) thunk) {
        case h_ipackets:
            return String(stats.ipackets);
        case h_ibytes:
            return String(stats.ibytes);
        case h_imissed:
            return String(stats.imissed);
        case h_ierrors:
            return String(stats.ierrors);
#if RTE_VERSION >= RTE_VERSION_NUM(18,05,0,0)
        case h_isolate: {
            return String(fd->get_device()->isolated() ? "1" : "0");
        }
#endif
    #if HAVE_FLOW_API
        case h_rules_list: {
            portid_t port_id = fd->get_device()->get_port_id();
            return FlowRuleManager::get_flow_rule_mgr(port_id)->flow_rules_list();
        }
        case h_rules_list_with_hits: {
            portid_t port_id = fd->get_device()->get_port_id();
            return FlowRuleManager::get_flow_rule_mgr(port_id)->flow_rules_list(true);
        }
        case h_rules_ids_global: {
            portid_t port_id = fd->get_device()->get_port_id();
            return FlowRuleManager::get_flow_rule_mgr(port_id)->flow_rule_ids_global();
        }
        case h_rules_ids_internal: {
            portid_t port_id = fd->get_device()->get_port_id();
            return FlowRuleManager::get_flow_rule_mgr(port_id)->flow_rule_ids_internal();
        }
        case h_rules_count: {
            portid_t port_id = fd->get_device()->get_port_id();
            return String(FlowRuleManager::get_flow_rule_mgr(port_id)->flow_rules_count_explicit());
        }
        case h_rules_count_with_hits: {
            portid_t port_id = fd->get_device()->get_port_id();
            return String(FlowRuleManager::get_flow_rule_mgr(port_id)->flow_rules_with_hits_count());
        }
    #endif
        case h_nombufs:
            return String(stats.rx_nombuf);
        default:
            return "<unknown>";
    }
}

int FromDPDKDevice::write_handler(
        const String &input, Element *e, void *thunk, ErrorHandler *errh) {
    FromDPDKDevice *fd = static_cast<FromDPDKDevice *>(e);
    if (!fd->_dev) {
        return -1;
    }

    switch((uintptr_t) thunk) {
        case h_add_mac: {
            EtherAddress mac;
            int pool = 0;
            int ret;
            if (!EtherAddressArg().parse(input, mac)) {
                return errh->error("Invalid MAC address %s",input.c_str());
            }

            ret = rte_eth_dev_mac_addr_add(
                fd->_dev->port_id,
                reinterpret_cast<rte_ether_addr*>(mac.data()), pool
            );
            if (ret != 0) {
                return errh->error("Could not add mac address!");
            }
            return 0;
        }
        case h_safe_active:
        case h_active: {
            bool active;
            if (!BoolArg::parse(input,active))
                return errh->error("Not a valid boolean");
            if (fd->_active != active) {
                fd->_active = active;
                Bitvector b(fd->router()->master()->nthreads());
                fd->get_spawning_threads(b, true, -1);
                if (fd->_active) { // Activating
                    fd->trigger_thread_reconfiguration(true,[fd,thunk](){
                        for (unsigned i = 0; i < fd->_thread_state.weight(); i++) {
                            if (fd->_thread_state.get_value(i).task)
                                fd->_thread_state.get_value(i).task->reschedule();
                        }
                        for (int q = 0; q <= fd->n_queues; q++) {
                            fd->thread_for_queue_offset(q);
                        }
                    }, b);
                } else { // Deactivating
                    fd->trigger_thread_reconfiguration(false,[fd](){
                        for (unsigned i = 0; i < fd->_thread_state.weight(); i++) {
                            if (fd->_thread_state.get_value(i).task)
                                fd->_thread_state.get_value(i).task->unschedule();
                        }

                        for (int q = 0; q <= fd->n_queues; q++) {
                            fd->thread_for_queue_offset(q);
                        }
                    }, b);
                }
            }
            return 0;
        }
        case h_rss: {
            int max;
            if (!IntArg().parse<int>(input,max))
                return errh->error("Not a valid integer");
            return fd->_dev->dpdk_set_rss_max(max);
        }
#if RTE_VERSION >= RTE_VERSION_NUM(18,05,0,0)
        case h_isolate: {
            if (input.empty()) {
                return errh->error("DPDK Flow Rule Manager (port %u): Specify isolation mode (true/1 -> isolation, otherwise no isolation)", fd->_dev->port_id);
            }
            bool status = (input.lower() == "true") || (input.lower() == "1") ? true : false;
            fd->_dev->set_isolation_mode(status);
            return 0;
        }
#endif

    }
    return -1;
}

#if HAVE_FLOW_API
int FromDPDKDevice::flow_handler(
        const String &input, Element *e, void *thunk, ErrorHandler *errh)
{
    FromDPDKDevice *fd = static_cast<FromDPDKDevice *>(e);
    if (!fd->get_device()) {
        return -1;
    }

    portid_t port_id = fd->get_device()->get_port_id();
    FlowRuleManager *flow_rule_mgr = FlowRuleManager::get_flow_rule_mgr(port_id, errh);
    assert(flow_rule_mgr);

    switch((uintptr_t) thunk) {
        case h_rule_add: {
            // Trim spaces left and right
            String rule = input.trim_space().trim_space_left();

            // A '\n' must be appended at the end of this rule, if not there
            int eor_pos = rule.find_right('\n');
            if ((eor_pos < 0) || (eor_pos != rule.length() - 1)) {
                rule += "\n";
            }

            // Detect and remove unwanted components
            if (!FlowRuleManager::flow_rule_filter(rule)) {
                return errh->error("DPDK Flow Rule Manager (port %u): Invalid rule '%s'", port_id, rule.c_str());
            }

            rule = "flow create " + String(port_id) + " " + rule;

            // Parse the queue index to infer the CPU core
            String queue_index_str = FlowRuleManager::fetch_token_after_keyword((char *) rule.c_str(), "queue index");
            int core_id = atoi(queue_index_str.c_str());

            const uint32_t int_rule_id = flow_rule_mgr->flow_rule_cache()->next_internal_rule_id();
            if (flow_rule_mgr->flow_rule_install(int_rule_id, (long) int_rule_id, core_id, rule) != 0) {
                return -1;
            }

            return static_cast<int>(int_rule_id);
        }
        case h_rules_del: {
            // Trim spaces left and right
            String rule_ids_str = input.trim_space().trim_space_left();

            // Split space-separated rule IDs
            Vector<String> rules_vec = rule_ids_str.split(' ');
            const uint32_t rules_nb = rules_vec.size();
            if (rules_nb == 0) {
                return -1;
            }

            // Store these rules IDs in an array
            uint32_t rule_ids[rules_nb];
            uint32_t i = 0;
            auto it = rules_vec.begin();
            while (it != rules_vec.end()) {
                rule_ids[i++] = (uint32_t) atoi(it->c_str());
                it++;
            }

            // Batch deletion
            return flow_rule_mgr->flow_rules_delete((uint32_t *) rule_ids, rules_nb);
        }
        case h_rules_flush: {
            return flow_rule_mgr->flow_rules_flush();
        }
    }

    return -1;
}
#endif

int FromDPDKDevice::xstats_handler(
        int operation, String &input, Element *e,
        const Handler *handler, ErrorHandler *errh) {
    FromDPDKDevice *fd = static_cast<FromDPDKDevice *>(e);
    if (!fd->_dev)
        return -1;

    int op = (intptr_t)handler->read_user_data();
    switch (op) {
        case h_xstats: {
            struct rte_eth_xstat_name *names;
        #if RTE_VERSION >= RTE_VERSION_NUM(16,07,0,0)
            int len = rte_eth_xstats_get_names(fd->_dev->port_id, 0, 0);
            names = static_cast<struct rte_eth_xstat_name *>(
                malloc(sizeof(struct rte_eth_xstat_name) * len)
            );
            rte_eth_xstats_get_names(fd->_dev->port_id, names, len);
            struct rte_eth_xstat *xstats;
            xstats = static_cast<struct rte_eth_xstat *>(malloc(
                sizeof(struct rte_eth_xstat) * len)
            );
            rte_eth_xstats_get(fd->_dev->port_id,xstats,len);
            if (input == "") {
                StringAccum acc;
                for (int i = 0; i < len; i++) {
                    acc << names[i].name << "[" <<
                           xstats[i].id << "] = " <<
                           xstats[i].value << "\n";
                }

                input = acc.take_string();
            } else {
                for (int i = 0; i < len; i++) {
                    if (strcmp(names[i].name,input.c_str()) == 0) {
                        input = String(xstats[i].value);
                        return 0;
                    }
                }
                return -1;
            }
            return 0;
        #else
            input = "unsupported with DPDK < 16.07";
            return -1;
        #endif
        }
        case h_queue_count:
            if (input == "") {
                StringAccum acc;
                for (uint16_t i = 0; i < fd->_dev->nb_rx_queues(); i++) {
                    int v = rte_eth_rx_queue_count(fd->_dev->get_port_id(), i);
                    acc << "Queue " << i << ": " << v << "\n";
                }
                input = acc.take_string();
            } else {
                int v = rte_eth_rx_queue_count(fd->_dev->get_port_id(), atoi(input.c_str()));
                input = String(v);
            }
            return 0;
    #if HAVE_FLOW_API
        case h_rule_byte_count:
        case h_rule_packet_hits: {
            portid_t port_id = fd->get_device()->get_port_id();
            FlowRuleManager *flow_rule_mgr = FlowRuleManager::get_flow_rule_mgr(port_id, errh);
            assert(flow_rule_mgr);
            if (input == "") {
                return errh->error("Aggregate flow rule counters are not supported. Please specify a rule number to query");
            } else {
                const uint32_t rule_id = atoi(input.c_str());
                int64_t matched_pkts = -1;
                int64_t matched_bytes = -1;
                flow_rule_mgr->flow_rule_query(rule_id, matched_pkts, matched_bytes);
                if (op == (int) h_rule_packet_hits) {
                    input = String(matched_pkts);
                } else {
                    input = String(matched_bytes);
                }
                return 0;
            }
        }
        case h_rules_aggr_stats: {
            portid_t port_id = fd->get_device()->get_port_id();
            FlowRuleManager *flow_rule_mgr = FlowRuleManager::get_flow_rule_mgr(port_id, errh);
            assert(flow_rule_mgr);
            input = flow_rule_mgr->flow_rule_aggregate_stats();
            return 0;
        }
    #endif
        case h_stats_packets:
        case h_stats_bytes: {
            struct rte_eth_stats stats;
            if (rte_eth_stats_get(fd->_dev->port_id, &stats))
                return -1;

            int id = atoi(input.c_str());
            if (id < 0 || id > RTE_ETHDEV_QUEUE_STAT_CNTRS)
                return -EINVAL;
            uint64_t v;
            if (op == (int) h_stats_packets)
                 v = stats.q_ipackets[id];
            else
                 v = stats.q_ibytes[id];
            input = String(v);
            return 0;
        }
        default:
            return -1;
    }
}

void FromDPDKDevice::add_handlers()
{
    add_read_handler("device",read_handler, h_device);

    add_read_handler("duplex",status_handler, h_duplex);
#if RTE_VERSION >= RTE_VERSION_NUM(16,04,0,0)
    add_read_handler("autoneg",status_handler, h_autoneg);
#endif
    add_read_handler("speed",status_handler, h_speed);
    add_read_handler("carrier",status_handler, h_carrier);
    add_read_handler("type",status_handler, h_type);

    set_handler("xstats", Handler::f_read | Handler::f_read_param, xstats_handler, h_xstats);
    set_handler("queue_count", Handler::f_read | Handler::f_read_param, xstats_handler, h_queue_count);
    set_handler("queue_packets", Handler::f_read | Handler::f_read_param, xstats_handler, h_stats_packets);
    set_handler("queue_bytes", Handler::f_read | Handler::f_read_param, xstats_handler, h_stats_bytes);
#if HAVE_FLOW_API
    set_handler(FlowRuleManager::FLOW_RULE_PACKET_HITS, Handler::f_read | Handler::f_read_param, xstats_handler, h_rule_packet_hits);
    set_handler(FlowRuleManager::FLOW_RULE_BYTE_COUNT,  Handler::f_read | Handler::f_read_param, xstats_handler, h_rule_byte_count);
    set_handler(FlowRuleManager::FLOW_RULE_AGGR_STATS,  Handler::f_read | Handler::f_read_param, xstats_handler, h_rules_aggr_stats);
#endif

    add_read_handler("active", read_handler, h_active);
    add_write_handler("active", write_handler, h_active);
    add_write_handler("safe_active", write_handler, h_safe_active);
    add_read_handler("count", count_handler, h_count);
    add_write_handler("reset_counts", reset_count_handler, 0, Handler::BUTTON);
    add_read_handler("nb_irq_wakeups", read_handler, h_irq);

    add_read_handler("nb_rx_queues",read_handler, h_nb_rx_queues);
    add_read_handler("nb_tx_queues",read_handler, h_nb_tx_queues);
    add_read_handler("nb_vf_pools",read_handler, h_nb_vf_pools);
    add_data_handlers("nb_rx_desc", Handler::h_read, &ndesc);

    add_read_handler("mac",read_handler, h_mac);
    add_read_handler("vendor", read_handler, h_vendor);
    add_read_handler("driver", read_handler, h_driver);
    add_write_handler("add_mac",write_handler, h_add_mac, 0);
    add_write_handler("remove_mac",write_handler, h_remove_mac, 0);
    add_read_handler("vf_mac_addr",read_handler, h_vf_mac);

    add_write_handler("max_rss", write_handler, h_rss, 0);
    add_read_handler("rss_reta",read_handler, h_rss_reta);
    add_read_handler("rss_reta_size",read_handler, h_rss_reta_size);

    add_read_handler("hw_count",statistics_handler, h_ipackets);
    add_read_handler("hw_bytes",statistics_handler, h_ibytes);
    add_read_handler("hw_dropped",statistics_handler, h_imissed);
    add_read_handler("hw_errors",statistics_handler, h_ierrors);
    add_read_handler("nombufs",statistics_handler, h_nombufs);

    add_write_handler("flow_isolate", write_handler, h_isolate, 0);
    add_read_handler ("flow_isolate", statistics_handler, h_isolate);

#if HAVE_FLOW_API
    add_write_handler(FlowRuleManager::FLOW_RULE_ADD,     flow_handler, h_rule_add,    0);
    add_write_handler(FlowRuleManager::FLOW_RULE_DEL,     flow_handler, h_rules_del,   0);
    add_write_handler(FlowRuleManager::FLOW_RULE_FLUSH,   flow_handler, h_rules_flush, 0);
    add_read_handler (FlowRuleManager::FLOW_RULE_IDS_GLB,         statistics_handler, h_rules_ids_global);
    add_read_handler (FlowRuleManager::FLOW_RULE_IDS_INT,         statistics_handler, h_rules_ids_internal);
    add_read_handler (FlowRuleManager::FLOW_RULE_LIST,            statistics_handler, h_rules_list);
    add_read_handler (FlowRuleManager::FLOW_RULE_LIST_WITH_HITS,  statistics_handler, h_rules_list_with_hits);
    add_read_handler (FlowRuleManager::FLOW_RULE_COUNT,           statistics_handler, h_rules_count);
    add_read_handler (FlowRuleManager::FLOW_RULE_COUNT_WITH_HITS, statistics_handler, h_rules_count_with_hits);
#endif

    add_read_handler("mtu",read_handler, h_mtu);
    add_data_handlers("burst", Handler::h_read | Handler::h_write, &_burst);
}

