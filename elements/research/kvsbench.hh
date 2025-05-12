// -*- c-basic-offset: 4 -*-
#ifndef CLICK_KVSBench_HH
#define CLICK_KVSBench_HH
#include <click/batchelement.hh>
#include "../standard/counter.hh"
#include <random>

CLICK_DECLS

/*
=c

KVSBench(W, N)

=s test

Compute a random number for a certain amount of W time, and makes N accesses to

*/
class KVSBench : public SimpleElement<KVSBench> {
    public:
        KVSBench() CLICK_COLD;

        const char *class_name() const override { return "KVSBench"; }
        const char *port_count() const override { return "1-/="; }
        const char *processing() const override { return PUSH; }

        int configure(Vector<String>&, ErrorHandler*) override;
        Packet* simple_action(Packet* p);

    private:
        
        unsigned char* _array;
        unsigned _value_size;
        uint64_t _nb_keys;
        int _offset;
        static std::random_device rd;
};

CLICK_ENDDECLS
#endif
