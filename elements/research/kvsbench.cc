// -*- c-basic-offset: 4 -*-
/*
 * KVSBench.{cc,hh} --
 * Tom Barbette
 *
 * Copyright (c) 2017 University of Liege
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

#include <click/config.h>
#include "kvsbench.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/standard/scheduleinfo.hh>

#define FRAND_MAX _gens->max()

CLICK_DECLS

std::random_device KVSBench::rd;


KVSBench::KVSBench()
{
}

int
KVSBench::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int s;
    if (Args(conf, this, errh)
        .read_or_set("S", s, 0) //Number of keys in MB
.read_or_set("OFFSET", _offset, 0)
        .read_or_set("VALUE_SIZE", _value_size, 64) //Value size
        .complete() < 0)
        return -1;

    _nb_keys = s * 1024 * 1024 / _value_size;
    click_chatter("%u keys, total size %lu",_nb_keys, _nb_keys  * _value_size);
    _array =(unsigned char*) malloc(_nb_keys  * _value_size);
    if (!_array)
        return errh->error("Could not allocate memory!");

    std::mt19937 g(rd());

    for (int i = 0; i < _nb_keys; i++) {
        unsigned char* value = (unsigned char*)_array + (i * _value_size);
        for (int j = 0; j < _value_size / 4; j++)
            ((uint32_t*) value)[j] = g();
        if (i % 1000000 == 0)
            click_chatter("Generated %d keys", i);
    }

    return 0;
}

Packet*
KVSBench::simple_action(Packet* p_in)
{
    WritablePacket* p = p_in->uniqueify();

    unsigned char* data = (unsigned char*)( p->udp_header() + 1) + _offset;
    //click_chatter("T %p, pos %d, payload len %d",  p->udp_header() + 1, data - p->data(), p->end_data() - data);
    uint64_t key = *(unsigned*)data;
    //click_chatter("Key %lu", key);
    p->udp_header()->uh_ulen = _value_size + sizeof(click_udp);
    unsigned char* value = (unsigned char*)_array + ((key % _nb_keys) * _value_size);
    memcpy(data, value, _value_size);
    int resize = (p->end_data() - data) - _value_size;
    if (resize < 0)
        p = p->put(-resize);
    else if (resize > 0)
        p->take(resize);
    return p;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(KVSBench)
