// -*- c-basic-offset: 4 -*-
#ifndef CLICK_BATCHELEMENT_HH
#define CLICK_BATCHELEMENT_HH
#include <click/glue.hh>
#include <click/vector.hh>
#include <click/string.hh>
#include <click/packet.hh>
#include <click/handler.hh>
#include <click/master.hh>
#include <click/element.hh>
#include <click/packet_anno.hh>
#include <click/routervisitor.hh>

/**
 * This file utilizes the Curiously Recurring Template Pattern (CRTP)
 * to provide an effective way of implementing helper template in Click
 * without adding costly virtual calls.
 */


CLICK_DECLS

#ifdef HAVE_BATCH

class PushToPushBatchVisitor;
class BatchModePropagate;


class BatchElement : public Element { public:
    BatchElement();

    ~BatchElement();

    virtual PacketBatch* simple_action_batch(PacketBatch* batch) {
        click_chatter("Warning in %s : simple_action_batch should be implemented."
         " This element is useless, batch will be returned untouched.",name().c_str());
        return batch;
    }

    virtual void push_batch(int port, PacketBatch* head) {
        head = simple_action_batch(head);
        if (head)
            output_push_batch(port,head);
    }

    virtual PacketBatch* pull_batch(int port, unsigned max) {
        PacketBatch* head = input_pull_batch(port,max);
        if (head) {
            head = simple_action_batch(head);
        }
        return head;
    }

    inline void checked_output_push_batch(int port, PacketBatch* batch) {
         if ((unsigned) port < (unsigned) noutputs()) {
#if BATCH_DEBUG
             assert(in_batch_mode == BATCH_MODE_YES);
#endif
             output_push_batch(port,batch);
         } else
             batch->fast_kill();
    }

    inline void checked_output_push(int port, Packet* p)
    {
        if ((unsigned) port < (unsigned) noutputs()) {
            if (in_batch_mode == BATCH_MODE_YES) {
                output_push_batch(port,PacketBatch::make_from_packet(p));
            } else {
                _ports[1][port].push(p);
            }
        } else {
            p->kill();
        }
    }

    inline void
    output_push_batch(int port, PacketBatch* batch) {
        output(port).push_batch(batch);
    }

    inline void
    output_push(int port, Packet* p) {
        if (in_batch_mode == BATCH_MODE_YES) {
            output(port).push_batch(PacketBatch::make_from_packet(p));
        } else {
            output(port).push(p);
        }
    }


    inline PacketBatch*
    input_pull_batch(int port, int max) {
        return input(port).pull_batch(max);
    }


protected :

    /**
     * Propagate a BATCH_MODE_YES upstream or downstream
     */
    class BatchModePropagate : public RouterVisitor { public:
        bool ispush;

        BatchModePropagate() : ispush(true) {}

        bool visit(Element *e, bool isoutput, int,
                Element *, int, int);
    };

    /**
     * RouterVisitor finding all reachable batch-enabled element
     */
    class PushToPushBatchVisitor : public RouterVisitor { public:

        PushToPushBatchVisitor(Element* origin);

        bool visit(Element *, bool, int,
                Element *, int, int);
        Element* _origin;
    };

    friend class Router;
};

#define BATCH_ELEMENT_DEFINE_SIMPLE_ACTION_BATCH(T) \
    PacketBatch* simple_action_batch(PacketBatch* batch) override {\
        EXECUTE_FOR_EACH_PACKET_DROPPABLE(T::simple_action,batch,[](Packet*){});\
        return batch;\
    }

#else
#define BATCH_ELEMENT_DEFINE_SIMPLE_ACTION_BATCH(T)
class BatchElement : public Element { public:
    inline void checked_output_push_batch(int, PacketBatch*) {
        click_chatter("Error : checked_output_push_batch called without batching being enabled");
        assert(false);
    }

    inline void
    output_push(int port, Packet* p) {
        output(port).push(p);
    }
};
#endif

/**
 * Batch helper element.
 *
 * Implement a (batch-compatible) element only by providing a function that
 *  returns a port index. It uses CRTP so no virtual call is added.
 *
 * Inherited class must implement inline int classify(Packet* p);
 *
 * The inherited element cannot be extended further because of CRTP !
 */

template <typename T, typename Base = BatchElement>
class ClassifyElement : public Base { public:

    void push(int, Packet *p) {
        Base::checked_output_push(static_cast<T&>(*this).classify(p),p);
    }

#if HAVE_BATCH
    void push_batch(int, PacketBatch *batch) {
          CLASSIFY_EACH_PACKET(Base::noutputs() + 1, static_cast<T&>(*this).classify,batch,Base::checked_output_push_batch);
    }
#endif

    private:
        ClassifyElement(){};
        friend T;
};


/**
 * Batch helper element.
 *
 * Allows the user to simply implement simple_action and simple_action_batch
 *  but relying on CRTP instead of virtual, removing one virtual call.
 *
 * The inherited element cannot be extended further because of CRTP !
 */
template <typename T>
class SimpleBatchElement : public BatchElement { public:

    void push(int port, Packet *p) override {
        p = static_cast<T&>(*this).simple_action(p);
        if (p)
            output(port).push(p);
    }

    Packet* pull(int port) override {
        Packet *p = input(port).pull();
        if (p)
            p = static_cast<T&>(*this).simple_action(p);
        return p;
    }

#if HAVE_BATCH
    void push_batch(int port, PacketBatch* head) override final {
        head = static_cast<T&>(*this).simple_action_batch(head);
        if (head)
            output_push_batch(port,head);
    }

    PacketBatch* pull_batch(int port, unsigned max) override final {
        PacketBatch* head = input_pull_batch(port,max);
        if (head)
            head = static_cast<T&>(*this).simple_action_batch(head);
        return head;
    }
#endif

    private:
        SimpleBatchElement(){};
        friend T;

};



template <typename T, typename Parent>
class SimpleInheritedElement : public Parent { public:

    void push(int port, Packet *p) override {
        p = static_cast<T&>(*this).simple_action(p);
        if (p)
            Parent::output(port).push(p);
    }

    Packet* pull(int port) override {
        Packet *p = Parent::input(port).pull();
        if (p)
            p = static_cast<T&>(*this).simple_action(p);
        return p;
    }

#if HAVE_BATCH
    void push_batch(int port, PacketBatch* head) override  {
            EXECUTE_FOR_EACH_PACKET_DROPPABLE(static_cast<T&>(*this).simple_action, head, [](Packet*){});
        if (head)
            Parent::output(port).push_batch(head);
    }

    PacketBatch* pull_batch(int port, unsigned max) override {
        PacketBatch* head = Parent::input_pull_batch(port,max);
        if (head)
            head = _sm_action_batch(head);
        return head;
    }
#endif

  private:

    inline PacketBatch* _sm_action_batch(PacketBatch* batch) {
        EXECUTE_FOR_EACH_PACKET_DROPPABLE(static_cast<T&>(*this).simple_action, batch, [](Packet*){});
        return batch;
    }

    SimpleInheritedElement(){};
    friend T;

};

/**
 * Batch helper element.
 *
 * Build an element that implements only simple_action, and
 * which does not call pull or push. Just extend SimpleElement<T> where T
 * is the new element itself.
 * It also avoids the virtual call, so a vanilla element using
 * this version even without batching will run faster.
 *
 * Downside :
 * The inherited element cannot be extended further because of CRTP !
 */
template <typename T>
using SimpleElement = SimpleInheritedElement<T,BatchElement>;

CLICK_ENDDECLS
#endif
