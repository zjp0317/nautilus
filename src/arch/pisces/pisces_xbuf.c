#include <arch/pisces/pisces_types.h>
#include <arch/pisces/pisces_xbuf.h>
#include <nautilus/nautilus.h>
#include <nautilus/spinlock.h>
#include <nautilus/scheduler.h>
#include <nautilus/irq.h>
#include <nautilus/waitqueue.h>

#ifndef NAUT_CONFIG_DEBUG_PISCES_XBUF
#undef DEBUG_PRINT
#define DEBUG_PRINT(fmt, args...) 
#endif

#define DEBUG(fmt, args...) DEBUG_PRINT("PISCES_XBUF: " fmt, ##args)
#define INFO(fmt, args...)  INFO_PRINT("PISCES_XBUF: " fmt, ##args)
#define WARN(fmt, args...)  WARN_PRINT("PISCES_XBUF: " fmt, ##args)
#define ERROR(fmt, args...) ERROR_PRINT("PISCES_XBUF: " fmt, ##args)

#if defined(CONFIG_X86_EARLYMIC)
#define mb()  asm volatile ("lock; addl $0,0(%%rsp)" ::: "memory")
#define rmb() asm volatile ("lock; addl $0,0(%%rsp)" ::: "memory")
#define wmb() asm volatile ("lock; addl $0,0(%%rsp)" ::: "memory")
#else
#define mb()  asm volatile("mfence":::"memory")
#define rmb() asm volatile("lfence":::"memory")
#define wmb() asm volatile("sfence" ::: "memory")
#endif

#define XBUF_READY     0x01ULL
#define XBUF_PENDING   0x02ULL
#define XBUF_STAGED    0x04ULL
#define XBUF_ACTIVE    0x08ULL
#define XBUF_COMPLETE  0x10ULL

struct pisces_xbuf {
	union {
		u64 flags;
		struct {
			u64 ready          : 1;   /* Flag set by enclave OS, after channel is init'd      */
			u64 pending        : 1;   /* Set when a message is ready to be received           */
			u64 staged         : 1;   /* Used by the endpoints for staged data transfers      */
			u64 active         : 1;   /* Set when a message has been accepted by the receiver */
			u64 complete       : 1;   /* Set by the receiver when message has been handled    */
			u64 rsvd           : 59;
		} __attribute__((packed));
	} __attribute__((packed));
    
	u32 host_apic;
	u32 host_vector;
	u32 enclave_cpu;
    u32 enclave_vector;
    u32 total_size;

    u32 data_len;

    u8 data[0];
} __attribute__((packed));

static int check_xbuf_cond(void *state) {
    return ((struct pisces_xbuf*)state)->pending == 0;
}

static void reset_flags(struct pisces_xbuf * xbuf) {
    u64 flags = XBUF_READY;

    __asm__ __volatile__ ("lock andq %1, %0;"
            : "+m"(xbuf->flags)
            : "r"(flags)
            : "memory");

}


static void set_flags(struct pisces_xbuf * xbuf, u64 new_flags) {
    __asm__ __volatile__ ("lock xchgq %1, %0;"
            : "+m"(xbuf->flags), "+r"(new_flags)
            : 
            : "memory");
}

static void raise_flag(struct pisces_xbuf * xbuf, u64 flags) {
    __asm__ __volatile__ ("lock orq %1, %0;"
            : "+m"(xbuf->flags)
            : "r"(flags)
            : "memory");
}

static void lower_flag(struct pisces_xbuf * xbuf, u64 flags) {
    u64 inv_flags = ~flags;

    __asm__ __volatile__ ("lock andq %1, %0;"
            : "+m"(xbuf->flags)
            : "r"(inv_flags)
            : "memory");
}

static u32 
init_stage_data(struct pisces_xbuf * xbuf, u8 * data, u32 data_len) 
{
    u32 xbuf_size  = xbuf->total_size;
    u32 staged_len = (data_len > xbuf_size) ? xbuf_size : data_len;

    xbuf->data_len = data_len;

    memcpy(xbuf->data, data, staged_len);
    raise_flag(xbuf, XBUF_STAGED);
    //xbuf->staged = 1;
    mb();

    return staged_len;
}

static u32 
send_data(struct pisces_xbuf * xbuf, u8 * data, u32 data_len) 
{
    u32 xbuf_size  = xbuf->total_size;
    u32 bytes_sent = 0;
    u32 bytes_left = data_len;

    while (bytes_left > 0) {
        u32 staged_len = (bytes_left > xbuf_size) ? xbuf_size : bytes_left;

        __asm__ __volatile__ ("":::"memory");
        if (!xbuf->ready) {
            printk("XBUF disabled during data transfer\n");
            return 0;
        }

        while (xbuf->staged == 1) {

            __asm__ __volatile__ ("":::"memory");
            if (!xbuf->ready) {
                printk("XBUF disabled during data transfer\n");
                return 0;
            }

            nk_sched_yield(0); //nk_sched_kick_cpu(my_cpu_id());
            __asm__ __volatile__ ("":::"memory");
        }

        memcpy(xbuf->data, data + bytes_sent, staged_len);
        //	xbuf->staged = 1;
        raise_flag(xbuf, XBUF_STAGED);
        mb();

        bytes_sent += staged_len;
        bytes_left -= staged_len;
    }

    return bytes_sent;
}

static u32 
recv_data(struct pisces_xbuf * xbuf, u8 ** data, u32 * data_len)
{
    u32 xbuf_size  = xbuf->total_size;
    u32 bytes_read = 0;
    u32 bytes_left = xbuf->data_len;

    while (xbuf->staged == 0) {
        nk_sched_yield(0); //nk_sched_kick_cpu(my_cpu_id());
        __asm__ __volatile__ ("":::"memory");
    }

    *data_len = xbuf->data_len;
    *data     = kmem_malloc(*data_len);


    //printk("Reading %u bytes\n", bytes_left);
    while (bytes_left > 0) {
        u32 staged_len = (bytes_left > xbuf_size) ? xbuf_size : bytes_left;

        __asm__ __volatile__ ("":::"memory");
        if (!xbuf->ready) {
            printk("XBUF disabled during data transfer\n");
            return 0;
        }

        while (xbuf->staged == 0) {

            __asm__ __volatile__ ("":::"memory");
            if (!xbuf->ready) {
                printk("XBUF disabled during data transfer\n");
                return 0;
            }

            nk_sched_yield(0); //nk_sched_kick_cpu(my_cpu_id());
            __asm__ __volatile__ ("":::"memory");
        }

        //printk("Copying data (%d bytes) (bytes_left=%d) (xbuf_size=%d)\n", staged_len, bytes_left, xbuf_size);

        memcpy(*data + bytes_read, xbuf->data, staged_len);

        //	xbuf->staged = 0;
        lower_flag(xbuf, XBUF_STAGED);
        mb();

        bytes_read += staged_len;
        bytes_left -= staged_len;
    }

    return bytes_read;
}

int 
pisces_xbuf_sync_send(struct pisces_xbuf_desc * desc, 
        u8                      * data, 
        u32                       data_len,
        u8                     ** resp_data, 
        u32                     * resp_len) 
{
    struct pisces_xbuf * xbuf     = desc->xbuf;
    unsigned int         flags    = 0;
    unsigned long        irqflags = 0;
    int                  acquired = 0;

    //printk("Sending XBUF request (idx=%llu)\n", xbuf_op_idx++);

    while (acquired == 0) {

        flags = spin_lock_irq_save(&(desc->xbuf_lock));
        {

            __asm__ __volatile__ ("":::"memory");
            if (!xbuf->ready) {
                printk("Attempted to send to unready xbuf\n");
                spin_unlock_irq_restore(&(desc->xbuf_lock), flags);
                goto err;
            }

            if (xbuf->pending == 0) {
                // clear all flags and signal that message is pending */
                //	    xbuf->flags = XBUF_READY | XBUF_PENDING;
                reset_flags(xbuf);
                raise_flag(xbuf, XBUF_PENDING);
                acquired = 1;
            }
        }
        spin_unlock_irq_restore(&(desc->xbuf_lock), flags);

        if (!acquired) {
            //wait_event_interruptible(desc->xbuf_waitq, (xbuf->pending == 0));
            nk_wait_queue_sleep_extended(&desc->xbuf_waitq, check_xbuf_cond, xbuf);
        }
    }

    if ((data != NULL) && (data_len > 0)) {
        u32 bytes_staged = 0;

        bytes_staged = init_stage_data(xbuf, data, data_len);

        //printk("Staged %u bytes of data\n", bytes_staged);

        data_len -= bytes_staged;
        data     += bytes_staged;
    }

    //printk("Sending IPI %d to cpu %d\n", xbuf->host_vector, xbuf->host_apic);
    apic_ipi(per_cpu_get(apic), xbuf->host_apic, xbuf->host_vector);
    /*
       local_irq_save(irqflags);
       {
       lapic_send_ipi_to_apic(xbuf->host_apic, xbuf->host_vector);
       }
       local_irq_restore(irqflags);
     */
    //printk("IPI completed\n");

    send_data(xbuf, data, data_len);

    //printk("XBUF has been sent\n");

    /* Wait for complete flag to be 1 */
    while (xbuf->complete == 0) {

        __asm__ __volatile__ ("":::"memory");
        if (!xbuf->ready) {
            printk("XBUF disabled during data transfer\n");
            goto err;
        }

        nk_sched_yield(0); //nk_sched_kick_cpu(my_cpu_id());
        __asm__ __volatile__ ("":::"memory");
    }

    //printk("XBUF is complete\n");

    if ((resp_data) && (xbuf->staged == 1)) {
        // Response exists and we actually want to retrieve it
        recv_data(xbuf, resp_data, resp_len);
    }


    mb();
    reset_flags(xbuf);
    mb();

    nk_wait_queue_wake_all_extended(&(desc->xbuf_waitq), 1); // waitq_wakeup(&(desc->xbuf_waitq));
    return 0;

err:
    nk_wait_queue_wake_all_extended(&(desc->xbuf_waitq), 1); // waitq_wakeup(&(desc->xbuf_waitq));
    return -1;
}

int 
pisces_xbuf_send(struct pisces_xbuf_desc * desc, u8 * data, u32 data_len) 
{
    return pisces_xbuf_sync_send(desc, data, data_len, NULL, NULL);
}

int 
pisces_xbuf_complete(struct pisces_xbuf_desc * desc, 
        u8                      * data, 
        u32                       data_len) 
{
    struct pisces_xbuf * xbuf = desc->xbuf;

    //printk("Completing Xbuf xfer (data_len = %u) (data=%p)\n", data_len, data);

    if (xbuf->active == 0) {
        printk("Error: Attempting to complete an inactive xbuf\n");
        return -1;
    }

    //    xbuf->active = 0;
    lower_flag(xbuf, XBUF_ACTIVE);

    __asm__ __volatile__ ("":::"memory");

    if ((data_len > 0) && (data != NULL)) {
        u32 bytes_staged = 0;
        //printk("initing staged data\n");

        bytes_staged = init_stage_data(xbuf, data, data_len);

        data_len -= bytes_staged;
        data     += bytes_staged;
    }

    __asm__ __volatile__ ("":::"memory");

    raise_flag(xbuf, XBUF_COMPLETE);
    //    xbuf->complete = 1;    

    __asm__ __volatile__ ("":::"memory");

    printk("Xbuf IS now complete\n");

    send_data(xbuf, data, data_len);

    printk("XBUF response is fully sent\n");

    return 0;
}

static int 
ipi_handler (excp_entry_t * excp, 
             excp_vec_t vec,
             void *state)
{	
    struct pisces_xbuf_desc * desc = state; //dev_id;
    struct pisces_xbuf      * xbuf = NULL;
    u8 * data      = NULL;
    u32  data_len  = 0;
    int ret = 0;

    printk("\nIPI Received\n");
    printk("desc=%p\n", desc);

    if (desc == NULL) {
        printk("IPI Handled for unknown XBUF\n");
        ret = -1;
        goto end;
    }

    xbuf = desc->xbuf;

    if (xbuf->active == 1) {
        printk("Error IPI for active xbuf, this should be impossible\n");
        ret = -1;
        goto end;
    }

    __asm__ __volatile__ ("":::"memory");
    if (!xbuf->ready) {
        printk("IPI Arrived for disabled XBUF\n");
        //	xbuf->complete = 1;
        raise_flag(xbuf, XBUF_COMPLETE);
        ret = 0;
        goto end;
    }

    //printk("Receiving Data\n");
    recv_data(xbuf, &data, &data_len);
    //printk("Data_len=%d\n", data_len);

    //xbuf->active = 1;
    raise_flag(xbuf, XBUF_ACTIVE);
    mb();
    __asm__ __volatile__ ("":::"memory");

    if (desc->recv_handler) {
        //printk("Calling Receive handler for IPI\n");
        desc->recv_handler(data, data_len, desc->private_data);
    } else {
        printk("IPI Arrived for XBUF without a handler\n");
        //	xbuf->complete = 1;
        raise_flag(xbuf, XBUF_COMPLETE);
    }
end:
    IRQ_HANDLER_END();
    return ret;
}

struct pisces_xbuf_desc * 
pisces_xbuf_server_init(uintptr_t   xbuf_va, 
        u32         xbuf_total_bytes, 
        void      (*recv_handler)(u8 * data, u32 data_len, void * priv_data), 
        void      * private_data, 
        u32         ipi_vector,
        u32         target_cpu) 
{
    struct pisces_xbuf_desc * desc = NULL;
    struct pisces_xbuf      * xbuf = (struct pisces_xbuf *)xbuf_va;

    desc = kmem_malloc(sizeof(struct pisces_xbuf_desc));

    if (desc == NULL) {
        printk("Could not allocate xbuf state\n");
        return NULL;
    }

    // reserve one with reserved_irq_handler
    if (ipi_vector == -1) {
        if (idt_find_and_reserve_range(1,1,(ulong_t*)&ipi_vector)) {
            printk("Cannot find/reserve one vector\n");
            kmem_free(desc);
            return NULL;
        }
    }
    // register the reserved one
    register_int_handler(ipi_vector, ipi_handler, desc);

    xbuf->enclave_cpu    = target_cpu;
    xbuf->enclave_vector = ipi_vector;
    xbuf->total_size     = xbuf_total_bytes - sizeof(struct pisces_xbuf);


    desc->xbuf         = xbuf;
    desc->private_data = private_data;
    desc->recv_handler = recv_handler;

    spinlock_init(&(desc->xbuf_lock));
    nk_wait_queue_initialize(&(desc->xbuf_waitq), NULL); // nk_queue_init(&(desc->xbuf_waitq));

    //    xbuf->ready = 1;
    set_flags(xbuf, 0);
    set_flags(xbuf, XBUF_READY);
    return desc;
}

int
pisces_xbuf_server_deinit(struct pisces_xbuf_desc * xbuf_desc)
{
    // free irq by registering null_irq_handler
    register_int_handler(xbuf_desc->xbuf->enclave_vector, null_irq_handler, NULL);

    set_flags(xbuf_desc->xbuf, 0);

    kmem_free(xbuf_desc);

    return 0;
}

struct pisces_xbuf_desc * 
pisces_xbuf_client_init(uintptr_t xbuf_va,
        u32       ipi_vector, 
        u32       target_cpu)
{
    struct pisces_xbuf      * xbuf = (struct pisces_xbuf *)xbuf_va;
    struct pisces_xbuf_desc * desc = kmem_malloc(sizeof(struct pisces_xbuf_desc));

    //printk("XBUF client init At VA=%p\n", (void *)xbuf_va);

    if ((desc == NULL) || (xbuf == NULL)) {
        printk("Error initializing xbuf\n");
        return NULL;
    }

    //printk("LCALL IPI %d to APIC %d\n", xbuf->host_vector, xbuf->host_apic);

    memset(desc, 0, sizeof(struct pisces_xbuf_desc));

    xbuf->enclave_cpu    = target_cpu;
    xbuf->enclave_vector = ipi_vector;

    desc->xbuf = xbuf;
    spinlock_init(&(desc->xbuf_lock));
    nk_wait_queue_initialize(&(desc->xbuf_waitq), NULL); // nk_queue_init(&(desc->xbuf_waitq));

    return desc;
}

int 
pisces_xbuf_disable(struct pisces_xbuf_desc * desc)
{
    struct pisces_xbuf * xbuf = desc->xbuf;

    __asm__ __volatile__ ("":::"memory");
    if ( !xbuf->ready ) {
        printk("Tried to disable an already disabled xbuf\n");
        return -1;
    }

    lower_flag(xbuf, XBUF_READY);

    return 0;
}

int 
pisces_xbuf_enable(struct pisces_xbuf_desc * desc)
{
    struct pisces_xbuf * xbuf = desc->xbuf;

    __asm__ __volatile__ ("":::"memory");
    if (xbuf->ready) {
        printk("Tried to enable an already enabled xbuf\n");
        return -1;
    }

    set_flags(xbuf, XBUF_READY);

    return 0;
}
