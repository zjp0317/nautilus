#include <nautilus/nautilus.h> 
#include <nautilus/waitqueue.h> 
#include <nautilus/mm.h> 
#include <nautilus/naut_types.h>
#include <nautilus/list.h>
#include <nautilus/naut_assert.h>
#include <nautilus/irq.h>

#include <arch/pisces/pisces_drequest.h>

#define DREQUEST_DEBUG 1

#define DR_PRINT(fmt, args...)  INFO_PRINT(fmt, ##args)
#define DR_ERROR(fmt, args...)  DR_PRINT(fmt, ##args)

#if DREQUEST_DEBUG 
#define DR_DEBUG(fmt, args...)  DR_PRINT(fmt, ##args)
#else
#define DR_DEBUG(fmt, args...) 
#endif

#ifdef NAUT_CONFIG_PISCES_DYNAMIC
struct pisces_mem_dmsg{
    union {
        u64 msg;
        struct {
            u32 size;
            u32 addr;
        };
    };
};

struct pisces_dchannel {
    u64     in_progress;
    u64     active;

    u64     host_apic;
    u64     host_vector;
    u64     enclave_vector;

    u64     max_len;
    u64     msg_len;

    u64     msg[DREQUEST_MSG_SIZE];
} __attribute__((packed));

nk_wait_queue_t prefetching_waitq;

static struct pisces_dchannel * prefetching_dchan;
static struct pisces_dchannel * removal_dchan;

inline u64 atomic_get64(u64 * ptr) {
    return __atomic_load_n(ptr, __ATOMIC_SEQ_CST);
}
inline void atomic_set64(u64 * ptr, u64 val) {
    __atomic_store_n(ptr, val, __ATOMIC_SEQ_CST);
}

static int check_prefetch_state(void *state) {
    return atomic_get64(&prefetching_dchan->in_progress) == 0;
}

inline void
drequest_wait_for_prefetch ()
{
    nk_wait_queue_sleep_extended(&prefetching_waitq, check_prefetch_state, NULL);
}

inline void
drequest_wakeup_for_prefetch ()
{
    nk_wait_queue_wake_all_extended(&prefetching_waitq, 0); 
}

inline void
drequest_set_removal_msg(u64 msg, u64 idx) {
    atomic_set64(&removal_dchan->msg[idx], msg);
}

inline void
drequest_set_removal_msg_len(u32 len) {
    atomic_set64(&removal_dchan->msg_len, len);
}

static inline void
drequest_send (struct pisces_dchannel* ch)
{
    atomic_set64(&ch->active, 1);
    mbarrier();
    apic_ipi(per_cpu_get(apic),
            ch->host_apic, ch->host_vector);
}

inline int 
claim_removal_dchan ()
{
    return atomic_cmpswap(removal_dchan->in_progress, 0, 1) == 0;
}

inline int 
release_removal_dchan ()
{
    //return atomic_cmpswap(ch->in_progress, 1, 0) == 1;
    atomic_set64(&removal_dchan->in_progress, 0);
    return 0;
}

inline void
drequest_try_prefetch() {
    if(atomic_cmpswap(prefetching_dchan->in_progress, 0, 1) == 0) {
        atomic_set64(&prefetching_dchan->msg[0], 0);
        //mbarrier();
        drequest_send(prefetching_dchan);
    }
}

inline void
drequest_confirm_remove() {
    drequest_send(removal_dchan);
}

static int
prefetching_ipi_handler (excp_entry_t * excp,
    excp_vec_t vec,
    void *state)
{
    /*
     * Pisces has already written response to msg, 
     * and cleared active flag. (mfence) 
     */
    u64 idx, msg_len;
    struct pisces_mem_dmsg dmsg; 

    //mbarrier();
    msg_len = (ulong_t)atomic_get64(&prefetching_dchan->msg_len);
    DR_PRINT("Receive new mem info of %lu pools\n", msg_len);

    for(idx = 0; idx < msg_len; idx++) {
        dmsg.msg = atomic_get64(&prefetching_dchan->msg[idx]);
        DR_DEBUG("msg %lu\n", dmsg.msg);

        if(0 != kmem_add_mempool(NULL,
                        (ulong_t)dmsg.addr << DREQUEST_ADDR_SHIFT,
                        (ulong_t)dmsg.size, 1)) {
            DR_ERROR("Failed to add new pool base_addr=%lx size=%lx\n",
                    dmsg.addr << DREQUEST_ADDR_SHIFT, dmsg.size);
        }
        //drequest_wakeup_for_prefetch();
    }
    drequest_wakeup_for_prefetch();

    if(idx == 0)
        DR_PRINT("Pisces cannot provide new mem now"); 

    /* reset channel state */
    mbarrier();
    atomic_set64(&prefetching_dchan->in_progress, 0);
    mbarrier();

    IRQ_HANDLER_END();
    return 0;
}

static int
removal_ipi_handler (excp_entry_t * excp,
    excp_vec_t vec,
    void *state)
{
    u64 size, num_removed;
    struct list_head pool_list;

    INIT_LIST_HEAD(&pool_list);

    //mbarrier();
    size = atomic_get64(&removal_dchan->msg[0]);

    DR_PRINT("Receive mem removal request of %lu bytes\n", size);

    mbarrier();
    /* try remove pool */
    kmem_try_remove(size);

    //drequest_confirm_remove();
    
    IRQ_HANDLER_END();
    return 0;
}

static int
dchannel_init (struct pisces_dchannel* ch)
{
    if (idt_find_and_reserve_range(1,1, (ulong_t*)&ch->enclave_vector)) {
        DR_ERROR("Cannot find/reserve vector for drequest channel\n");
        return -1;
    }

    atomic_set64(&ch->in_progress, 0);
    atomic_set64(&ch->active, 0);

    mbarrier();
    return 0;
}

int
drequest_init ()
{
    DR_PRINT("Init drequest\n");

    prefetching_dchan = (struct pisces_dchannel*) pisces_boot_params->prefeching_dchan_addr;
    removal_dchan = (struct pisces_dchannel*) pisces_boot_params->removal_dchan_addr;


    if(0 != dchannel_init(prefetching_dchan)
        || 0 != dchannel_init(removal_dchan)) {
        DR_ERROR("Failed to initialize drequest channel");
        return -1;
    }

    register_int_handler(prefetching_dchan->enclave_vector, prefetching_ipi_handler, prefetching_dchan);
    register_int_handler(removal_dchan->enclave_vector, removal_ipi_handler, removal_dchan);

    nk_wait_queue_initialize(&(prefetching_waitq), NULL);

    return 0;
}
#endif
