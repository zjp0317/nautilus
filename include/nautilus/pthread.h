/*
 * This is a simple macro-based hack for supporting pthread in nautilus
 */
#ifndef __NAUT_PTHREAD_H__
#define __NAUT_PTHREAD_H__

#include <nautilus/nautilus.h>
#include <nautilus/thread.h>
#include <nautilus/scheduler.h>
#include <nautilus/spinlock.h>
#include <nautilus/condvar.h>

/* Mutex Lock */
#define pthread_mutex_t             NK_LOCK_T
#define PTHREAD_MUTEX_INITIALIZER   SPINLOCK_INITIALIZER
#define pthread_mutex_init(m, attr) ({ int ret=0; NK_LOCK_INIT(m); ret; }) // attr not used
#define pthread_mutex_lock(m)       ({ int ret=0; NK_LOCK(m); ret; })
#define pthread_mutex_trylock(m)    ({ int ret=0; NK_TRY_LOCK(m); ret; })
#define pthread_mutex_unlock(m)     ({ int ret=0; NK_UNLOCK(m); ret; })
#define pthread_mutex_destroy(m)    ({ int ret=0; NK_LOCK_DEINIT(m); ret; }) // leak

/* Cond */
#define PTHREAD_COND_INITIALIZER    {0}
#define pthread_cond_t              nk_condvar_t
#define pthread_cond_init(c, attr)  nk_condvar_init(c) // attr not used
#define pthread_cond_wait(c, l)     nk_condvar_wait(c, l)
#define pthread_cond_signal(c)      nk_condvar_signal(c)
#define pthread_cond_broadcast(c)   nk_condvar_bcast(c)

/* Thread */
#define pthread_t                   nk_thread_id_t
#define pthread_create(tp,ap,f,i)   nk_thread_start((nk_thread_fun_t)f,i,0,0,TSTACK_DEFAULT,tp,-1)
#define pthread_join(tp,ap)         nk_join(tp,ap)
#define pthread_self()              ({ get_cur_thread()->tid; })

#define NAUT_SIZEOF_PTHREAD_ATTR_T  56
union naut_pthread_attr_t
{
  char __size[NAUT_SIZEOF_PTHREAD_ATTR_T];
  long int __align;
};
typedef union naut_pthread_attr_t pthread_attr_t;
//pthread_attr_init
#define pthread_attr_init(m)    ({ int ret=0; memset(m, 0, NAUT_SIZEOF_PTHREAD_ATTR_T); ret; })

//pthread_once_t
#if 0 
#define NAUT_PTHREAD_ONCE_INIT          0
#define NAUT_PTHREAD_ONCE_INPROGRESS    1
#define NAUT_PTHREAD_ONCE_DONE          2
#define pthread_once_t                  int
//pthread_once
nk_wait_queue_t naut_pthread_once_waitq; // TODO one queue per ctrl
int pthread_once(pthread_once_t * ctrl, void (*init_routine)(void))
{
    if (__sync_bool_compare_and_swap(ctrl, NAUT_PTHREAD_ONCE_DONE, NAUT_PTHREAD_ONCE_DONE)) {
        // already done
        return 0;
    }
    if (__sync_bool_compare_and_swap(ctrl, NAUT_PTHREAD_ONCE_INPROGRESS, NAUT_PTHREAD_ONCE_INPROGRESS)) {
        // someone already called init
        //nk_wait_queue_sleep_extended(&naut_pthread_once_waitq, check_pisces_buf_cond, pisces_buf);
    }
    
    init_routine();
    return 0;
}
#endif
/* Thread specific */

//pthread_key_t
#define pthread_key_t               nk_tls_key_t
//pthread_key_create
#define pthread_key_create(m, func) nk_tls_key_create(m, func)
// pthread_setspecific 
#define pthread_setspecific(m, val) nk_tls_set(m, val)
//pthread_getspecific
#define pthread_getspecific(m)      nk_tls_get(m)

/* Not used */

#define pthread_barrier_t           nk_counting_barrier_t
#define pthread_barrier_init(p,n,c) nk_counting_barrier_init(p,c)
#define pthread_barrier_wait(p)     do { nk_counting_barrier(p); } while (0)
//#define pthread_barrier_wait(p)     do { if (!skipbarrier) { DEBUG("barrier start %s:%d\n",__FILE__,__LINE__); nk_counting_barrier(p); DEBUG("barrier end %s:%d\n",__FILE__,__LINE__);} } while (0)
#define pthread_barrier_destroy(p)  //leak

#endif
