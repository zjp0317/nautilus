/* Pisces Cross OS Spinlock implementation 
 *  (c) 2013, Jiannan Ouyang (ouyang@cs.pitt.edu)
 *  (c) 2013, Jack Lange (jacklange@cs.pitt.edu)
 */


#ifndef __PISCES_LOCK_H__
#define __PISCES_LOCK_H__

#include <nautilus/naut_types.h>

struct pisces_spinlock {
    uint64_t raw_lock;
} __attribute__((packed));


void pisces_lock_init(struct pisces_spinlock * lock);
void pisces_spin_lock(struct pisces_spinlock * lock);
void pisces_spin_unlock(struct pisces_spinlock * lock);


#endif
