/* 
 * This file is part of the Nautilus AeroKernel developed
 * by the Hobbes and V3VEE Projects with funding from the 
 * United States National  Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  The Hobbes Project is a collaboration
 * led by Sandia National Laboratories that includes several national 
 * laboratories and universities. You can find out more at:
 * http://www.v3vee.org  and
 * http://xstack.sandia.gov/hobbes
 *
 * Copyright (c) 2015, Kyle C. Hale <kh@u.northwestern.edu>
 * Copyright (c) 2015, The V3VEE Project  <http://www.v3vee.org> 
 *                     The Hobbes Project <http://xstack.sandia.gov/hobbes>
 * All rights reserved.
 *
 * Author: Kyle C. Hale <kh@u.northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "LICENSE.txt".
 */
#ifndef __BUDDY_H__
#define __BUDDY_H__

#include <nautilus/naut_types.h>
#include <nautilus/spinlock.h>

struct buddy_memzone {
    ulong_t     max_order;      /* max size of memory pool = 2^max_order */
    ulong_t     min_order;      /* minimum allocatable block size */

    uint_t      node_id;        /* The NUMA node this zone allocates */

    ulong_t     num_pools;

    struct list_head * avail;   /* one free list for each block size,
                                 * indexed by block order:
                                 *   avail[i] = free list of 2^i 
                                 */

    spinlock_t  lock;           /* For now we will lock all zone operations...
                                 *   Hopefully this does not cause a performance 
                                 */

    struct list_head mempools;  /* since we have hash for pools, we don't need rbtree */
};

struct buddy_mempool {
    ulong_t    base_addr;       /* base address of the memory pool */
    ulong_t    pool_order;      /* size of memory pool = 2^pool_order */
    ulong_t    min_order;       /* minimum allocatable block size */

    ulong_t    num_blocks;      /* number of bits in tag_bits */
    ulong_t    num_free_blocks;

    ulong_t    *tag_bits;       /* one bit for each 2^min_order block:
                                 *   0 = block is allocated
                                 *   1 = block is available 
                                 */
    ulong_t    *order_bits;     /* one bit for each 2^min_order block:
                                 *   only the last block is set 
                                 * Traverse the order bits till an '1' to get the order value. 
                                 */
                                    
    ulong_t    *flag_bits;      /* Since nautilus currently only has one flag: VISITED,
                                 * one bit for each 2^min_order block: 
                                 *    1 = block is VISITED
                                 */

    struct buddy_memzone * zone;
    
    struct list_head link;
};

struct buddy_memzone * buddy_init (uint_t node_id, ulong_t max_order, ulong_t min_order);

struct buddy_mempool * buddy_init_pool (struct buddy_memzone * zone, ulong_t base_addr, ulong_t pool_order);

void insert_mempool (struct buddy_memzone * zone, struct buddy_mempool * pool);
struct buddy_mempool * buddy_create_pool (struct buddy_memzone * zone, ulong_t base_addr, ulong_t pool_order);
int buddy_remove_pool (struct buddy_mempool * mp);

int zone_mem_show(struct  buddy_memzone * zone);

inline ulong_t get_block_order (struct buddy_mempool *mp, void *block);

void buddy_free (struct buddy_mempool * mp, void * addr, ulong_t order);
void * buddy_alloc (struct buddy_memzone * zone, ulong_t order);

int  buddy_sanity_check(struct buddy_mempool *mp);

struct buddy_pool_stats {
    void   *start_addr;
    void   *end_addr;
    uint64_t total_blocks_free;
    uint64_t total_bytes_free;
    uint64_t min_alloc_size;
    uint64_t max_alloc_size;
};

void buddy_stats(struct buddy_mempool *mp, struct buddy_pool_stats *stats);


#endif
