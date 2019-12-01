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
 * Copyright (c) 2017, Peter A. Dinda <pdinda@northwestern.edu>
 * Copyright (c) 2015, The V3VEE Project  <http://www.v3vee.org> 
 *                     The Hobbes Project <http://xstack.sandia.gov/hobbes>
 * All rights reserved.
 *
 * Authors: Kyle C. Hale <kh@u.northwestern.edu>
 *          Peter A. Dinda <pdinda@northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "LICENSE.txt".
 *
 * This file includes code borrowed from the Kitten LWK, with modifications
 */
#include <nautilus/nautilus.h>
#include <nautilus/mm.h>
#include <nautilus/buddy.h>
#include <nautilus/paging.h>
#include <nautilus/numa.h>
#include <nautilus/spinlock.h>
#include <nautilus/macros.h>
#include <nautilus/naut_assert.h>
#include <nautilus/math.h>
#include <nautilus/intrinsics.h>
#include <nautilus/percpu.h>
#include <nautilus/shell.h>

#include <dev/gpio.h>

#ifndef NAUT_CONFIG_DEBUG_KMEM
#undef DEBUG_PRINT
#define DEBUG_PRINT(fmt, args...)
#endif

#include <nautilus/backtrace.h>

// turn this on to have a sanity check run before and after each
// malloc and free
#define SANITY_CHECK_PER_OP 0

#define KMEM_DEBUG(fmt, args...) DEBUG_PRINT("KMEM: " fmt, ##args)
#define KMEM_ERROR(fmt, args...) ERROR_PRINT("KMEM: " fmt, ##args)
#define KMEM_PRINT(fmt, args...) INFO_PRINT("KMEM: " fmt, ##args)
#define KMEM_WARN(fmt, args...)  WARN_PRINT("KMEM: " fmt, ##args)

#ifndef NAUT_CONFIG_DEBUG_KMEM
#define KMEM_DEBUG_BACKTRACE()
#else
#define KMEM_DEBUG_BACKTRACE() BACKTRACE(KMEM_DEBUG,3)
#endif	

#define KMEM_ERROR_BACKTRACE() BACKTRACE(KMEM_ERROR,3)
	    

/**
 * This specifies the minimum sized memory block to request from the underlying
 * buddy system memory allocator, 2^MIN_ORDER bytes. It must be at least big
 * enough to hold a 'struct kmem_block_hdr'.
 */
#define MIN_ORDER   5  /* 32 bytes */

#define MAX_ORDER   (27+12)  /* 128MB * 4K, max order for each zone */

/**
 *  * Total number of bytes in the kernel memory pool.
 *   */
static unsigned long kmem_bytes_managed;


/**
 *  * Total number of bytes allocated from the kernel memory pool.
 *   */
static unsigned long kmem_bytes_allocated_internal = 0;
static unsigned long kmem_bytes_allocated_regular = 0;

// zjp
static unsigned long kmem_bytes_allocated_regular_peak = 0;


/* This is the list of all memory zones */
static struct list_head glob_zone_list;


/* zjp:
 * We organize the kernel memory as a set of 'units'. 
 * Each unit has associated with it one kmem_unit_hdr entry by hash.
 * --Hash key is the starting address of unit.
 * --Hash value is the associated kmem_unit_hdr entry.
 * Each hasn entry stores a pointer to the corresponding buddy_mempool.
 * Each buddy_mempool structure stores tag-bits, order-bits, and flags for all blocks.
 */
#define KMEM_UNIT_SIZE  PISCES_MEM_UNIT // unit size: 128MB
#define KMEM_UNIT_MASK  (~(KMEM_UNIT_SIZE - 1))
#define KMEM_UNIT_NUM   0x2000ULL       // support 8K discontinous units 
struct kmem_unit_hdr {
    /*
     * Intuitively, unit_addr is the start address of each 128M unit ( 128M-aligned ) 
     * BUT, such start address can be 0x0. So, we use the last bit as an 'offset',
     * such that, the actual unit_addr for address 0x0 is 0x1, and unit_addr for 0x8000000 is 0x8000001.
     * In addition, unit_addr == 0x0 can be used to indicate a free entry 
     */   
    union {
        uint64_t unit_addr; 

        struct {
            uint64_t offset_bit: 1; 
            uint64_t rsvd : 63;
        } __attribute__((packed));
    } __attribute__((packed));

    struct buddy_mempool * mempool; /* address of zone to which this block belongs */
} __packed __attribute((aligned(8)));

static struct kmem_unit_hdr * unit_hash_entries=0;
static uint64_t               unit_hash_num_entries=0;

static struct buddy_mempool * internal_mempool = NULL; /* for internal usage */
static struct buddy_memzone * internal_zone = NULL;

//static struct buddy_mempool * first_mempool = NULL; /* 1st pool for app/runtime usage */
static uint64_t internal_mem_start = 0;
static uint64_t internal_mem_end = 0;

/* zjp:
 * Init the unit hash map with capacity = KMEM_UNIT_NUM
 */
static int unit_hash_init()
{
    uint64_t num_entries = KMEM_UNIT_NUM;
    uint64_t entry_size = sizeof(*unit_hash_entries);

    KMEM_DEBUG("unit_hash_init with %lu entries each of size %lu bytes (%lu bytes)\n",
            num_entries, entry_size, num_entries*entry_size);

    unit_hash_entries = mm_boot_alloc(num_entries*entry_size);

    if (!unit_hash_entries) { 
        KMEM_ERROR("unit_hash_init failed\n");
        return -1;
    }

    memset(unit_hash_entries,0,num_entries*entry_size);

    unit_hash_num_entries = num_entries;

    return 0;
}

/* zjp
 * Hash on start address of each unit.
 */
static inline uint64_t unit_hash_hash(const void *ptr)
{
    uint64_t n = ((uint64_t) ptr) & KMEM_UNIT_MASK; // just in case the ptr is not aligned

    n =  n ^ (n>>1) ^ (n<<2) ^ (n>>3) ^ (n<<5) ^ (n>>7)
        ^ (n<<11) ^ (n>>13) ^ (n<<17) ^ (n>>19) ^ (n<<23) 
        ^ (n>>29) ^ (n<<31) ^ (n>>37) ^ (n<<41) ^ (n>>43)
        ^ (n<<47) ^ (n<<53) ^ (n>>59) ^ (n<<61);

    n = n % unit_hash_num_entries;

    KMEM_DEBUG("hash of %p returns 0x%lx\n",ptr, n);

    return n;
}

/* zjp
 * Find the hash entry given an address 
 */
static inline struct kmem_unit_hdr * unit_hash_find_entry(const void *ptr)
{
  uint64_t i;
  uint64_t unit_start = ((uint64_t) ptr) & KMEM_UNIT_MASK; // just in case the ptr is not aligned
  unit_start |= 0x1; // set the "offset bit" 
  uint64_t start = unit_hash_hash(ptr);
  
  for (i = start; i < unit_hash_num_entries; i++) { 
      //if (unit_hash_entries[i].unit_addr == unit_start) {
      if (unit_hash_entries[i].unit_addr == unit_start && unit_hash_entries[i].mempool != NULL) {
          KMEM_DEBUG("Find entry scanned %lu entries\n", i-start+1);
          return &unit_hash_entries[i];
      }
  }
  for (i = 0; i < start; i++) { 
      //if (unit_hash_entries[i].unit_addr == unit_start) {
      if (unit_hash_entries[i].unit_addr == unit_start && unit_hash_entries[i].mempool != NULL) {
          KMEM_DEBUG("Find entry scanned %lu entries\n", i-start+1);
          return &unit_hash_entries[i];
      }
  }
  return 0;
}

/* zjp
 * Alloc a hash entry for a new unit.
 * This can only happen when there's a new unit, e.g., pisces adds a new chunk of mem.
 * Allocating a block will not use this function!
 */
static inline struct kmem_unit_hdr * unit_hash_alloc(void *ptr)
{
  uint64_t i;
  uint64_t unit_start = ((uint64_t) ptr) & KMEM_UNIT_MASK; // just in case the ptr is not aligned
  unit_start |= 0x1; // set the "offset bit" 
  uint64_t start = unit_hash_hash(ptr);
  
  for (i = start; i < unit_hash_num_entries; i++) { 
      if (__sync_bool_compare_and_swap(&unit_hash_entries[i].unit_addr, 0, unit_start)) {
          KMEM_DEBUG("Allocation scanned %lu entries\n", i-start+1);
          return &unit_hash_entries[i];
      }
  }
  for (i = 0; i < start; i++) { 
      if (__sync_bool_compare_and_swap(&unit_hash_entries[i].unit_addr, 0, unit_start)) {
          KMEM_DEBUG("Allocation scanned %lu entries\n", i-start+1);
          return &unit_hash_entries[i];
      }
  }
  return 0;
}

static inline void unit_hash_free_entry(struct kmem_unit_hdr *u)
{
    u->mempool = NULL;
    __sync_fetch_and_and (&u->unit_addr, 0);
}

static inline int unit_hash_free(void *ptr)
{
    struct kmem_unit_hdr *u = unit_hash_find_entry(ptr);

    if (!u) { 
        return -1;
    } else {
        unit_hash_free_entry(u);
        return 0;
    }
}

struct mem_region *
kmem_get_base_zone (void)
{
    KMEM_DEBUG("getting base zone\n");
    return list_first_entry(&glob_zone_list, struct mem_region, glob_link);
}


/* TODO: if we're going to be using this at runtime, really need to 
 * key these regions in a tree
 */
struct mem_region *
kmem_get_region_by_addr (ulong_t addr)
{
    struct mem_region * region = NULL;
    list_for_each_entry(region, &glob_zone_list, glob_link) {
        if (addr >= region->base_addr && 
            addr < (region->base_addr + region->len)) {
            return region;
        }
    }

    return NULL;
}

/* zjp
 * Get the mempool pointer based on unit hash
 */
struct buddy_mempool *
kmem_get_mempool_by_addr (ulong_t addr)
{
    if (addr >= internal_mem_start && addr < internal_mem_end) {
        return internal_mempool;
    }

    struct kmem_unit_hdr * hdr = unit_hash_find_entry((void*)addr);
    if (hdr == NULL) {
        ERROR_PRINT("Could not find unit hash with base address (%p), addr (%p)\n",
                (void*)((uint64_t)addr & KMEM_UNIT_MASK), (void *)addr);
        return NULL;
    }
    return hdr->mempool;
}

/**
 * This adds memory to the kernel memory pool. The memory region being added
 * must fall within a mempool previously initialized via buddy_init_pool().
 *
 * Arguments:
 *       [IN] mp:        mempool of memory to add
 *       [IN] base_addr: the base address of the memory to add
 *       [IN] size:      the size of the memory to add
 */
void
kmem_add_memory (struct buddy_mempool * mp, 
                ulong_t base_addr, 
                size_t size)
{
    /*
     * kmem buddy allocator is initially empty.
     * Memory is added to it via buddy_free().
     * buddy_free() will panic if there are any problems with the args.
     * However, buddy_free() does expect chunks of memory aligned
     * to their size, which we manufacture out of the memory given.
     * buddy_free() will coalesce these chunks as appropriate
     */
    uint64_t max_chunk_size = base_addr ? 1ULL << __builtin_ctzl(base_addr) : size;
    uint64_t chunk_size = max_chunk_size < size ? max_chunk_size : size;
    uint64_t chunk_order = ilog2(chunk_size); // floor 
    uint64_t num_chunks = size/chunk_size; // floor
    void *addr=(void*)pa_to_va(base_addr);
    uint64_t i;

    KMEM_DEBUG("Add Memory to mempool %p base_addr=0x%llx size=0x%llx chunk_size=0x%llx, chunk_order=0x%llx, num_chunks=0x%llx, addr=%p\n",
	       mp,base_addr,size,chunk_size,chunk_order,num_chunks,addr);
    
    for (i = 0; i < num_chunks; i++) { 
        buddy_free(mp, addr+i*chunk_size, chunk_order);
    }

    /* Update statistics */
    kmem_bytes_managed += chunk_size*num_chunks;
}

void *boot_mm_get_cur_top();

static void *kmem_private_start;
static void *kmem_private_end;

/* zjp
 * Alloc unit hash entries for range [base_addr, end_addr).
 */
static int kmem_alloc_unit_hash (uint64_t base_addr, uint64_t end_addr, struct buddy_mempool* mp) {
    uint64_t unit_addr;
    for(unit_addr = base_addr; unit_addr < end_addr; unit_addr += KMEM_UNIT_SIZE) {
        struct kmem_unit_hdr * hdr = unit_hash_alloc((void*)unit_addr);
        if(!hdr) {
            ERROR_PRINT("Can not allocate unit hash entry for unit_addr %lx, region base_addr=%lx, region end_addr=%lu\n",
                    unit_addr, base_addr, end_addr);
            for(; base_addr < unit_addr; base_addr += KMEM_UNIT_SIZE) {
                unit_hash_free((void*)base_addr);
            }
            return -1;
        }
        hdr->mempool = mp;
    }
    return 0;
}

/* 
 * Add a new mempool into a zone 
 */
int
kmem_add_mempool (struct buddy_memzone * zone,
                 ulong_t base_addr, 
                 ulong_t size)
{
    uint8_t flags = 0;

    /* create a mempool struct for given memory */
    struct buddy_mempool * mp = buddy_create_pool(zone, base_addr, ilog2(size));
    if(mp == NULL) {
        ERROR_PRINT("Failed to add mempool for base_addr=0x%lx size=0x%lx\n", base_addr, size);
        printk("Failed to add mempool for base_addr=0x%lx size=0x%lx\n", base_addr, size);
        return -1;
    }

    if(0 != fill_page_tables(base_addr, base_addr, size, PTE_PRESENT_BIT | PTE_WRITABLE_BIT)) {
        ERROR_PRINT("Failed to alloc new page table for mempool %p base_addr=0x%lx size=0x%lx\n", mp, base_addr, size);
        goto err;
    }

    /* alloc hash entries for this mempool */
    if(kmem_alloc_unit_hash(base_addr, base_addr + size, mp) != 0) {
        ERROR_PRINT("Failed to alloc unit hash for mempool %p base_addr=0x%lx size=0x%lx\n", mp, base_addr, size);
        printk("Failed to alloc unit hash for mempool %p base_addr=0x%lx size=0x%lx\n", mp, base_addr, size);
        goto err;
    }

    /* add to the zone's pool list */
    flags = spin_lock_irq_save(&(zone->lock));
    {
        insert_mempool(zone, mp);
    }
    spin_unlock_irq_restore(&(zone->lock), flags);

    /* now it's safe to enable allocation on this mempool */ 
    buddy_free(mp, (void*)base_addr, mp->pool_order);

    return 0;
err:
    free_page_tables(base_addr, size);
    buddy_cleanup_pool(mp);
    return -1;
}

/* 
 * Given the base_addr and size, remove the corresponding mempool 
 */
int
kmem_remove_mempool (ulong_t base_addr, 
                    ulong_t size)
{
    /* try get the corresponding mempool */
    struct buddy_mempool *mp = kmem_get_mempool_by_addr(base_addr);
    if(mp == NULL) {
        ERROR_PRINT("Cannot find mempool for base_addr=0x%lx\n", base_addr);
        return -1;
    }

    /* remove the mempool from the zone's free list and pool list */
    if ( 0 != buddy_remove_pool(mp)) {
        ERROR_PRINT("Failed to remove mempool %p base_addr=0x%lx\n", mp, base_addr);
        return -1;
    }

    /* free the unit hash entries */
    ulong_t unit_addr;
    for(unit_addr = base_addr; unit_addr < base_addr + size; unit_addr += KMEM_UNIT_SIZE) {
        unit_hash_free((void*)unit_addr);
    }

    if(0 != free_page_tables(base_addr, size)) {
        ERROR_PRINT("Failed to clean page tables for mempool %p base_addr=0x%lx\n", mp, base_addr);
        return -1;
    }
    return 0;
}

/* 
 * initializes the kernel memory pools based on previously 
 * collected memory information (including NUMA domains etc.)
 */
int
nk_kmem_init (void)
{
    struct sys_info * sys = &(nk_get_nautilus_info()->sys);
    struct nk_locality_info * numa_info = &(nk_get_nautilus_info()->sys.locality_info);
    struct mem_region * ent = NULL;
    unsigned i = 0, j = 0;
    uint64_t total_mem=0;
    uint64_t total_phys_mem=0;
    
    kmem_private_start = boot_mm_get_cur_top();

    /* initialize the global zone list */
    INIT_LIST_HEAD(&glob_zone_list);

    /* init hash entries, by default, supporting 1TB (8K units * 128MB per unit) */
    if (unit_hash_init()) {
        KMEM_ERROR("Failed to initialize unit hash\n");
        return -1;
    }

#ifndef NAUT_CONFIG_PISCES // no co-kernel case
    for (i = 0; i < numa_info->num_domains; i++) {
        /* create zone for this domain */
        struct buddy_memzone * zone = buddy_init(numa_info->domains[i]->id, MAX_ORDER, MIN_ORDER);
        if(zone == NULL) {
            panic("Could not initialize memory management for domain %d\n", numa_info->domains[i]->id);
            return -1;
        }
        numa_info->domains[i]->zone = zone;
        /* add pools into this zone */
        j = 0;
        list_for_each_entry(ent, &(numa_info->domains[i]->regions), entry) {
            if (ent->mm_state) {
                panic("Memory zone already exists for memory region ([%p - %p] domain %u)\n",
                        (void*)ent->base_addr,
                        (void*)(ent->base_addr + ent->len),
                        ent->domain_id);
            }
            if (ent->len < (1UL << MIN_ORDER)) { 
                KMEM_DEBUG("Skipping kmem initialization of oddball region of size %lu\n", ent->len);
                continue;
            }

            ulong_t len = round_up(ent->len, KMEM_UNIT_SIZE);

            struct buddy_mempool * mp = NULL;
            mp = buddy_init_pool(internal_zone, ent->base_addr, ilog2(len)); 
            printk("initialize mem pool at %p\n", ent->base_addr);

            if(mp == NULL) {
                panic("Could not initialize pool for region %u in domain %u\n", j, i);
                return -1;
            }

            if(kmem_alloc_unit_hash(ent->base_addr, ent->base_addr + len, mp) != 0) {
                mm_boot_free(mp, sizeof(struct buddy_mempool));
                panic("Could not initialize unit hash for region %u in domain %u\n", j, i);
                return -1;
            }
            list_add(&(ent->glob_link), &glob_zone_list); // zjp useless for new design?

            ent->mm_state = mp;
            total_phys_mem += ent->len;
            ++j;

            if ((ent->base_addr + ent->len) >= sys->mem.phys_mem_avail) {
                sys->mem.phys_mem_avail = ent->base_addr + ent->len;
            }
        }
    }

    KMEM_PRINT("Malloc configured to support a maximum of: 0x%lx bytes of physical memory\n", total_phys_mem);

    // the assumption here is that no further boot_mm allocations will
    // be made by kmem from this point on
    kmem_private_end = boot_mm_get_cur_top();

    return 0;

#else // Pisces. Only initialize internal mempool here, full initialization is done by nk_kmem_init_all()

    // Create internal zone to handle the 1st region in domain 0, for internal usage 
    internal_zone = buddy_init(numa_info->domains[0]->id, MAX_ORDER, MIN_ORDER);
    if(internal_zone == NULL) {
        panic("Could not initialize memory management for internal region\n"); 
        return -1;
    }

    list_for_each_entry(ent, &(numa_info->domains[i]->regions), entry) {
        if (ent->mm_state) {
            panic("Memory zone already exists for memory region ([%p - %p] domain %u)\n",
                    (void*)ent->base_addr,
                    (void*)(ent->base_addr + ent->len),
                    ent->domain_id);
        }
        if (ent->len < (1UL << MIN_ORDER)) { 
            KMEM_DEBUG("Skipping kmem initialization of oddball region of size %lu\n", ent->len);
            continue;
        }

        ulong_t len = round_up(ent->len, KMEM_UNIT_SIZE);

        internal_mempool = buddy_init_pool(internal_zone, ent->base_addr, ilog2(len)); 
        if(internal_mempool == NULL) {
            panic("Failed to initialize the internal mem pool at %p\n", ent->base_addr);
            return -1;
        }
        KMEM_PRINT("initialize the internal mem pool at %p size %lx\n", ent->base_addr, ent->len);

        internal_mem_start = ent->base_addr;
        internal_mem_end = ent->base_addr + len;

        ent->mm_state = internal_mempool;

        /* keep some stuff from natilus, not sure we'll need it or not */
        list_add(&(ent->glob_link), &glob_zone_list); 

        if ((ent->base_addr + ent->len) >= sys->mem.phys_mem_avail) {
            sys->mem.phys_mem_avail = ent->base_addr + ent->len;
        }

        kmem_private_end = boot_mm_get_cur_top();

        break;
    }
    return 0;
#endif
}

#ifdef NAUT_CONFIG_PISCES
int
nk_kmem_init_all (void)
{
    struct sys_info * sys = &(nk_get_nautilus_info()->sys);
    struct nk_locality_info * numa_info = &(nk_get_nautilus_info()->sys.locality_info);
    struct mem_region * ent = NULL;
    unsigned i = 0, j = 0;
    uint64_t total_mem=0;
    uint64_t total_phys_mem=0;

    for (i = 0; i < numa_info->num_domains; i++) {
        /* create zone for this domain */
        struct buddy_memzone * zone = buddy_create(numa_info->domains[i]->id, MAX_ORDER, MIN_ORDER);
        if(zone == NULL) {
            panic("Could not initialize memory management for domain %d\n", numa_info->domains[i]->id);
            return -1;
        }
        numa_info->domains[i]->zone = zone;
        list_for_each_entry(ent, &(numa_info->domains[i]->regions), entry) {
            if(j++ == 0)
                continue; // skip the internal region

            if (ent->mm_state) {
                panic("Memory zone already exists for memory region ([%p - %p] domain %u)\n",
                        (void*)ent->base_addr,
                        (void*)(ent->base_addr + ent->len),
                        ent->domain_id);
            }
            if (ent->len < (1UL << MIN_ORDER)) { 
                KMEM_DEBUG("Skipping kmem initialization of oddball region of size %lu\n", ent->len);
                continue;
            }

            ulong_t len = round_up(ent->len, KMEM_UNIT_SIZE);

            struct buddy_mempool * mp = buddy_create_pool(zone, ent->base_addr, ilog2(len));

            if(mp == NULL) {
                panic("Could not initialize pool for region %u in domain %u\n", j, i);
                return -1;
            }
            KMEM_PRINT("initialize mem pool at %p size %lx\n", ent->base_addr, ent->len);

            if(kmem_alloc_unit_hash(ent->base_addr, ent->base_addr + len, mp) != 0) {
                mm_boot_free(mp, sizeof(struct buddy_mempool));
                panic("Could not initialize unit hash for region %u in domain %u\n", j, i);
                return -1;
            }

            insert_mempool(zone, mp); 

            ulong_t block_order = ilog2(KMEM_UNIT_SIZE); 
            for (uint64_t block_addr = ent->base_addr; 
                    block_addr < ent->base_addr + len; block_addr += KMEM_UNIT_SIZE) { 
                buddy_free(mp, (void*)block_addr, block_order);
            }

            ent->mm_state = mp;
            total_phys_mem += ent->len;

            /* keep some stuff from natilus, not sure we'll need it or not */
            list_add(&(ent->glob_link), &glob_zone_list); 

            if ((ent->base_addr + ent->len) >= sys->mem.phys_mem_avail) {
                sys->mem.phys_mem_avail = ent->base_addr + ent->len;
            }
        }
    }
    KMEM_PRINT("Malloc configured to support a maximum of: 0x%lx bytes for runtime/applications\n", total_phys_mem);

    kmem_private_end = boot_mm_get_cur_top();

    return 0;
}
#endif

// A fake header representing the boot allocations
static void     *boot_start;
static void     *boot_end;
static uint64_t  boot_flags;

void kmem_inform_boot_allocation(void *low, void *high)
{
    KMEM_DEBUG("Handling boot range %p-%p\n", low, high);
    boot_start = low;
    boot_end = high;
    boot_flags = 0;
    KMEM_PRINT("   boot range: %p-%p   kmem private: %p-%p\n",
 	       low, high, kmem_private_start, kmem_private_end);
}


/**
 * Allocates memory from the kernel memory pool. This will return a memory
 * region that is at least 16-byte aligned. The memory returned is 
 * optionally zeroed.
 *
 * Arguments:
 *       [IN] size: Amount of memory to allocate in bytes.
 *       [IN] cpu:  affinity cpu (-1 => current cpu)
 *       [IN] zero: Whether to zero the whole allocated block
 *
 * Returns:
 *       Success: Pointer to the start of the allocated memory.
 *       Failure: NULL
 */
static void *
_kmem_malloc (size_t size, int cpu, int zero)
{
    NK_GPIO_OUTPUT_MASK(0x20,GPIO_OR);
    int first = 1;
    void *block = 0;
    struct kmem_block_hdr *hdr = NULL;
    struct mem_reg_entry * reg = NULL;
    ulong_t order;
    cpu_id_t my_id;

    if (cpu < 0 || cpu >= nk_get_num_cpus()) {
        my_id = my_cpu_id();
    } else {
        my_id = cpu;
    }

    KMEM_DEBUG("malloc of %lu bytes (zero=%d) from:\n",size,zero);
    KMEM_DEBUG_BACKTRACE();

#if SANITY_CHECK_PER_OP
    if (kmem_sanity_check()) { 
        panic("KMEM HAS GONE INSANE PRIOR TO MALLOC\n");
        return 0;
    }
#endif

    /* Calculate the block order needed */
    order = ilog2(roundup_pow_of_two(size));
    if (order < MIN_ORDER) {
        order = MIN_ORDER;
    }

    struct numa_domain* local_domain = nk_get_nautilus_info()->sys.cpus[my_id]->domain;
    struct nk_locality_info * numa_info = &(nk_get_nautilus_info()->sys.locality_info);

retry:

    /* try alloc from local zone first, then other zones */
    block = buddy_alloc(local_domain->zone, order);
    if(block == NULL) {
        unsigned i;
        for(i = 0; i < numa_info->num_domains; i++) {
            block = buddy_alloc(numa_info->domains[i]->zone, order);
            if(block) {
                break;
            }
        }
    }

    if (block) {
        __asm__ __volatile__ ("" :::"memory");
        kmem_bytes_allocated_regular += (1UL << order);
        if(kmem_bytes_allocated_regular > kmem_bytes_allocated_regular_peak)
            kmem_bytes_allocated_regular_peak = kmem_bytes_allocated_regular;
    } else {
        // attempt to get memory back by reaping threads now...
        if (first) {
            KMEM_DEBUG("malloc initially failed for size %lu order %lu attempting reap\n",size,order);
            nk_sched_reap(1);
            first = 0;
            goto retry;
        }
        KMEM_DEBUG("malloc permanently failed for size %lu order %lu\n",size,order);
        NK_GPIO_OUTPUT_MASK(~0x20,GPIO_AND);
        return NULL;
    }

    KMEM_DEBUG("malloc succeeded: size %lu order %lu -> 0x%lx\n",size, order, block);

    if (zero) { 
        //printk("malloc succeeded: size %lu order %lu -> 0x%lx blockorder %lu\n",size, order, block, ((struct block*)block)->order);
        memset(block,0,size);
        /*
        size_t n = size;
        while (n--) {
            if(order <2)
            printk("zjp here\n");
        }
         */
        //memset(block,0,1ULL << ((struct block*)block)->order);
    }
    
#if SANITY_CHECK_PER_OP
    if (kmem_sanity_check()) { 
        panic("KMEM HAS GONE INSANE AFTER MALLOC\n");
        return 0;
    }
#endif

    NK_GPIO_OUTPUT_MASK(~0x20,GPIO_AND);

    /* Return address of the block */
    return block;
}

void *kmem_malloc(size_t size)
{
    return _kmem_malloc(size,-1,0);
}

void *kmem_mallocz(size_t size)
{
    return _kmem_malloc(size,-1,1);
}

void *kmem_malloc_specific(size_t size, int cpu, int zero)
{
    return _kmem_malloc(size,cpu,zero);
}

/**
 * Internal kmem allocator for internal usage
 */
static void*
_kmem_malloc_internal (size_t size, int zero)
{
    void *block = 0;
    ulong_t order;
    
    /* Calculate the block order needed */
    order = ilog2(roundup_pow_of_two(size));
    if (order < MIN_ORDER) {
        order = MIN_ORDER;
    }

    block = buddy_alloc(internal_mempool->zone, order);
    
    if(!block) {
        KMEM_DEBUG("malloc permanently failed for size %lu order %lu\n",size,order);
        return NULL;
    }

    kmem_bytes_allocated_internal += (1UL << ((struct block*)block)->order);

    if(zero) {
        memset(block,0,1ULL << ((struct block*)block)->order);
    }

    return block;
}

void *kmem_malloc_internal(size_t size)
{
    return _kmem_malloc_internal(size, 0);
}

void *kmem_mallocz_internal(size_t size)
{
    return _kmem_malloc_internal(size, 1);
}

void *kmem_malloc_specific_internal(size_t size, int cpu, int zero)
{
    return _kmem_malloc_internal(size, zero);
}

void
kmem_free_internal (void * addr)
{
    ulong_t order;

    if (!addr) {
        return;
    }
    if ((uint64_t)addr < internal_mem_start || (uint64_t)addr >= internal_mem_end) {
        KMEM_ERROR("Addr %p is not in the internal region", addr);
        KMEM_ERROR_BACKTRACE();
        return;
    }

    // internal zone only has one pool
    order = get_block_order(internal_mempool, addr);
    kmem_bytes_allocated_internal -= (1UL << order);
    buddy_free(internal_mempool, addr, order);
}
/**
 * Frees memory previously allocated with kmem_alloc().
 *
 * Arguments:
 *       [IN] addr: Address of the memory region to free.
 */
void
kmem_free (void * addr)
{
    struct kmem_unit_hdr *hdr;
    ulong_t order;

    KMEM_DEBUG("free of address %p from:\n", addr);
    KMEM_DEBUG_BACKTRACE();

#if SANITY_CHECK_PER_OP
    if (kmem_sanity_check()) { 
        panic("KMEM HAS GONE INSANE PRIOR TO FREE\n");
        return;
    }
#endif

    if (!addr) {
        return;
    }

    // currently do this to avoid modify every free() location
    if ((uint64_t)addr >= internal_mem_start && (uint64_t)addr < internal_mem_end) {
        kmem_free_internal(addr);
        return;
    }

    /* retrieve the mempool info */
    hdr = unit_hash_find_entry(addr);
    if (!hdr) {
        KMEM_ERROR("Failed to find entry for addr %p in kmem_free()\n",addr);
        KMEM_ERROR_BACKTRACE();
        return;
    }
    struct buddy_mempool *mp = hdr->mempool;
    /* Return block to the underlying buddy system */
    order = get_block_order(mp, addr);

    kmem_bytes_allocated_regular -= (1UL << order);
    buddy_free(mp, addr, order);
    KMEM_DEBUG("free succeeded: addr=0x%lx order=%lu\n",addr,order);

#if SANITY_CHECK_PER_OP
    if (kmem_sanity_check()) { 
        panic("KMEM HAS GONE INSANE AFTER FREE\n");
        return;
    }
#endif

}

/*
 * This is a *dead simple* implementation of realloc that tries to change the
 * size of the allocation pointed to by ptr to size, and returns ptr.  Realloc will
 * malloc a new block of memory, copy as much of the old data as it can, and free the
 * old block. If ptr is NULL, this is equivalent to a malloc for the specified size.
 *
 */
void * 
kmem_realloc (void * ptr, size_t size)
{
	struct kmem_unit_hdr *hdr;
	size_t old_size;
	void * tmp = NULL;

	/* this is just a malloc */
	if (!ptr) {
		return kmem_malloc(size);
	}

    /* get the order from mempool based on our hash */
    hdr = unit_hash_find_entry(ptr);
    if (!hdr) {
        KMEM_DEBUG("Realloc failed to find entry for addr %p\n", ptr);
        return NULL;
    }
    ulong_t order = get_block_order(hdr->mempool, ptr);

	old_size = 1 << order;
	tmp = kmem_malloc(size);
	if (!tmp) {
		panic("Realloc failed\n");
	}

	if (old_size >= size) {
		memcpy(tmp, ptr, size);
	} else {
		memcpy(tmp, ptr, old_size);
	}
	
	kmem_free(ptr);
	return tmp;
}

void * 
kmem_realloc_internal (void * ptr, size_t size)
{
	size_t old_size;
	void * tmp = NULL;

	/* this is just a malloc */
	if (!ptr) {
		return kmem_malloc_internal(size);
	}

    if ((uint64_t)ptr < internal_mem_start || (uint64_t)ptr >= internal_mem_end) {
        KMEM_ERROR("realloc(): Old ptr %p is not in the internal region", ptr);
        KMEM_ERROR_BACKTRACE();
        return NULL;
    }

    ulong_t order = get_block_order(internal_mempool, ptr);

	old_size = 1 << order;
	tmp = kmem_malloc_internal(size);
	if (!tmp) {
		panic("Realloc failed\n");
	}

	if (old_size >= size) {
		memcpy(tmp, ptr, size);
	} else {
		memcpy(tmp, ptr, old_size);
	}
	
    //kmem_free_internal(ptr);
    // just in case
	kmem_free(ptr);
	return tmp;
}


typedef enum {GET,COUNT} stat_type_t;

static uint64_t _kmem_stats(struct kmem_stats *stats, stat_type_t what)
{
    return 0;
#if 0
    uint64_t cur;
    struct mem_reg_entry * reg = NULL;
    struct kmem_data * my_kmem = &(nk_get_nautilus_info()->sys.cpus[my_cpu_id()]->kmem);
    if (what==GET) { 
	uint64_t num = stats->max_pools;
	memset(stats,0,sizeof(*stats));
	stats->min_alloc_size=-1;
	stats->max_pools = num;
    }

    // We will scan all memory from the current CPU's perspective
    // Since every CPUs sees all memory pools (albeit in NUMA order)
    // this will cover all memory
    cur = 0;
    list_for_each_entry(reg, &(my_kmem->ordered_regions), mem_ent) {
	if (what==GET) { 
	    struct buddy_mempool * zone = reg->mem->mm_state;
	    struct buddy_pool_stats pool_stats;
	    buddy_stats(zone,&pool_stats);
	    if (cur<stats->max_pools) { 
		stats->pool_stats[cur] = pool_stats;
		stats->num_pools++;
	    }
	    stats->total_blocks_free += pool_stats.total_blocks_free;
	    stats->total_bytes_free += pool_stats.total_bytes_free;
	    if (pool_stats.min_alloc_size < stats->min_alloc_size) { 
		stats->min_alloc_size = pool_stats.min_alloc_size;
	    }
	    if (pool_stats.max_alloc_size > stats->max_alloc_size) { 
		stats->max_alloc_size = pool_stats.max_alloc_size;
	    }
	}
	cur++;
    }
    if (what==GET) {
	stats->total_num_pools=cur;
    }
    return cur;
#endif
}


uint64_t kmem_num_pools()
{
    return _kmem_stats(0,COUNT);
}

void kmem_stats(struct kmem_stats *stats)
{
    _kmem_stats(stats,GET);
}

int kmem_sanity_check()
{
    return 0;
#if 0
    int rc=0;
    uint64_t cur;
    struct mem_reg_entry * reg = NULL;
    struct kmem_data * my_kmem = &(nk_get_nautilus_info()->sys.cpus[my_cpu_id()]->kmem);

    list_for_each_entry(reg, &(my_kmem->ordered_regions), mem_ent) {
	struct buddy_mempool * zone = reg->mem->mm_state;
	if (buddy_sanity_check(zone)) { 
	    ERROR_PRINT("buddy memory pool %p is insane\n", zone);
	    rc|=-1;
	}
    }

    return rc;
#endif
}


void  kmem_get_internal_pointer_range(void **start, void **end)
{
    *start = kmem_private_start;
    *end = kmem_private_end;
}

int  kmem_find_block(void *any_addr, void **block_addr, uint64_t *block_size, uint64_t *flags)
{
    return 0;
#if 0
    uint64_t i;
    uint64_t order;
    addr_t   zone_base;
    uint64_t zone_min_order;
    uint64_t zone_max_order;
    addr_t   any_offset;
    struct mem_region *reg;

    if (!(reg = kmem_get_region_by_addr((addr_t)any_addr))) {
	// not in any region we manage
	return -1;
    }

    if (any_addr>=boot_start && any_addr<boot_end) { 
	// in some boot_mm allocation that we treat as a single block
	*block_addr = boot_start;
	*block_size = boot_end-boot_start;
	*flags = boot_flags;
	KMEM_DEBUG("Search of %p found boot block (%p-%p)\n", any_addr, boot_start, boot_end);
	return 0;
    }

    zone_base = reg->mm_state->base_addr;
    zone_min_order = reg->mm_state->min_order;
    zone_max_order = reg->mm_state->pool_order;

    any_offset = (addr_t)any_addr - (addr_t)zone_base;
    
    for (order=zone_min_order;order<=zone_max_order;order++) {
	addr_t mask = ~((1ULL << order)-1);
	void *search_addr = (void*)(zone_base + (any_offset & mask));
	struct kmem_block_hdr *hdr = block_hash_find_entry(search_addr);
	// must exist and must be allocated
	if (hdr && hdr->order>=MIN_ORDER) { 
	    *block_addr = search_addr;
	    *block_size = 0x1ULL<<hdr->order;
	    *flags = hdr->flags;
	    return 0;
	    
	}
    }
    return -1;
#endif
}


// set the flags of an allocated block
int  kmem_set_block_flags(void *block_addr, uint64_t flags)
{
    return 0;
#if 0
    if (block_addr>=boot_start && block_addr<boot_end) { 
	boot_flags = flags;
	return 0;

    } else {

	struct kmem_block_hdr *h =  block_hash_find_entry(block_addr);
	
	if (!h || h->order<MIN_ORDER) { 
	    return -1;
	} else {
	    h->flags = flags;
	    return 0;
	}
    }
#endif
}

// applies only to allocated blocks
int  kmem_mask_all_blocks_flags(uint64_t mask, int or)
{
    return 0;
#if 0
    uint64_t i;

    if (!or) { 
	boot_flags &= mask;
	for (i=0;i<block_hash_num_entries;i++) { 
	    if (block_hash_entries[i].order>=MIN_ORDER) { 
		block_hash_entries[i].flags &= mask;
	    }
	}
    } else {
	boot_flags |= mask;
	for (i=0;i<block_hash_num_entries;i++) { 
	    if (block_hash_entries[i].order>=MIN_ORDER) { 
		block_hash_entries[i].flags |= mask;
	    }
	}
    }

    return 0;
#endif
}
    
int  kmem_apply_to_matching_blocks(uint64_t mask, uint64_t flags, int (*func)(void *block, void *state), void *state)
{
    return 0;
#if 0
    uint64_t i;
    
    if (((boot_flags & mask) == flags)) {
	if (func(boot_start,state)) { 
	    return -1;
	}
    }

    for (i=0;i<block_hash_num_entries;i++) { 
	if (block_hash_entries[i].order>=MIN_ORDER) { 
	    if ((block_hash_entries[i].flags & mask) == flags) {
		if (func(block_hash_entries[i].addr,state)) { 
		    return -1;
		}
	    }
	}
    } 
    
    return 0;
#endif
}
    

// We also create malloc, etc, functions to link to
// This is needed for C++ support or anything else
// that expects these to exist in some object file...

// First we generate functions using the macros, which means
// we get the glue logic from the macros, e.g., to the garbage collectors

#ifdef NAUT_CONFIG_PISCES
static inline void *ext_malloc(size_t size)
{
    // this is expanded using the malloc wrapper in mm.h
    return malloc(size);
}

static inline void *ext_realloc(void *p, size_t s)
{
    // this is expanded using the realloc wrapper in mm.h
    return realloc(p,s);
}
#undef malloc
#undef realloc
void *malloc(size_t size)
{
    // just keep it as mm.h
    return ext_malloc(size);
}

void free(void *p)
{
    kmem_free(p);
}

void *realloc(void *p, size_t n)
{
    // just keep it as mm.h
    return ext_realloc(p,n);
}
#else
static inline void *ext_malloc(size_t size)
{
    // this is expanded using the malloc wrapper in mm.h
    return malloc(size);
}

static inline void ext_free(void *p)
{
    // this is expanded using the free wrapper in mm.h
    free(p);
}

static inline void *ext_realloc(void *p, size_t s)
{
    // this is expanded using the realloc wrapper in mm.h
    return realloc(p,s);
}

// Next we blow away the macros

#undef malloc
#undef free
#undef realloc


// Finally, we generate the linkable functions

void *malloc(size_t size)
{
    return ext_malloc(size);
}

void free(void *p)
{
    return ext_free(p);
}

void *realloc(void *p, size_t n)
{
    return ext_realloc(p,n);
}
#endif

static int
handle_meminfo (char * buf, void * priv)
{
    int i;
    struct nk_locality_info * numa_info = &(nk_get_nautilus_info()->sys.locality_info);

    uint64_t used_internal = 0;
    uint64_t used_regular = 0;

    if(internal_zone) {
        nk_vc_printf("Internal zone:\n");
        used_internal = zone_mem_show(internal_zone);
    }
    
    nk_vc_printf("Regular zone:\n");
    for(i = 0; i < numa_info->num_domains; i++) {
        used_regular += zone_mem_show(numa_info->domains[i]->zone);
    }

    nk_vc_printf("\nInternal used %lu bytes.\nRegular used %lu bytes, used-peak %lu bytes.\n\n",
        used_internal, used_regular, kmem_bytes_allocated_regular_peak);
    return 0;
/*    
    uint64_t num = kmem_num_pools();
    struct kmem_stats *s = malloc(sizeof(struct kmem_stats)+num*sizeof(struct buddy_pool_stats));
    uint64_t i;

    if (!s) { 
        nk_vc_printf("Failed to allocate space for mem info\n");
        return 0;
    }

    s->max_pools = num;

    kmem_stats(s);

    for (i=0;i<s->num_pools;i++) { 
        nk_vc_printf("pool %lu %p-%p %lu blks free %lu bytes free\n  %lu bytes min %lu bytes max\n", 
                i,
                s->pool_stats[i].start_addr,
                s->pool_stats[i].end_addr,
                s->pool_stats[i].total_blocks_free,
                s->pool_stats[i].total_bytes_free,
                s->pool_stats[i].min_alloc_size,
                s->pool_stats[i].max_alloc_size);
    }

    nk_vc_printf("%lu pools %lu blks free %lu bytes free\n", s->total_num_pools, s->total_blocks_free, s->total_bytes_free);
    nk_vc_printf("  %lu bytes min %lu bytes max\n", s->min_alloc_size, s->max_alloc_size);

    free(s);

    return 0;
    */
}


static struct shell_cmd_impl meminfo_impl = {
    .cmd      = "meminfo",
    .help_str = "meminfo [detail]",
    .handler  = handle_meminfo,
};
nk_register_shell_cmd(meminfo_impl);


#define BYTES_PER_LINE 16

static int
handle_mem (char * buf, void * priv)
{
    uint64_t addr, data, len, size;

    if ((sscanf(buf, "mem %lx %lu %lu",&addr,&len,&size)==3) ||
            (size=8, sscanf(buf, "mem %lx %lu", &addr, &len)==2)) { 
        uint64_t i,j,k;
        for (i=0;i<len;i+=BYTES_PER_LINE) {
            nk_vc_printf("%016lx :",addr+i);
            for (j=0;j<BYTES_PER_LINE && (i+j)<len; j+=size) {
                nk_vc_printf(" ");
                for (k=0;k<size;k++) { 
                    nk_vc_printf("%02x", *(uint8_t*)(addr+i+j+k));
                }
            }
            nk_vc_printf(" ");
            for (j=0;j<BYTES_PER_LINE && (i+j)<len; j+=size) {
                for (k=0;k<size;k++) { 
                    nk_vc_printf("%c", isalnum(*(uint8_t*)(addr+i+j+k)) ? 
                            *(uint8_t*)(addr+i+j+k) : '.');
                }
            }
            nk_vc_printf("\n");
        }	      

        return 0;
    }
    return 0;
}

static struct shell_cmd_impl mem_impl = {
    .cmd      = "mem",
    .help_str = "mem x n [s]",
    .handler  = handle_mem,
};
nk_register_shell_cmd(mem_impl);


static int
handle_peek (char * buf, void * priv)
{
    uint64_t addr, data, len, size;
    char bwdq;

    if (((bwdq='b', sscanf(buf,"peek b %lx", &addr))==1) ||
            ((bwdq='w', sscanf(buf,"peek w %lx", &addr))==1) ||
            ((bwdq='d', sscanf(buf,"peek d %lx", &addr))==1) ||
            ((bwdq='q', sscanf(buf,"peek q %lx", &addr))==1) ||
            ((bwdq='q', sscanf(buf,"peek %lx", &addr))==1)) {
        switch (bwdq) { 
            case 'b': 
                data = *(uint8_t*)addr;       
                nk_vc_printf("Mem[0x%016lx] = 0x%02lx\n",addr,data);
                break;
            case 'w': 
                data = *(uint16_t*)addr;       
                nk_vc_printf("Mem[0x%016lx] = 0x%04lx\n",addr,data);
                break;
            case 'd': 
                data = *(uint32_t*)addr;       
                nk_vc_printf("Mem[0x%016lx] = 0x%08lx\n",addr,data);
                break;
            case 'q': 
                data = *(uint64_t*)addr;       
                nk_vc_printf("Mem[0x%016lx] = 0x%016lx\n",addr,data);
                break;
            default:
                nk_vc_printf("Unknown size requested\n",bwdq);
                break;
        }
        return 0;
    }

    nk_vc_printf("invalid poke command\n");

    return 0;
}

static struct shell_cmd_impl peek_impl = {
    .cmd      = "peek",
    .help_str = "peek [bwdq] x",
    .handler  = handle_peek,
};
nk_register_shell_cmd(peek_impl);

static int
handle_poke (char * buf, void * priv)
{
    uint64_t addr, data, len, size;
    char bwdq;

    if (((bwdq='b', sscanf(buf,"poke b %lx %lx", &addr,&data))==2) ||
            ((bwdq='w', sscanf(buf,"poke w %lx %lx", &addr,&data))==2) ||
            ((bwdq='d', sscanf(buf,"poke d %lx %lx", &addr,&data))==2) ||
            ((bwdq='q', sscanf(buf,"poke q %lx %lx", &addr,&data))==2) ||
            ((bwdq='q', sscanf(buf,"poke %lx %lx", &addr, &data))==2)) {
        switch (bwdq) { 
            case 'b': 
                *(uint8_t*)addr = data; clflush_unaligned((void*)addr,1);
                nk_vc_printf("Mem[0x%016lx] = 0x%02lx\n",addr,data);
                break;
            case 'w': 
                *(uint16_t*)addr = data; clflush_unaligned((void*)addr,2);
                nk_vc_printf("Mem[0x%016lx] = 0x%04lx\n",addr,data);
                break;
            case 'd': 
                *(uint32_t*)addr = data; clflush_unaligned((void*)addr,4);
                nk_vc_printf("Mem[0x%016lx] = 0x%08lx\n",addr,data);
                break;
            case 'q': 
                *(uint64_t*)addr = data; clflush_unaligned((void*)addr,8);
                nk_vc_printf("Mem[0x%016lx] = 0x%016lx\n",addr,data);
                break;
            default:
                nk_vc_printf("Unknown size requested\n");
                break;
        }
        return 0;
    }

    nk_vc_printf("invalid poke command\n");

    return 0;
}

static struct shell_cmd_impl poke_impl = {
    .cmd      = "poke",
    .help_str = "poke [bwdq] x y",
    .handler  = handle_poke,
};
nk_register_shell_cmd(poke_impl);
