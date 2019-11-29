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
 * http://xtack.sandia.gov/hobbes
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
#include <nautilus/nautilus.h>
#include <nautilus/paging.h>
#include <nautilus/naut_string.h>
#include <nautilus/mb_utils.h>
#include <nautilus/idt.h>
#include <nautilus/cpu.h>
#include <nautilus/errno.h>
#include <nautilus/cpuid.h>
#include <nautilus/backtrace.h>
#include <nautilus/macros.h>
#include <nautilus/naut_assert.h>
#include <nautilus/numa.h>
#include <nautilus/mm.h>
#include <lib/bitmap.h>
#include <nautilus/percpu.h>

#ifdef NAUT_CONFIG_XEON_PHI
#include <nautilus/sfi.h>
#endif

#ifdef NAUT_CONFIG_HVM_HRT
#include <arch/hrt/hrt.h>
#endif

#ifndef NAUT_CONFIG_DEBUG_PAGING
#undef DEBUG_PRINT
#define DEBUG_PRINT(fmt, args...)
#endif

#ifdef NAUT_CONFIG_PISCES
#include <arch/pisces/pisces_boot_params.h>
extern addr_t _loadStart;
#endif

extern uint8_t boot_mm_inactive;

extern ulong_t pml4;


static char * ps2str[3] = {
    [PS_4K] = "4KB",
    [PS_2M] = "2MB",
    [PS_1G] = "1GB",
};


extern uint8_t cpu_info_ready;

/*
 * align_addr
 *
 * align addr *up* to the nearest align boundary
 *
 * @addr: address to align
 * @align: power of 2 to align to
 *
 * returns the aligned address
 * 
 */
static inline ulong_t
align_addr (ulong_t addr, ulong_t align) 
{
    ASSERT(!(align & (align-1)));
    return (~(align - 1)) & (addr + align);
}


static inline int
gig_pages_supported (void)
{
    cpuid_ret_t ret;
    struct cpuid_amd_edx_flags flags;
    cpuid(CPUID_AMD_FEATURE_INFO, &ret);
    flags.val = ret.d;
    return flags.pg1gb;
}


static page_size_t
largest_page_size (void)
{
#ifdef NAUT_CONFIG_PISCES
    return PS_2M; // zjp: TODO test
#else
    if (gig_pages_supported()) {
        return PS_1G;
    }

    return PS_2M;
#endif
}

/*
static int 
drill_pt (pte_t * pt, addr_t addr, addr_t map_addr, uint64_t flags)
{
    uint_t pt_idx = PADDR_TO_PT_IDX(addr);
    addr_t page = 0;

    DEBUG_PRINT("drilling pt, pt idx: 0x%x\n", pt_idx);

    if (PTE_PRESENT(pt[pt_idx])) {

        DEBUG_PRINT("pt entry is present\n");
        page = (addr_t)(pt[pt_idx] & PTE_ADDR_MASK);

    } else {

        DEBUG_PRINT("pt entry not there, creating a new one\n");

        if (map_addr) {

            DEBUG_PRINT("creating manual mapping to paddr: %p\n", map_addr);
            page = map_addr;
            pt[pt_idx] = page | flags;

        } else {
            page = alloc_page();

            if (!page) {
                ERROR_PRINT("out of memory in %s\n", __FUNCTION__);
                return -1;
            }

            DEBUG_PRINT("allocated new page at 0x%x\n", page);

            pt[pt_idx] = page | PTE_PRESENT_BIT | PTE_WRITABLE_BIT;
        }

    }

    return 0;
}
*/


static int 
drill_pd (pde_t * pd, addr_t addr, addr_t map_addr, uint64_t flags)
{
    uint_t pd_idx = PADDR_TO_PD_IDX(addr);
    pte_t * pt = 0;
    addr_t page = 0;

    DEBUG_PRINT("drilling pd, pd idx: 0x%x\n", pd_idx);

    if (PDE_PRESENT(pd[pd_idx])) {

        DEBUG_PRINT("pd entry is present, setting (addr=%p,flags=%x)\n", (void*)map_addr,flags);
        pd[pd_idx] = map_addr | flags | PTE_PAGE_SIZE_BIT | PTE_PRESENT_BIT;
        invlpg(map_addr);

    } else {

        if (map_addr) {

            DEBUG_PRINT("creating manual mapping to paddr: %p\n", map_addr);
            page = map_addr;
            // NOTE: 2MB page assumption
            pd[pd_idx] = page | flags | PTE_PAGE_SIZE_BIT;

        } else {

            panic("trying to allocate 2MB page with no address provided!\n");
#if 0
            DEBUG_PRINT("pd entry not there, creating a new one\n");
            pt = (pte_t*)alloc_page();

            if (!pt) {
                ERROR_PRINT("out of memory in %s\n", __FUNCTION__);
                return -1;
            }

            memset((void*)pt, 0, NUM_PT_ENTRIES*sizeof(pte_t));

            pd[pd_idx] = (ulong_t)pt | PTE_PRESENT_BIT | PTE_WRITABLE_BIT;
#endif
        }
    }

    return 0;
}


static int 
drill_pdpt (pdpte_t * pdpt, addr_t addr, addr_t map_addr, uint64_t flags)
{
    uint_t pdpt_idx = PADDR_TO_PDPT_IDX(addr);
    pde_t * pd = 0;

    DEBUG_PRINT("drilling pdpt, pdpt idx: 0x%x\n", pdpt_idx);

    if (PDPTE_PRESENT(pdpt[pdpt_idx])) {

        DEBUG_PRINT("pdpt entry is present\n");
        pd = (pde_t*)(pdpt[pdpt_idx] & PTE_ADDR_MASK);

    } else {

        DEBUG_PRINT("pdpt entry not there, creating a new page directory\n");
        pd = (pde_t*)mm_boot_alloc_aligned(PAGE_SIZE_4KB, PAGE_SIZE_4KB);
        DEBUG_PRINT("page dir allocated at %p\n", pd);

        if (!pd) {
            ERROR_PRINT("out of memory in %s\n", __FUNCTION__);
            return -EINVAL;
        }

        memset((void*)pd, 0, NUM_PD_ENTRIES*sizeof(pde_t));

        pdpt[pdpt_idx] = (ulong_t)pd | PTE_PRESENT_BIT | PTE_WRITABLE_BIT;

    }

    DEBUG_PRINT("the entry (addr: 0x%x): 0x%x\n", &pdpt[pdpt_idx], pdpt[pdpt_idx]);
    return drill_pd(pd, addr, map_addr, flags);
}


static int 
drill_page_tables (addr_t addr, addr_t map_addr, uint64_t flags)
{
#ifdef NAUT_CONFIG_PISCES
    return fill_page_tables(addr, map_addr, PAGE_SIZE_2MB, flags);
#endif
    pml4e_t * _pml4 = (pml4e_t*)read_cr3();
    uint_t pml4_idx = PADDR_TO_PML4_IDX(addr);
    pdpte_t * pdpt  = 0;
    
    if (PML4E_PRESENT(_pml4[pml4_idx])) {

        DEBUG_PRINT("pml4 entry is present\n");
        pdpt = (pdpte_t*)(_pml4[pml4_idx] & PTE_ADDR_MASK);

    } else {

        panic("no PML4 entry!\n");

        DEBUG_PRINT("pml4 entry not there, creating a new one\n");

        pdpt = (pdpte_t*)mm_boot_alloc_aligned(PAGE_SIZE_4KB, PAGE_SIZE_4KB);

        if (!pdpt) {
            ERROR_PRINT("out of memory in %s\n", __FUNCTION__);
            return -EINVAL;
        }

        memset((void*)pdpt, 0, NUM_PDPT_ENTRIES*sizeof(pdpte_t));
        _pml4[pml4_idx] = (ulong_t)pdpt | PTE_PRESENT_BIT | PTE_WRITABLE_BIT;
    }

    DEBUG_PRINT("the entry (addr: 0x%x): 0x%x\n", &_pml4[pml4_idx], _pml4[pml4_idx]);
    return drill_pdpt(pdpt, addr, map_addr, flags);
}


/*
 * nk_map_page
 *
 * @vaddr: virtual address to map to
 * @paddr: physical address to create mapping for 
 *         (must be page aligned)
 * @flags: bits to set in the PTE
 *
 * create a manual page mapping
 * (currently unused since we're using an ident map)
 *
 */
int 
nk_map_page (addr_t vaddr, addr_t paddr, uint64_t flags, page_size_t ps)
{
    if (drill_page_tables(ROUND_DOWN_TO_PAGE(paddr), ROUND_DOWN_TO_PAGE(paddr), flags) != 0) {
        ERROR_PRINT("Could not map page at vaddr %p paddr %p\n", (void*)vaddr, (void*)paddr);
        return -EINVAL;
    }

    return 0;
}


/*
 * nk_map_page_nocache
 *
 * map this page as non-cacheable
 * 
 * @paddr: the physical address to create a mapping for
 *         (must be page aligned)
 * @flags: the flags (besides non-cacheable) to use in the PTE
 *
 * returns -EINVAL on error, 0 on success 
 *
 */
int
nk_map_page_nocache (addr_t paddr, uint64_t flags, page_size_t ps)
{
    if (nk_map_page(paddr, paddr, flags|PTE_CACHE_DISABLE_BIT, ps) != 0) {
        ERROR_PRINT("Could not map uncached page\n");
        return -EINVAL;
    }

    return 0;
}


/*
 * nk_pf_handler
 *
 * page fault handler
 *
 */
int
nk_pf_handler (excp_entry_t * excp,
               excp_vec_t     vector,
               addr_t         fault_addr)
{

    cpu_id_t id = cpu_info_ready ? my_cpu_id() : 0xffffffff;

#ifdef NAUT_CONFIG_HVM_HRT
    if (excp->error_code == UPCALL_MAGIC_ERROR) {
        return nautilus_hrt_upcall_handler(NULL, 0);
    }
#endif

    printk("\n+++ Page Fault +++\n"
            "RIP: %p    Fault Address: 0x%llx \n"
            "Error Code: 0x%x    (core=%u)\n", 
            (void*)excp->rip, 
            fault_addr, 
            excp->error_code, 
            id);

    struct nk_regs * r = (struct nk_regs*)((char*)excp - 128);
    nk_print_regs(r);
    backtrace(r->rbp);

    panic("+++ HALTING +++\n");
    return 0;
}


/* don't really use the page size here, unless we get bigger pages 
 * someday
 */
static void
__fill_pml (pml4e_t * pml, 
            page_size_t ps, 
            ulong_t base_addr,
            ulong_t nents, 
            ulong_t flags)
{
    ulong_t i;

    ASSERT(nents <= NUM_PML4_ENTRIES);

    for (i = 0; i < nents; i++) {
        pdpte_t * pdpt = NULL;
        pdpt = mm_boot_alloc_aligned(PAGE_SIZE_4KB, PAGE_SIZE_4KB);
        if (!pdpt) {
            ERROR_PRINT("Could not allocate pdpt\n");
            return;
        }
        memset((void*)pdpt, 0, PAGE_SIZE_4KB);
        pml[i] = (ulong_t)pdpt | flags;
    }

}


static void
__fill_pdpt (pdpte_t * pdpt, 
             page_size_t ps, 
             ulong_t base_addr,
             ulong_t nents,
             ulong_t flags)
{
    ulong_t i;

    ASSERT(nents <= NUM_PDPT_ENTRIES);

    for (i = 0; i < nents; i++) {

        if (ps == PS_1G) {
            pdpt[i] = base_addr | flags | PTE_PAGE_SIZE_BIT;
        } else {
            pde_t * pd = NULL;
            pd = mm_boot_alloc_aligned(PAGE_SIZE_4KB, PAGE_SIZE_4KB);
            if (!pd) {
                ERROR_PRINT("Could not allocate pd\n");
                return;
            }
            memset(pd, 0, PAGE_SIZE_4KB);
            pdpt[i] = (ulong_t)pd | flags;
        }

        base_addr += PAGE_SIZE_1GB;
    }
}

static void
__fill_pd (pde_t * pd, 
           page_size_t ps, 
           ulong_t base_addr,
           ulong_t nents,
           ulong_t flags)
{
    ulong_t i;

    ASSERT(nents <= NUM_PD_ENTRIES);
    ASSERT(ps == PS_2M || ps == PS_4K);

    for (i = 0; i < nents; i++) {

        if (ps == PS_2M) {
            pd[i] = base_addr | flags | PTE_PAGE_SIZE_BIT;
        } else {
            pte_t * pt = NULL;
            pt = mm_boot_alloc_aligned(PAGE_SIZE_4KB, PAGE_SIZE_4KB);
            if (!pt) {
                ERROR_PRINT("Could not allocate pt\n");
                return;
            }
            memset(pt, 0, PAGE_SIZE_4KB);
            pd[i] = (ulong_t)pt | flags;
        }

        base_addr += PAGE_SIZE_2MB;

    }
}


static void
__fill_pt (pte_t * pt, 
           page_size_t ps, 
           ulong_t base_addr,
           ulong_t nents,
           ulong_t flags)
{
    ulong_t i;

    ASSERT(ps == PS_4K);
    ASSERT(nents <= NUM_PT_ENTRIES);

    for (i = 0; i < nents; i++) {
        pt[i] = base_addr | flags;
        base_addr += PAGE_SIZE_4KB;
    }
}

static void
__construct_tables_4k (pml4e_t * pml, ulong_t bytes)
{
    ulong_t npages    = (bytes + PAGE_SIZE_4KB - 1)/PAGE_SIZE_4KB;
    ulong_t num_pts   = (npages + NUM_PT_ENTRIES - 1)/ NUM_PT_ENTRIES;
    ulong_t num_pds   = (num_pts + NUM_PD_ENTRIES - 1)/NUM_PD_ENTRIES;
    ulong_t num_pdpts = (num_pds + NUM_PDPT_ENTRIES - 1)/NUM_PDPT_ENTRIES;
    ulong_t filled_pdpts = 0;
    ulong_t filled_pds   = 0;
    ulong_t filled_pts   = 0;
    ulong_t filled_pgs   = 0;
    unsigned i, j, k;
    ulong_t addr = 0;

    __fill_pml(pml, PS_4K, addr, num_pdpts, PTE_PRESENT_BIT | PTE_WRITABLE_BIT);

    for (i = 0; i < NUM_PML4_ENTRIES && filled_pdpts < num_pdpts; i++) {

        pdpte_t * pdpt = (pdpte_t*)PTE_ADDR(pml[i]);
        ulong_t pdpte_to_fill = ((num_pds - filled_pds) > NUM_PDPT_ENTRIES) ? NUM_PDPT_ENTRIES:
            (num_pds - filled_pds);
        __fill_pdpt(pdpt, PS_4K, addr, pdpte_to_fill, PTE_PRESENT_BIT | PTE_WRITABLE_BIT);

        for (j = 0; j < NUM_PDPT_ENTRIES && filled_pds < num_pds; j++) {

            pde_t * pd = (pde_t*)PTE_ADDR(pdpt[j]);
            ulong_t pde_to_fill = ((num_pts - filled_pts) > NUM_PD_ENTRIES) ? NUM_PD_ENTRIES:
                (num_pts - filled_pts);
            __fill_pd(pd, PS_4K, addr, pde_to_fill, PTE_PRESENT_BIT | PTE_WRITABLE_BIT);

            for (k = 0; k < NUM_PD_ENTRIES && filled_pts < num_pts; k++) {

                pte_t * pt = (pte_t*)PTE_ADDR(pd[k]);

                ulong_t to_fill = ((npages - filled_pgs) > NUM_PT_ENTRIES) ? NUM_PT_ENTRIES : 
                    npages - filled_pgs;

                __fill_pt(pt, PS_4K, addr, to_fill, PTE_PRESENT_BIT | PTE_WRITABLE_BIT);

                filled_pgs += to_fill;
                addr += PAGE_SIZE_4KB*to_fill;

                ++filled_pts;
            }

            ++filled_pds;
        }

        ++filled_pdpts;
    }
}


static void
__construct_tables_2m (pml4e_t * pml, ulong_t bytes)
{
    ulong_t npages    = (bytes + PAGE_SIZE_2MB - 1)/PAGE_SIZE_2MB;
    ulong_t num_pds   = (npages + NUM_PD_ENTRIES - 1)/NUM_PD_ENTRIES;
    ulong_t num_pdpts = (num_pds + NUM_PDPT_ENTRIES - 1)/NUM_PDPT_ENTRIES;
    ulong_t filled_pdpts = 0;
    ulong_t filled_pds   = 0;
    ulong_t filled_pgs   = 0;
    unsigned i, j;
    ulong_t addr = 0;

    __fill_pml(pml, PS_2M, addr, num_pdpts, PTE_PRESENT_BIT | PTE_WRITABLE_BIT);

    for (i = 0; i < NUM_PML4_ENTRIES && filled_pdpts < num_pdpts; i++) {

        pdpte_t * pdpt = (pdpte_t*)PTE_ADDR(pml[i]);
        ulong_t pdpte_to_fill = ((num_pds - filled_pds) > NUM_PDPT_ENTRIES) ? NUM_PDPT_ENTRIES:
            (num_pds - filled_pds);
        __fill_pdpt(pdpt, PS_2M, addr, pdpte_to_fill, PTE_PRESENT_BIT | PTE_WRITABLE_BIT);

        for (j = 0; j < NUM_PDPT_ENTRIES && filled_pds < num_pds; j++) {

            pde_t * pd = (pde_t*)PTE_ADDR(pdpt[j]);

            ulong_t to_fill = ((npages - filled_pgs) > NUM_PD_ENTRIES) ? NUM_PD_ENTRIES : 
                npages - filled_pgs;

            __fill_pd(pd, PS_2M, addr, to_fill, PTE_PRESENT_BIT | PTE_WRITABLE_BIT);

            filled_pgs += to_fill;
            addr += PAGE_SIZE_2MB*to_fill;

            ++filled_pds;
        }

        ++filled_pdpts;
    }

    ASSERT(filled_pgs == npages);
}


static void
__construct_tables_1g (pml4e_t * pml, ulong_t bytes)
{
    ulong_t npages = (bytes + PAGE_SIZE_1GB - 1)/PAGE_SIZE_1GB;
    ulong_t num_pdpts = (npages + NUM_PDPT_ENTRIES - 1)/NUM_PDPT_ENTRIES;
    ulong_t filled_pdpts = 0;
    ulong_t filled_pgs   = 0;
    unsigned i;
    ulong_t addr = 0;

    __fill_pml(pml, PS_1G, addr, num_pdpts, PTE_PRESENT_BIT | PTE_WRITABLE_BIT);

    for (i = 0; i < NUM_PML4_ENTRIES && filled_pdpts < num_pdpts; i++) {

        pdpte_t * pdpt = (pdpte_t*)PTE_ADDR(pml[i]);

        ulong_t to_fill = ((npages - filled_pgs) > NUM_PDPT_ENTRIES) ? NUM_PDPT_ENTRIES : 
            npages - filled_pgs;

        __fill_pdpt(pdpt, PS_1G, addr, to_fill, PTE_PRESENT_BIT | PTE_WRITABLE_BIT);

        filled_pgs += to_fill;
        addr += PAGE_SIZE_1GB*to_fill;

        ++filled_pdpts;
    }
}


static void 
construct_ident_map (pml4e_t * pml, page_size_t ptype, ulong_t bytes)
{
    ulong_t ps = ps_type_to_size(ptype);

    switch (ptype) {
        case PS_4K:
            __construct_tables_4k(pml, bytes);
            break;
        case PS_2M:
            __construct_tables_2m(pml, bytes);
            break;
        case PS_1G:
            __construct_tables_1g(pml, bytes);
            break;
        default:
            ERROR_PRINT("Undefined page type (%u)\n", ptype);
            return;
    }
}

#ifdef NAUT_CONFIG_PISCES
static spinlock_t pagetable_lock;

#define PAGETABLE_LOCK_CONF uint8_t _pagetable_lock_flags;
#define PAGETABLE_LOCK() _pagetable_lock_flags = spin_lock_irq_save(&pagetable_lock);
#define PAGETABLE_UNLOCK() spin_unlock_irq_restore(&pagetable_lock, _pagetable_lock_flags);
/*
 * Update page table for a continuous range [addr, addr + size).
 * Currently support 2MB page.
 */

static int
__fill_page_tables (pml4e_t * pml4,
                    addr_t addr,
                    addr_t map_addr,
                    ulong_t size,
                    ulong_t flags,
                    int invalidate_tlb) 
{
    pdpte_t * pdpt  = 0;
    pde_t * pd = 0;

    ulong_t pml4_idx_start = PADDR_TO_PML4_IDX(addr);
    ulong_t pml4_idx_end = 0;
    ulong_t pdpt_idx_last = 0;
    ulong_t pd_idx_last = 0;

    // adjust the index of the last entry, when the end address is aligned to boundary
    ulong_t end_addr = addr + size;
    pd_idx_last = PADDR_TO_PD_IDX(end_addr - 1);
    pdpt_idx_last = PADDR_TO_PDPT_IDX(end_addr - 1);
    pml4_idx_end = PADDR_TO_PML4_IDX(end_addr - 1);

    ulong_t pml4_idx;
    // PML4 level
    PAGETABLE_LOCK_CONF;
    PAGETABLE_LOCK();
    //preempt_disable();
    for(pml4_idx = pml4_idx_start; pml4_idx <= pml4_idx_end; pml4_idx++) {
        if (likely(PML4E_PRESENT(pml4[pml4_idx]))) {
            DEBUG_PRINT("pml4 entry is present\n");
            pdpt = (pdpte_t*)(pml4[pml4_idx] & PTE_ADDR_MASK);
        } else {
            DEBUG_PRINT("pml4 entry not there, creating a new one\n");
            if(likely(boot_mm_inactive == 1))
                pdpt = (pdpte_t*)kmem_malloc_internal(PAGE_SIZE_4KB);
            else
                pdpt = (pdpte_t*)mm_boot_alloc_aligned(PAGE_SIZE_4KB, PAGE_SIZE_4KB);

            if (!pdpt) {
                ERROR_PRINT("out of memory in %s\n", __FUNCTION__);
                panic("out of memory in %s\n", __FUNCTION__);
                return -EINVAL;
            }

            memset((void*)pdpt, 0, PAGE_SIZE_4KB);
            pml4[pml4_idx] = (ulong_t)pdpt | flags;
        }

        DEBUG_PRINT("the entry (addr: 0x%x): 0x%x\n", &pml4[pml4_idx], pml4[pml4_idx]);

        // PDPT level
        ulong_t pdpt_idx_start = (pml4_idx == pml4_idx_start) ?
                                    PADDR_TO_PDPT_IDX(addr) : 0;
        ulong_t pdpt_idx_end = (pml4_idx == pml4_idx_end) ?
                                    pdpt_idx_last : (NUM_PDPT_ENTRIES - 1);
        ulong_t pdpt_idx;
        for(pdpt_idx = pdpt_idx_start; pdpt_idx <= pdpt_idx_end; pdpt_idx++) {
            if (PDPTE_PRESENT(pdpt[pdpt_idx])) {
                DEBUG_PRINT("pdpt entry is present\n");
                pd = (pde_t*)(pdpt[pdpt_idx] & PTE_ADDR_MASK);
            } else {
                DEBUG_PRINT("pdpt entry not there, creating a new page directory\n");
                if(likely(boot_mm_inactive == 1))
                    pd = (pde_t*)kmem_malloc_internal(PAGE_SIZE_4KB);
                else
                    pd = (pde_t*)mm_boot_alloc_aligned(PAGE_SIZE_4KB, PAGE_SIZE_4KB);

                if (!pd) {
                    ERROR_PRINT("out of memory in %s\n", __FUNCTION__);
                    panic("out of memory in %s\n", __FUNCTION__);
                    return -EINVAL;
                }

                memset((void*)pd, 0, PAGE_SIZE_4KB);
                pdpt[pdpt_idx] = (ulong_t)pd | flags;
            }

            // PD level
            ulong_t pd_idx_start = (pml4_idx == pml4_idx_start && pdpt_idx == pdpt_idx_start) ? 
                                        PADDR_TO_PD_IDX(addr) : 0;
            ulong_t pd_idx_end = (pml4_idx == pml4_idx_end && pdpt_idx == pdpt_idx_end) ? 
                                        pd_idx_last : (NUM_PD_ENTRIES - 1);
            ulong_t pd_idx;
            for(pd_idx = pd_idx_start; pd_idx <= pd_idx_end; pd_idx++) {
                // Support 2MB page 
                if (PDE_PRESENT(pd[pd_idx])) {
                    DEBUG_PRINT("pde is present, setting (addr=%p,flags=%x) on pml4_idx %d pdpt_idx %d pd_idx %d\n",
                                    (void*)map_addr,flags, pml4_idx, pdpt_idx, pd_idx);
                    pd[pd_idx] = map_addr | flags | PTE_PAGE_SIZE_BIT | PTE_PRESENT_BIT;
                    if(likely(invalidate_tlb))
                        invlpg(map_addr);
                } else {
                    DEBUG_PRINT("pde is not present, setting (addr=%p,flags=%x) on pml4_idx %d pdpt_idx %d pd_idx %d\n",
                                    (void*)map_addr,flags, pml4_idx, pdpt_idx, pd_idx);
                    pd[pd_idx] = map_addr | flags | PTE_PAGE_SIZE_BIT;
                }

                map_addr += PAGE_SIZE_2MB;
            }
        }
    }
    //preempt_enable();
    PAGETABLE_UNLOCK();
    return 0;
}

int
free_page_tables (addr_t addr, ulong_t size)
{
    pml4e_t * pml4 = (pml4e_t*)read_cr3();
    pdpte_t * pdpt  = 0;
    pde_t * pd = 0;
    ulong_t vaddr = addr;

    ulong_t pml4_idx_start = PADDR_TO_PML4_IDX(addr);
    ulong_t pml4_idx_end = 0;
    ulong_t pdpt_idx_last = 0;
    ulong_t pd_idx_last = 0;

    // adjust the index of the last entry, when the end address is aligned to boundary
    ulong_t end_addr = addr + size;
    pd_idx_last = PADDR_TO_PD_IDX(end_addr - 1);
    pdpt_idx_last = PADDR_TO_PDPT_IDX(end_addr - 1);
    pml4_idx_end = PADDR_TO_PML4_IDX(end_addr - 1);

    ulong_t pml4_idx;
    PAGETABLE_LOCK_CONF;
    PAGETABLE_LOCK();
    //preempt_disable();
    // PML4 level
    for(pml4_idx = pml4_idx_start; pml4_idx <= pml4_idx_end; pml4_idx++) {
        if (likely(PML4E_PRESENT(pml4[pml4_idx]))) {
            DEBUG_PRINT("pml4 entry is present\n");
            pdpt = (pdpte_t*)(pml4[pml4_idx] & PTE_ADDR_MASK);
        } else {
            panic("%s: pml4 entry is not present!!!\n", __FUNCTION__);
            return -EINVAL;
        }

        // PDPT level
        ulong_t pdpt_idx_start = (pml4_idx == pml4_idx_start) ?
                                    PADDR_TO_PDPT_IDX(addr) : 0;
        ulong_t pdpt_idx_end = (pml4_idx == pml4_idx_end) ?
                                    pdpt_idx_last : (NUM_PDPT_ENTRIES - 1);
        ulong_t pdpt_idx;
        for(pdpt_idx = pdpt_idx_start; pdpt_idx <= pdpt_idx_end; pdpt_idx++) {
            if (PDPTE_PRESENT(pdpt[pdpt_idx])) {
                DEBUG_PRINT("pdpt entry is present\n");
                pd = (pde_t*)(pdpt[pdpt_idx] & PTE_ADDR_MASK);
            } else {
                panic("%s: pdpt entry is not present!!!\n", __FUNCTION__);
                return -EINVAL;
            }

            // PD level
            ulong_t pd_idx_start = (pml4_idx == pml4_idx_start && pdpt_idx == pdpt_idx_start) ? 
                                        PADDR_TO_PD_IDX(addr) : 0;
            ulong_t pd_idx_end = (pml4_idx == pml4_idx_end && pdpt_idx == pdpt_idx_end) ? 
                                        pd_idx_last : (NUM_PD_ENTRIES - 1);
            ulong_t pd_idx;
            for(pd_idx = pd_idx_start; pd_idx <= pd_idx_end; pd_idx++) {
                // Support 2MB page 
                if (PDE_PRESENT(pd[pd_idx])) {
                    DEBUG_PRINT("free pde pml4_idx %d pdpt_idx %d pd_idx %d\n", pml4_idx, pdpt_idx, pd_idx);
                    pd[pd_idx] = 0; 
                    invlpg(vaddr);
                } else {
                    panic("%s: pd entry is not present!!!\n", __FUNCTION__);
                    return -EINVAL;
                }

                vaddr += PAGE_SIZE_2MB;
            }
            // If All PD level entries are freed, backwards to PDPT level
            if(pd_idx_start == 0 && pd_idx_end == NUM_PD_ENTRIES - 1) {
                kmem_free_internal(pd);
                pdpt[pdpt_idx] = 0;
                DEBUG_PRINT("free pdpte pml4_idx %d pdpt_idx %d pd_idx %d\n", pml4_idx, pdpt_idx, pd_idx);
                // If All PDPT level entries are freed, backwars to PML level
                ulong_t pdpt_index;
                for(pdpt_index = 0; pdpt_index < NUM_PDPT_ENTRIES; pdpt_index++) {
                    if(pdpt[pdpt_index] != 0)
                        break;
                }
                if(pdpt_index == NUM_PDPT_ENTRIES) {
                    kmem_free_internal(pdpt);
                    pml4[pml4_idx] = 0;
                    DEBUG_PRINT("free pmle pml4_idx %d pdpt_idx %d pd_idx %d\n", pml4_idx, pdpt_idx, pd_idx);
                }
            }
        }
    }
    //preempt_enable();
    PAGETABLE_UNLOCK();
    return 0;
}

int
fill_page_tables (addr_t addr,
                    addr_t map_addr,
                    ulong_t size,
                    ulong_t flags)
{
    //return __fill_page_tables ((pml4e_t*)read_cr3(), addr, map_addr, size, flags, 1);
    addr_t aligned_addr = round_down(addr, PAGE_SIZE_2MB);
    addr_t aligned_map_addr = round_down(map_addr, PAGE_SIZE_2MB);
    addr_t aligned_addr_end = round_up(addr + size, PAGE_SIZE_2MB);
    ulong_t aligned_size = aligned_addr_end - aligned_addr;
    return __fill_page_tables ((pml4e_t*)read_cr3(), aligned_addr, aligned_map_addr, aligned_size, flags, 1);
}

static void
__construct_tables_2m_pisces(pml4e_t * pml)
{
    // Pisces uses 2MB alignment 

    /* Step 1: identity mapping */ 
    __fill_page_tables(pml, pisces_boot_params->base_mem_paddr,
                            pisces_boot_params->base_mem_paddr, 
                            pisces_boot_params->base_mem_size,
                            PTE_PRESENT_BIT | PTE_WRITABLE_BIT, 0);

    /* Step 2: offset mapping */
    ulong_t kernel_start_page = round_down((ulong_t)&_loadStart, PAGE_SIZE_2MB);
    ulong_t kernel_end_page = round_up((ulong_t)&_loadStart + pisces_boot_params->kernel_size, PAGE_SIZE_2MB);
    __fill_page_tables(pml, kernel_start_page,
                            pisces_boot_params->kernel_addr,
                            kernel_end_page - kernel_start_page,
                            PTE_PRESENT_BIT | PTE_WRITABLE_BIT, 0);
}

static void
construct_ident_map_pisces (pml4e_t * pml, page_size_t ptype)
{
    switch (ptype) {
        case PS_4K:
            //__construct_tables_4k_pisces(pml);
            break;
        case PS_2M:
            __construct_tables_2m_pisces(pml);
            break;
        case PS_1G:
            //__construct_tables_1g_pisces(pml);
            break;
        default:
            ERROR_PRINT("Undefined page type (%u)\n", ptype);
            return;
    }

}
#endif
/* 
 * Identity map all of physical memory using
 * the largest pages possible
 */
static void
kern_ident_map (struct nk_mem_info * mem, ulong_t mbd)
{
    page_size_t lps  = largest_page_size();
    ulong_t last_pfn = mm_boot_last_pfn();
    ulong_t ps       = ps_type_to_size(lps);
    pml4e_t * pml    = NULL;

    /* create a new PML4 */
    pml = mm_boot_alloc_aligned(PAGE_SIZE_4KB, PAGE_SIZE_4KB);
    if (!pml) {
        ERROR_PRINT("Could not allocate new PML4\n");
        return;
    }
    memset(pml, 0, PAGE_SIZE_4KB);



#ifdef NAUT_CONFIG_PISCES
    /* zjp:
     * temporarily fix pagefault for dynamically adding memory,
     * by mapping from 0x0 to a large enough address, e.g., 1TB.
     * TODO: better design for page fault
     */
    spinlock_init(&pagetable_lock);

    printk("Remapping phys mem [%p - %p] with %s pages\n", 
            pisces_boot_params->base_mem_paddr, 
            pisces_boot_params->base_mem_size, 
            ps2str[lps]);

    construct_ident_map_pisces(pml, lps);
#else
    printk("Remapping phys mem [%p - %p] with %s pages\n", 
            (void*)0, 
            (void*)(last_pfn<<PAGE_SHIFT), 
            ps2str[lps]);
    construct_ident_map(pml, lps, last_pfn<<PAGE_SHIFT);
#endif
    /* install the new tables, this will also flush the TLB */
    write_cr3((ulong_t)pml);
}


void
nk_paging_init (struct nk_mem_info * mem, ulong_t mbd)
{
    kern_ident_map(mem, mbd);
}
