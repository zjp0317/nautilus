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
#include <nautilus/mm.h>
#include <nautilus/mb_utils.h>
#include <nautilus/macros.h>
#include <nautilus/multiboot2.h>

#include <arch/pisces/pisces_boot_params.h>

extern char * mem_region_types[6];

#ifndef NAUT_CONFIG_DEBUG_BOOTMEM
#undef DEBUG_PRINT
#define DEBUG_PRINT(fmt, args...)
#endif

#define BMM_DEBUG(fmt, args...) DEBUG_PRINT("BOOTMEM: " fmt, ##args)
#define BMM_PRINT(fmt, args...) printk("BOOTMEM: " fmt, ##args)
#define BMM_WARN(fmt, args...)  WARN_PRINT("BOOTMEM: " fmt, ##args)


void 
arch_reserve_boot_regions (unsigned long mbd)
{
#ifdef NAUT_CONFIG_REAL_MODE_INTERFACE
    INFO_PRINT("Reserving Long->Real Interface Segment (%p, size %lu)\n",
		NAUT_CONFIG_REAL_MODE_INTERFACE_SEGMENT*16UL, 65536UL);
    mm_boot_reserve_mem((addr_t)(NAUT_CONFIG_REAL_MODE_INTERFACE_SEGMENT*16UL),
			(ulong_t)65536);
#endif
}

void
arch_detect_mem_map (mmap_info_t * mm_info, 
                     mem_map_entry_t * memory_map,
                     unsigned long mbd)
{
    /* 
     * Note that our buddy allocator requires ~1.5MB metadata for 128MB memory (see buddy.c).
     * --Map[0]. 0x0 ~ base_mem_paadr, mark as BAD RAM.
     * --Map[1]. The 1st block is for internal usage:
     *     Page tables, devices, metadata of the 1st buddy pool, etc.
     *     TODO: actually, the 1st buddy pool of each zone, when numa support is implemented.
     * --Map[2]. The 2nd block is the 1st buddy pool, which is used for:
     *     metadata of 3rd buddy pool, app/runtime usage
     * --Map[3]. The rest blocks if exist. 
     */
    int n = 0; // index for memory_map[]
    uint64_t addr = 0;
    uint64_t base_mem_end = pisces_boot_params->base_mem_paddr + pisces_boot_params->base_mem_size;
    /* keep filling memory_map till the end of base_mem */
    for(n = 0; addr < base_mem_end; n++) {
        if (n > MAX_MMAP_ENTRIES) {
            panic("Reached memory region limit!\n");
        }
        uint64_t len;
        uint32_t type;
        if(addr < pisces_boot_params->base_mem_paddr) {
            len = pisces_boot_params->base_mem_paddr;
            type = MULTIBOOT_MEMORY_BADRAM;
        } else {
            if(n >= 3) { // if more than 2 blocks exist
                len = pisces_boot_params->base_mem_size - 2 * pisces_boot_params->block_size;
            } else {
                len = pisces_boot_params->block_size;
            }

            type = MULTIBOOT_MEMORY_AVAILABLE;
            mm_info->usable_ram += len;
        }
        memory_map[n].addr = addr;
        memory_map[n].len  = len;
        memory_map[n].type = type;
        addr += len; 
        BMM_PRINT("Memory map[%d] - [%p - %p] <%s>\n",
                n,
                memory_map[n].addr,
                memory_map[n].addr + memory_map[n].len,
                mem_region_types[memory_map[n].type]);

        if (addr > (mm_info->last_pfn << PAGE_SHIFT)) {
            mm_info->last_pfn = addr >> PAGE_SHIFT;
        }

        mm_info->total_mem += memory_map[n].len;

        ++mm_info->num_regions;
    }
    return;

    /* zjp
     * The old code is based on multiboot. Keep it for reference.
     */
#if 0
    struct multiboot_tag * tag;
    uint32_t n = 0;

    if (mbd & 7) {
        panic("ERROR: Unaligned multiboot info struct\n");
    }

    tag = (struct multiboot_tag*)(mbd+8);
    while (tag->type != MULTIBOOT_TAG_TYPE_MMAP) {
        tag = (struct multiboot_tag*)((multiboot_uint8_t*)tag + ((tag->size+7)&~7));
    }

    if (tag->type != MULTIBOOT_TAG_TYPE_MMAP) {
        panic("ERROR: no mmap tag found\n");
    }

    multiboot_memory_map_t * mmap;

    for (mmap=((struct multiboot_tag_mmap*)tag)->entries;
            (multiboot_uint8_t*)mmap < (multiboot_uint8_t*)tag + tag->size;
            mmap = (multiboot_memory_map_t*)((ulong_t)mmap + 
                ((struct multiboot_tag_mmap*)tag)->entry_size)) {


        if (n > MAX_MMAP_ENTRIES) {
            panic("Reached memory region limit!\n");
        }

        ulong_t start,end;

        start = round_up(mmap->addr, PAGE_SIZE_4KB);
        end   = round_down(mmap->addr + mmap->len, PAGE_SIZE_4KB);

        memory_map[n].addr = start;
        memory_map[n].len  = end-start;
        memory_map[n].type = mmap->type;

        BMM_PRINT("Memory map[%u] - [%p - %p] <%s>\n", 
                n, 
                start,
                end,
                mem_region_types[memory_map[n].type]);

        if (mmap->type == MULTIBOOT_MEMORY_AVAILABLE) {
            mm_info->usable_ram += mmap->len;
        }

        if (end > (mm_info->last_pfn << PAGE_SHIFT)) {
            mm_info->last_pfn = end >> PAGE_SHIFT;
        }

        mm_info->total_mem += end-start;

        ++n;
        ++mm_info->num_regions;
    }
#endif
}

