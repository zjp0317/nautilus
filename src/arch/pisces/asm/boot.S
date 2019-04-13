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
 * Copyright (c) 2017, Kyle C. Hale <khale@cs.iit.edu>
 * Copyright (c) 2017, The V3VEE Project  <http://www.v3vee.org> 
 *                     The Hobbes Project <http://xstack.sandia.gov/hobbes>
 * All rights reserved.
 *
 * Author: Kyle C. Hale <khale@cs.iit.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "LICENSE.txt".
 */

#include <asm/lowlevel.h>
#include <nautilus/smp.h>
#include <nautilus/gdt.h>

/* 
 * This is the stage 2 pisces bootloader for Nautilus. We land here
 * in 64-bit mode with a pointer to pisces' boot params struct
 * sitting in esi. We basically need to finish the PT setup and
 * transfer to C code, where we can do the translation from 
 * pisces_boot_params to multiboot (which will allow us to reuse
 * existing multiboot code
 *
 */

/*
 * If Kitten is to be trusted, we are in 64-bit mode here
 * with Cs.L = 1, CS.D = 1, and someone has already loaded
 * an identity mapped pt. %esi holds pointer to linux real_mode_data
 * struct. 
 *
 * We have to do some fixup since we're likely to be loaded at an
 * address that is different than what we're compiled for (we're
 * not compiling nautilus as a relocatable kernel)
 */

.code64
.align 8
.section .boot
GLOBAL(pisces_boot_start)
    /*
     * We need the following 3 infomation to do a safe mapping:
     * 1. pisces_boot_params->kernel_addr  (offset from pisces_boot_params: 1176 bytes)
     * 2. pisces_boot_params->kernel_size  (offset 1184 bytes) 
     * 3. pisces_boot_params->base_mem_paddr  (offset 1272 bytes)
     *
     * Ident map:
     *   [base_mem_paddr, base_mem_paddr + 128MB)
     * Offset map:
     *   [&_loadStart, &_loadStart + kernel_size] --> [kernel_addr, kernel_addr + kernel_size)
     */
     
    /* 
     * Get the address of pisces_boot_params to rbp.
     * It's also equals to pisces_boot_params->base_mem_paddr.
     * It's 128M-aligned.
     */
    movq    %rsi, %rbp 
    shl     $12, %rbp

    /* Get pisces_boot_params->kernel_addr to r10 */
    movq    1176(%rbp), %r10

    /* Get pisces_boot_params->kernel_size to r11 */
    movq    1184(%rbp), %r11

    /* Get the offset ( kernel_addr - &_loadStart ) to r12 */ 
    movq    %r10, %r12
    subq    $_loadStart, %r12

    /*
     * ident map
     */

    /* Calculate ( base_mem_paddr / 1GB ) to r13 */ 
    movq    %rbp, %r13
    shr     $30, %r13

    /* decide whether need extra pdpt and/or extra pd */
    cmp     $512, %r13  // need both extra pdpt and extra pd, if r13 >= 512
    jae     .both_need_extra
    movq    $pdpt, %rax
    cmp     $0, %r13    // need extra pd, if r13 > 0
    ja      .need_extra_pd
    movq    $pd, %rbx

.finish_decision:
    addq    %r12, %rax  // load offset adjustment
    addq    %r12, %rbx  // load offset adjustment
    movq    $pml4, %rdx
    addq    %r12, %rdx  // load offset adjustment
    jmp     .fill_page_table

.both_need_extra:
    movq    $pdpt_extra, %rax
.need_extra_pd:
    movq    $pd_extra, %rbx
    jmp     .finish_decision
    
.fill_page_table:
    /* 
     * do ident map
     *
     * RAX : paddr of actual PDPT for ident map
     * RBX : paddr of actual PD for ident map
     * RDX : paddr of PML4 for both ident map and offset-map
     * RBP : base_mem_paddr
     * r10 : kernel_addr
     * r11 : kernel_size
     * r12 : offset = ( kernel_addr - &_loadStart ) 
     * r13 : ( base_mem_paddr / 1GB )
     * r14 : use it to hold the value to be filled
     */

    /* fill pml4[X] with pdpt, index X = (r13 / 512), store in rcx */
    movq    %r13, %rcx
    shr     $9, %rcx             // X = (r13 / 512)
    movq    %rax, %r14          // pdpt 
    orq     $0x3, %r14          // entry is present, rw
    movq    %r14, (%rdx,%rcx,8) // pml4[x] = pdpt_paddr | flags

    /* fill pdpt[X] with pd, index X = (r13 % 512), store in rcx */
    movq    %r13, %rcx
    andq    $0x1FF, %rcx        // X = (r13 % 512)
    movq    %rbx, %r14          // pd
    orq     $0x3, %r14          // entry is present, rw
    movq    %r14, (%rax,%rcx,8) // pdpt[X] = pd_paddr | flags

    /* fill pd,
     * starting from pd[X], and only handle SIZE = 128MB. 
     * Note that base_mem_paddr is 128M-aligned:
     *
     *  X = (base_mem_paddr / 2M) % 512;
     *  base_addr = base_mem_paddr | flags; 
     *  for(i = 64; i > 0; i--) {
     *      pd[X++] = base_addr;
     *      base_addr += 2MB;
     *  }
     */

    // re-use r13 to store the index X 
    movq    %rbp, %r13
    shr     $21, %r13
    andq    $0x1FF, %r13    // X = (base_mem_paddr / 2M) % 512

    movq    %rbp, %r14
    orq     $0x83, %r14     // base_addr =  base_mem_paddr | flags

    movq    $64, %rcx       // 64 iterations
.write_pde:
    movq    %r14, (%rbx,%r13,8)     // pd[X] = base_addr
    addq    $1, %r13                // X++
    addq    $0x200000, %r14         // base_addr += 2MB
    loop    .write_pde

    /* Now, ident map is done, prepare for offset map */

    movq    $pdpt, %rax
    addq    %r12, %rax      // RAX: PDPT
    movq    $pd, %rbx
    addq    %r12, %rbx      // RBX: PD

    /*
     * do offset map
     *
     * RAX : paddr of PDPT for offset-map
     * RBX : paddr of PD for offset-map
     * RDX : paddr of PML4 
     * r10 : kernel_addr
     * r11 : kernel_size
     * r12 : offset = ( kernel_addr - &_loadStart ) 
     * r14 : use it to hold the value to be filled
     */

    /* fill pml4[0] with pdpt, may be redundant */
    movq    %rax, %r14
    orq     $0x3, %r14      // entry is present, rw
    movq    %r14, (%rdx)    // pml4[0] = pdpt_paddr | flags
    
    /* fill pdpt[0] with pd, may be redundant */
    movq    %rbx, %r14
    orq     $0x3, %r14      // entry is present, rw
    movq    %r14, (%rax)    // pbpt[0] = pdpt_paddr | flags

    /* fill pd,
     * Note that kernel_addr is 2M-aligned:
     *
     *  X = (&_loadStart / 2M);
     *  N = (&_loadStart + kernel_size) / 2M;
     *  base_addr = kernel_addr | flags; 
     *  while ( X <= N ) { 
     *      pd[X++] = base_addr;
     *      base_addr += 2MB;
     *  }
     */
    movq    $_loadStart, %r13
    shr     $21, %r13           // X = (&_loadStart / 2M)
    addq    $_loadStart, %r11   // re-use r11 to store N 
    shr     $21, %r11           // N = (&_loadStart + kernel_size) / 2M
    
    movq    %r10, %r14
    orq     $0x83, %r14         // base_addr = kernel_addr | flags;

    subq    %r13, %r11
    addq    $1, %r11
    movq    %r11, %rcx          // (N - X + 1) iterations
.offset_write_pde:
    movq    %r14, (%rbx,%r13,8)     // pd[X] = base_addr
    addq    $1, %r13                // X++
    addq    $0x200000, %r14         // base_addr += 2MB
    loop    .offset_write_pde

    /* put pml4 address in cr3 */
    movq    $pml4, %rax
    addq    %r12, %rax // load offset adjustment
    movq    %rax, %cr3

    /* enable PAE */
    movq    %cr4, %rax
    orq     $(1<<5), %rax
    movq    %rax, %cr4

    /* enable lme bit in MSR */
    movl    $0xc0000080, %ecx
    rdmsr
    orl     $(1<<8), %eax
    wrmsr

    /* paging enable */
    movq    %cr0, %rax
    or      $(1<<31), %eax

    /* USING VIRTUAL ADDRESSES NOW */

    /* make sure we're in "normal cache mode" */
    movq    $~(3<<29), %rbx
    andq    %rbx, %rax

    movq    %rax, %cr0

    /* now our long mode GDT */
    movl    $gdtr64, %eax
    lgdt    (%eax)

    /* done setting up paging */
    movq    $0x10, %rax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss

    movq    $boot_stack_end, %rsp

    // clear EFLAGS
    pushq   $0
    popfq

    /* real mode crap is in rsi still */
    movq    %rsi, %rdi
    movq    $main, %rax
    callq   *%rax

    /* shouldn't get here */
    cli
    jmp .
