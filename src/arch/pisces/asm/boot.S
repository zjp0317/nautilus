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

    /* this computes the delta from where I'm loaded
     * and where I expect to be loaded
     */
    leaq _loadStart(%rip), %rbp
    subq $_loadStart, %rbp

    

    /* setup the identity mapped pts */

    /* PML4[0] -> PDPT */
    movq $pdpt, %rax
    addq %rbp, %rax // load offset adjustment
    orq $0x3, %rax       /* entry is present, rw */
    movq $pml4, %rbx
    addq %rbp, %rbx
    movq %rax, (%rbx)

    // PDPT[0] -> PDT 
    movq $pd, %rax
    addq %rbp, %rax // load offset adjustment
    orq $0x3, %rax
    movq $pdpt, %rbx
    addq %rbp, %rbx
    movq %rax, (%rbx)

    // Identity map the first GB
    movq $512, %rcx
    movq $pd, %rdx
    addq %rbp, %rdx // load offset adjustment
    movq $0x83, %rax // set PS bit also (PDE -> 2MB page)
.write_pde:
    movq %rax, (%rdx)
    addq $0x200000, %rax
    addq $0x8, %rdx
    loop .write_pde

    // Fix up the kernel text + data (2nd + 3rd pd entry)
    movq $pd, %rdx
    addq %rbp, %rdx // load offset adjustment
    movq $0x83, %rax
    addq %rbp, %rax
    addq $0x200000, %rax
    movq %rax, 8(%rdx)
    addq $0x200000, %rax
    movq %rax, 16(%rdx)
    

    /* put pml4 address in cr3 */
    movq $pml4, %rax
    addq %rbp, %rax // load offset adjustment
    movq %rax, %cr3

    movq %rsi, %rbx
    shl $12, %rbx
    addq $64, %rbx
    movq $hello_str, %rcx

    movb (%rcx), %dl
    movb %dl, (%rbx)
    movb 1(%rcx), %dl
    movb %dl, 1(%rbx)
    movb 2(%rcx), %dl
    movb %dl, 2(%rbx)
    movb 3(%rcx), %dl
    movb %dl, 3(%rbx)
    movb 4(%rcx), %dl
    movb %dl, 4(%rbx)
    movb 5(%rcx), %dl
    movb %dl, 5(%rbx)
    movb 6(%rcx), %dl
    movb %dl, 6(%rbx)
    movb 7(%rcx), %dl
    movb %dl, 7(%rbx)
    movq %rbp, 8(%rbx)

#if 0
    test:
        hlt
        jmp test


    /* enable PAE */
    movq %cr4, %rax
    orq $(1<<5), %rax
    movq %rax, %cr4


    /* enable lme bit in MSR */
    movl $0xc0000080, %ecx
    rdmsr
    orl $(1<<8), %eax
    wrmsr

    /* paging enable */
    movq %cr0, %rax
    or $(1<<31), %eax

    /* USING VIRTUAL ADDRESSES NOW */

    /* make sure we're in "normal cache mode" */
    movq $~(3<<29), %rbx
    andq %rbx, %rax

    movq %rax, %cr0

    /* done setting up paging */
    movq $0x10, %rax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss

#endif

    movq $boot_stack_end, %rsp

    // clear EFLAGS
    pushq $0
    popfq

    // N -> P
    movb $0x50, (%rbx)

    /* real mode crap is in rsi still */
    movq $pisces_go, %rax
    movq %rsi, %rdi
    movq $0, %rbp
    callq *%rax

    /* shouldn't get here */
    cli
    jmp .


hello_str:
.asciz "NAUT!  "
