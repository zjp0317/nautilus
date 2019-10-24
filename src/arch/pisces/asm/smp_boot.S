#include <asm/lowlevel.h>
#include <nautilus/smp.h>
#include <nautilus/gdt.h>
/*
 * If Kitten is to be trusted, we are in 64-bit mode here
 * with Cs.L = 1, CS.D = 1, and someone has already loaded
 * an identity mapped pt. %esi holds pointer to linux real_mode_data
 * struct. 
 */

.code64
.align 8
.section .text
ENTRY(pisces_boot_ap)
    /*
     * esi holds pisces boot pmem address 
     */
    //movq    $PISCES_AP_INFO_AREA, %rdx
    movq    %rsi, %rdx
    shl     $PISCES_PAGE_SHIFT, %rdx
    addq    $PISCES_AP_INFO_AREA, %rdx

    /* update cr3 */
    movq    74(%rdx), %rax

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

    /* make sure we're in "normal cache mode" */
    movq    $~(3<<29), %rbx
    andq    %rbx, %rax
    movq    %rax, %cr0

    /* now our long mode GDT */
    movl    $gdtr64, %eax
    lgdt    (%eax)

    /* set all other selectors */
    movq    $0x10, %rax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss

    //movw    %ax, %fs
    //movw    %ax, %gs

    /* update stack */
    //movq    $PISCES_AP_INFO_AREA, %rdx 
    movq    %rsi, %rdx
    shl     $PISCES_PAGE_SHIFT, %rdx
    addq    $PISCES_AP_INFO_AREA, %rdx

    movq    (%rdx), %rbx
    addq    $0x1000, %rbx
    movq    %rbx, %rsp

    // clear EFLAGS
    pushq   $0
    popfq


    // Fetch the desired C entry point and argument from the information
    movq    82(%rdx), %rdi

#if 0
    movq    90(%rdx), %rsi
    // Enter the C code with our argument
    callq   *%rsi

    /* shouldn't get here */
    cli
    jmp .

#else

    movq    initial_code(%rip), %rax
    pushq   $0      # fake return address to stop unwinder
    pushq   $KERNEL_CS    # set correct cs
    pushq   %rax        # target address in negative space
    lretq

    /* shouldn't get here */
    cli
    jmp .

.align 8
GLOBAL(initial_code)
    .quad   smp_ap_entry
#endif
