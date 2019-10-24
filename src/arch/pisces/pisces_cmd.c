// Now just for test adding cpu

#include <arch/pisces/pisces_boot_params.h>
#include <arch/pisces/pisces_xbuf.h>
#include <arch/pisces/pisces.h>
#include <nautilus/nautilus.h>
#include <nautilus/paging.h>

#include <nautilus/math.h>

#include <nautilus/shell.h>

struct cmd_cpu_add cpu_cmd;

static int
handle_pisces (char * buf, void * priv)
{
    int ret,cpu;
    ret = add_cpu(cpu_cmd.apic_id, &cpu);
    if(ret != 0) {
        printk("Failed to ADD_MEM phys_cpu_id %lu apic_id %lu\n", cpu_cmd.phys_cpu_id, cpu_cmd.apic_id); 
        return 0;
    }
    ret = smp_bringup_cpu(cpu);
    if(ret != 0) {
        printk("Failed to bringup cpu %d apic_id %lu\n", cpu, cpu_cmd.apic_id); 
    }
    return 0;
}



static struct shell_cmd_impl pisces_impl = {
    .cmd      = "pisces",
    .help_str = "pisces cmd",
    .handler  = handle_pisces,
};
nk_register_shell_cmd(pisces_impl);
