//#include <arch/pisces/pisces_types.h>
#include <arch/pisces/pisces_boot_params.h>
#include <arch/pisces/pisces_xbuf.h>
#include <arch/pisces/pisces.h>
#include <nautilus/nautilus.h>
#include <nautilus/paging.h>

#include <nautilus/math.h>
//#include <arch/pisces/pisces_file.h>

#include <nautilus/shell.h>
extern char* pisces_buf;
extern nk_wait_queue_t pisces_waitq;

#include <dev/e1000e_pci.h>
#include <dev/pci.h>

#ifndef NAUT_CONFIG_DEBUG_PISCES_CTRL
#undef DEBUG_PRINT
#define DEBUG_PRINT(fmt, args...) 
#endif

#define DEBUG(fmt, args...) DEBUG_PRINT("PISCES_CTRL: " fmt, ##args)
#define INFO(fmt, args...)  INFO_PRINT("PISCES_CTRL: " fmt, ##args)
#define WARN(fmt, args...)  WARN_PRINT("PISCES_CTRL: " fmt, ##args)
#define ERROR(fmt, args...) ERROR_PRINT("PISCES_CTRL: " fmt, ##args)

static struct pisces_xbuf_desc   * xbuf_desc = NULL;

static u8      * cmd_data   = NULL;
static u32       cmd_len    = 0;

static void 
cmd_handler(u8    * data, 
	    u32     data_len, 
	    void  * priv_data)
{	
    int ret = 0;
	cmd_data = data;
	cmd_len  = data_len;
	__asm__ __volatile__("":::"memory");

    struct pisces_cmd * cmd = (struct pisces_cmd*)data; 
    struct pisces_resp resp;
    u32 resp_len = sizeof(struct pisces_resp);
    memset(&resp, 0, resp_len); 

    switch(cmd->cmd) {
        case ENCLAVE_CMD_NAUTILUS_CMD: {
            struct cmd_nautilus_cmd *nautilus_cmd = (struct cmd_nautilus_cmd *)cmd;
            printk("Receive cmd %s!\n", nautilus_cmd->cmd);
            //break;
            /* zjp
             * nautilus-shell will keep waiting until xbuf receives this cmd from pisces 
             * TODO: this is just a test. Need a better design.
             */
            if(pisces_buf == NULL) {
                printk("Error: pisces_buf is not initialized when issuing cmd %s !\n", nautilus_cmd->cmd);
                break;
            }
            strncpy(pisces_buf, nautilus_cmd->cmd, SHELL_MAX_CMD);
            // wakeup nautilus' shell
            nk_wait_queue_wake_all_extended(&(pisces_waitq), 0);
            break;
        }
        case ENCLAVE_CMD_ADD_MEM: {
            struct cmd_mem_add *mem_cmd = (struct cmd_mem_add*)cmd;
            printk("Reiceve ADD_MEM addr %lx size %lx\n", mem_cmd->phys_addr, mem_cmd->size);
            // zjp: TODO this is just a test that adds to domian 0. Need to support any domain
            struct nk_locality_info * numa_info = &(nk_get_nautilus_info()->sys.locality_info);
            ret = kmem_add_mempool(numa_info->domains[0]->zone, mem_cmd->phys_addr, mem_cmd->size);
            if(ret != 0) {
                printk("Failed to ADD_MEM addr %lx size %lx\n", mem_cmd->phys_addr, mem_cmd->size);
            }
#if 1 // test codes to verify the buddy states 
            zone_mem_show(numa_info->domains[0]->zone);
            char* ptr_prev_1 = kmem_malloc( 64*1024*1024);
            char* ptr_prev_2 = kmem_malloc( 32*1024*1024);
            char* ptr_1 = kmem_malloc( 32*1024*1024);
            char* ptr_2 = kmem_malloc( 64*1024*1024);
            char* ptr_3 = kmem_malloc( 32*1024*1024);
            zone_mem_show(numa_info->domains[0]->zone);

            ret = kmem_remove_mempool(mem_cmd->phys_addr, mem_cmd->size);
            if(ret != 0) {
                printk("expected: Failed to REMOVE_MEM addr %lx size %lx\n", mem_cmd->phys_addr, mem_cmd->size);
            }
            kmem_free(ptr_1);
            printk("freed 32MB \n");
            zone_mem_show(numa_info->domains[0]->zone);
            kmem_free(ptr_2);
            printk("freed 64MB \n");
            zone_mem_show(numa_info->domains[0]->zone);
            kmem_free(ptr_3);
            printk("freed 32MB \n");
            zone_mem_show(numa_info->domains[0]->zone);
            kmem_free(ptr_prev_2);
            kmem_free(ptr_prev_1);
            printk("freed 64MB pool\n");
            ret = kmem_remove_mempool(mem_cmd->phys_addr, mem_cmd->size);
            if(ret != 0) {
                printk("expected: Failed to REMOVE_MEM addr %lx size %lx\n", mem_cmd->phys_addr, mem_cmd->size);
            }
            zone_mem_show(numa_info->domains[0]->zone);

#endif
            break;
        }
        case ENCLAVE_CMD_REMOVE_MEM: {
            struct cmd_mem_add *mem_cmd = (struct cmd_mem_add*)cmd;
            printk("Reiceve REMOVE_MEM addr %lx size %lx\n", mem_cmd->phys_addr, mem_cmd->size);
            // zjp: TODO this is just a test that adds to domian 0. Need to support any domain
            ret = kmem_remove_mempool(mem_cmd->phys_addr, mem_cmd->size);
            if(ret != 0) {
                printk("Failed to REMOVE_MEM addr %lx size %lx\n", mem_cmd->phys_addr, mem_cmd->size);
            }
            break;
        }
        case ENCLAVE_CMD_ADD_CPU: {
#if 0
            extern struct cmd_cpu_add cpu_cmd;
            memcpy(&cpu_cmd, cmd, sizeof(struct cmd_cpu_add));
            break;
#else
            struct cmd_cpu_add *cpu_cmd = (struct cmd_cpu_add*)cmd;
            int cpu;
            ret = add_cpu(cpu_cmd->apic_id, &cpu);
            if(ret != 0) {
                printk("Failed to ADD_MEM phys_cpu_id %lu apic_id %lu\n", cpu_cmd->phys_cpu_id, cpu_cmd->apic_id); 
                break;
            }
            ret = smp_bringup_cpu(cpu);
            if(ret != 0) {
                printk("Failed to bringup cpu %d apic_id %lu\n", cpu, cpu_cmd->apic_id); 
                break;
            }

            //printk("Successfully added and booted cpu %d phys_cpu_id %lu apic_id %lu\n", cpu,cpu_cmd->phys_cpu_id, cpu_cmd->apic_id); 
            //apic_ipi(nk_get_nautilus_info()->sys.cpus[0]->apic, nk_get_nautilus_info()->sys.cpus[cpu]->apic->id, 13);
            break;
#endif
        }
        case ENCLAVE_CMD_ADD_V3_PCI: {
            struct cmd_add_pci_dev pci_cmd;
            memcpy(&pci_cmd, cmd, sizeof(struct cmd_add_pci_dev));
            struct pisces_pci_spec *dev_spec = &pci_cmd.spec;
            printk("Add_PCI name %s bus %u dev %u func %u\n", dev_spec->name, dev_spec->bus, dev_spec->dev, dev_spec->func); 
            // TODO Note that currently nautilus directly scan and probe. Thus the dev has already been registered
            ret = pisces_pci_add(dev_spec->bus, dev_spec->dev, dev_spec->func);
            if(ret != 0)
                printk("Falied to Add_PCI name %s bus %u dev %u func %u\n", dev_spec->name, dev_spec->bus, dev_spec->dev, dev_spec->func);
            uint8_t vec;
            ret = pisces_e1000e_pci_init(dev_spec->bus, dev_spec->dev, dev_spec->func, &vec);
            if(ret != 0)
                printk("Falied to init PCI name %s bus %u dev %u func %u\n", dev_spec->name, dev_spec->bus, dev_spec->dev, dev_spec->func);
            else
                printk("Successfully init PCI name %s bus %u dev %u func %u vec %u\n", dev_spec->name, dev_spec->bus, dev_spec->dev, dev_spec->func, vec);
                // use MSI now
            //resp.status = vec;
            break;
        }
        default:
            break;
    }

    if(ret != 0)
        resp.status = -1;
    __asm__ __volatile__ ("":::"memory"); 
    pisces_xbuf_complete(xbuf_desc, (u8*)&resp, resp_len); 
    __asm__ __volatile__ ("":::"memory");
	return;
}

int 
pisces_ctrl_init(void)
{
	xbuf_desc = pisces_xbuf_server_init((uintptr_t)pa_to_va(pisces_boot_params->control_buf_addr), 
					    pisces_boot_params->control_buf_size, 
					    cmd_handler, NULL, -1, 0);		 

	if (xbuf_desc == NULL) {
		printk("Could not initialize cmd/ctrl xbuf channel\n");
		return -1;
	}

	return 0;
}
