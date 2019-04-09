//#include <arch/pisces/pisces_types.h>
#include <arch/pisces/pisces_boot_params.h>
#include <arch/pisces/pisces_xbuf.h>
#include <arch/pisces/pisces.h>
#include <nautilus/nautilus.h>
#include <nautilus/paging.h>

#include <nautilus/math.h>
//#include <arch/pisces/pisces_file.h>

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
	cmd_data = data;
	cmd_len  = data_len;
	__asm__ __volatile__("":::"memory");

    struct pisces_cmd * cmd = (struct pisces_cmd*)data; 
    switch(cmd->cmd) {
        case ENCLAVE_CMD_NAUTILUS_CMD: {
            struct cmd_nautilus_cmd *nautilus_cmd = (struct cmd_nautilus_cmd *)cmd;
            printk("Receive cmd %s!\n", nautilus_cmd->cmd);
            break;
        }
        case ENCLAVE_CMD_ADD_MEM: {
            struct cmd_mem_add *mem_cmd = (struct cmd_mem_add*)cmd;
            printk("Reiceve ADD_MEM addr %lx size %lx\n", mem_cmd->phys_addr, mem_cmd->size);
            break;
        }
        case ENCLAVE_CMD_ADD_CPU: {
            struct cmd_cpu_add *cpu_cmd = (struct cmd_cpu_add*)cmd;
            break;
        }
        default:
            break;
    }

    __asm__ __volatile__ ("":::"memory"); 
    pisces_xbuf_complete(xbuf_desc, data, data_len);
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
