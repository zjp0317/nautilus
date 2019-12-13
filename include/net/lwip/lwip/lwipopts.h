#ifndef LWIPOPTS_H
#define LWIPOPTS_H

// zjp
#define NAUT_CONFIG_PISCES_SHORT_LWIP 1
#define LWIP_SO_LINGER                1  
#define SO_REUSE 1
#define TCP_MSS         1460
#define TCP_WND         0x600000 // default in ubuntu tcp_rmem is 4096  87380   6291456 
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                   7 // 0xffff << e > TCP_WND 
#define MEMP_MEM_MALLOC 1
//#define PBUF_POOL_SIZE                  16 // * BUFSIZE(~TCP_MSS) should > TCP_WND
#define MEMP_NUM_NETCONN                5
#define MEMP_NUM_TCP_PCB                5
#define MEMP_NUM_TCP_PCB_LISTEN         8
#define TCP_SND_BUF                     (64 * TCP_MSS)
#define TCP_SNDLOWAT                    (TCP_SND_BUF / 2)
//#define MEMP_NUM_TCP_SEG                256
#define MEM_ALIGNMENT                   4
//#define CHECKSUM_GEN_TCP                0
//#define CHECKSUM_CHECK_TCP                0
//#define CHECKSUM_GEN_IP                 0
//#define CHECKSUM_CHECK_IP                 0

// We don't need v6
#define LWIP_IPV6 0 // zjp 0

// We use nautilus system, so have threads to run in OS mode
#define NO_SYS 0

// We want the embedded loopback interface
#define LWIP_HAVE_LOOPIF 1

// We want it to use NK's malloc
// not that MEM_USE_POOLS/etc is off, so all allocation goes via NK
// we're not concerned about speed yet
#define MEM_LIBC_MALLOC 1 // zjp 1

// zjp  configs that may matter
#if 0
//#define MEM_USE_POOLS                   1
//#define MEM_USE_POOLS_TRY_BIGGER_POOL   1
#define MEMP_NUM_NETCONN                4
#define MEMP_NUM_TCP_PCB                5
#define MEMP_NUM_TCP_PCB_LISTEN         8
#define MEMP_NUM_TCP_SEG                16
#define MEMP_NUM_REASSDATA              5
#define MEMP_NUM_TCPIP_MSG_API          8
#define MEMP_NUM_TCPIP_MSG_INPKT        8
//#define PBUF_POOL_SIZE                  16
#endif

// ?
//#define LWIP_DBG_TYPES_ON 1

// New after here

// new - do core locking
#define LWIP_TCPIP_CORE_LOCKING 1

// put the tcpip thread on a large stack regardless of
// compile-time config of NK
#define TCPIP_THREAD_STACKSIZE (2*1024*1024)
// nice big mbox - we have plenty of memory
#define TCPIP_MBOX_SIZE        256 // zjp 128

// Make everything else nice and chunky
#define DEFAULT_THREAD_STACKSIZE (2*1024*1024)
#define DEFAULT_RAW_RECVMBOX_SIZE 256 // zjp 128
#define DEFAULT_UDP_RECVMBOX_SIZE 256 // zjp 128 
#define DEFAULT_TCP_RECVMBOX_SIZE 256 // zjp 128
#define DEFAULT_ACCEPTMBOX_SIZE   256 // zjp 128
#endif
