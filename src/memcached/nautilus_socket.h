#ifndef __NAUT_SOCKET_H__
#define __NAUT_SOCKET_H__

#ifdef NAUT_CONFIG_NET_LWIP
#include <net/lwip/lwip.h>

typedef uint32_t socklen_t;

#else
#error Must eanble lwip for socket usage
#endif

#endif
