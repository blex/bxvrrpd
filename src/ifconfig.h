#ifndef XTVRRPD_IFCONFIG_H
#define XTVRRPD_IFCONFIG_H
#include <stdint.h>

int get_hwaddr(const char *ifname, char *hwaddr);
int get_ipaddr(const char *ifname, uint32_t *ipaddr);

int set_hwaddr(const char *ifname, const char *hwaddr, size_t addrlen);

int set_promiscuous(const char *ifname);
int unset_promiscuous(const char *ifname);

#endif //XTVRRPD_IFCONFIG_H

