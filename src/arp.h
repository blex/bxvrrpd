#ifndef XTVRRPD_GARP_H
#define XTVRRPD_GARP_H
#include <net/if_arp.h>
#include <net/ethernet.h>

#define BROADCAST_MAC "\xFF\xFF\xFF\xFF\xFF\xFF"

/**
 * @brief A structure to implement ARP packet from layer 2.
 */
struct arppkt {
	struct ethhdr ethh;
	struct arphdr arph;
	char sha[6];
	char sip[4];
	char dha[6];
	char dip[4];
};

int send_garp_request(int ifidx, const char *mac, uint32_t nw_ipaddr);

#endif //XTVRRPD_GARP_H
