#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netpacket/packet.h>

#include "arp.h"

//! @brief Send gratuituous ARP requset
//! @param[in] ifidx The index of interface to send packet
//! @param[in] mac The src hwaddr
//! @param[in] nw_ipaddr The src/dst ipaddr (in netwot byteorder)
//! @retval 0 Success
//! @retval -1 Failure
int send_garp_request(int ifidx, const char *mac, uint32_t nw_ipaddr)
{
	assert(ifidx > 0);

	int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (fd < 0) return -1;

	struct sockaddr_ll ll;
	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifidx;
	ll.sll_halen = 6;
	memcpy(ll.sll_addr, BROADCAST_MAC, 6);

	int bcast = 1;
	int ret = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &bcast, 
		sizeof(bcast));
	if (ret < 0) goto err;

	struct arppkt pkt;
	memcpy(pkt.ethh.h_dest, BROADCAST_MAC, 6);
	memcpy(pkt.ethh.h_source, mac, 6);
	pkt.ethh.h_proto = htons(ETH_P_ARP);
	pkt.arph.ar_hrd=htons(ARPHRD_ETHER);
	pkt.arph.ar_pro=htons(ETH_P_IP);
	pkt.arph.ar_hln=6;
        pkt.arph.ar_pln=4;
        pkt.arph.ar_op=htons(ARPOP_REQUEST);
	memcpy(pkt.sha, mac, 6);
	//*((uint32_t *)pkt.sip) = nw_ipaddr;
	*(pkt.sip) = nw_ipaddr;
	memcpy(pkt.dha, mac, 6);
	//*((uint32_t *)pkt.dip) = nw_ipaddr;
	*(pkt.dip) = nw_ipaddr;

	ret = sendto(fd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&ll, 
		sizeof(ll));
	if (ret < 0) goto err;

	close(fd);
	return 0;
err:
	close(fd);
	return -1;
}

