#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <netpacket/packet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "vrrp_common.h"
#include "arp.h"
#include "ifconfig.h"
#include "iproute.h"

//extern struct vrrp_app app;
#define IPADDR_STR_LEN 16 // 255.255.255.255'\0'
#define HWADDR_STR_LEN 18 // 00-00-00-00-00-00'\0'

//! @brief Return a ip address string by given ipaddr value
//! @param[in] ipaddr The given ipaddr value (in host byteorder)
static inline char* ipaddr_to_str(const uint32_t ipaddr)
{
	static char ip_buf[IPADDR_STR_LEN] = {0};
	memset(ip_buf, 0, IPADDR_STR_LEN);
	sprintf(ip_buf, "%u.%u.%u.%u", 
		(ipaddr >> 24 )& 0xFF, (ipaddr >> 16) & 0xFF, 
		(ipaddr >> 8) & 0xFF, ipaddr & 0xFF);
	return ip_buf;
}

//! @brief Return a mac address string by given hw address data
//! @param[in] hwaddr Pointer to hw address data
static inline char* hwaddr_to_str(const unsigned char *hwaddr)
{
	static char hw_buf[HWADDR_STR_LEN] = {0};
	memset(hw_buf, 0, HWADDR_STR_LEN);
	sprintf(hw_buf, "%02x:%02x:%02x:%02x:%02x:%02x", 
		hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], 
		hwaddr[4], hwaddr[5]);
	return hw_buf;
}


//! @brief Get current time in usecs
//! @return The current usec time
uint32_t now_usec(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return USEC_FROM_SEC(tv.tv_sec) + tv.tv_usec;
}

//! @brief See if the given file already exists
//! @param[in] path Full path to the given file 
//! @retval 0 Not exist
//! @retval 1 Exist
static inline int pidfile_exist(const char *path)
{
	FILE *fp = fopen(path, "r");
        if (!fp) return 0;
	fclose(fp);
	return 1;
}

//! @brief Write down PID by the given file path
//! @param[in] path The given file path
//! @retval 0 Success
//! @retval -1 Failure
static inline int pidfile_write(const char *path)
{
	FILE *fp = fopen(path, "w");
	if (!fp) {
		VRRPLOG("write pidfile:%s", strerror(errno));
		return -1;
	}
	fprintf(fp, "%d\n", getpid());
        fclose(fp);
        return 0;
}

//! @brief Check if the PID file exists
//! @param[out] buff Where to store the PID file path
//! @param[in] buffsiz The size of |buff|
//! @param[in] tag Used to generate the PID file name
int check_pidfile(char *buff, size_t buffsiz, const char *tag)
{
	snprintf(buff, buffsiz, "%s/bxvrrpd_%s.pid", PIDFILE_DIR, tag);
	if (pidfile_exist(buff)) {
		VRRPLOG("pidfile %s exists", buff);
		return -1;
	}
	pidfile_write(buff);
	return 0;
}

//! @brief Open socket and join the multicast group 224.0.0.18
//! @return socket fd for success or -1 for failure
static int open_adver_socket(uint32_t if_ipv4)
{
	int sock = socket(PF_INET, SOCK_RAW, IPPROTO_VRRP);
	if (sock < 0) {
		VRRPLOG("open adver socket:%s\n", strerror(errno));
		return -1;
	}

	struct ip_mreq req;
	memset(&req, 0, sizeof(req));
	req.imr_multiaddr.s_addr = VRRP_MCAST_ADDR_NW;
	req.imr_interface.s_addr = htonl(if_ipv4);
	if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
		(char *)&req, sizeof(req)) < 0) 
	{
		VRRPLOG("set option IP_MEMBERSHIP:%s\n", strerror(errno));
		goto err;
	}
	char loopch = 0;
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, 
		&loopch, sizeof(loopch)) < 0) 
	{
		VRRPLOG("set option IP_MULTICAST_LOOP:%s\n", strerror(errno));
		goto err;
	}

	struct in_addr local_if;	
	memset(&local_if, 0, sizeof(local_if));
	local_if.s_addr = htonl(if_ipv4);
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, 
		(char*)&local_if, sizeof(local_if)) < 0) 
	{
		VRRPLOG("set option IP_MULTICAST_IF:%s\n", strerror(errno));
		goto err;
	}

	unsigned char mcast_ttl = 255;
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, 
		&mcast_ttl, sizeof(mcast_ttl)) < 0)
	{
		VRRPLOG("set option IP_MULTICAST_TTL:%s\n", strerror(errno));
		goto err;
	} 

	return sock;
err:
	close(sock);
	return -1;
}

//! @brief Get the usec delta to see if the timer is expired
//! @param[in] value Given timer value
//! @param[in] upbound The upbound of delta
//! @note If delta is greater than |upbound|, it means someone had put system 
//!	clock back.
//! @retval 0 No
//! @retval 1 Yes
int vrrp_timer_fires(uint32_t value, uint32_t upbound)
{
	int delta = value - now_usec();
	if (0 > delta || delta > upbound) return 1;
	return 0;
}

//! @brief Free resources when shutdown
//! @param[in] sock The socket number
//! @param[in] pidfile PID file name
int vrrp_shutdown(int sock, const char *pidfile)
{
	close(sock);
	unlink(pidfile);
	VRRPLOG("Shutdown now\n");
	return 0;
}

//! Dump the given vrrp_app structure
//! param[in] app The given vrrp_app structure
int vrrp_dump(struct vrrp_app *app)
{
	// Check options
	printf("> Interface      : %s (idx%d, %s, %s)\n"
		"> VRID           : %d\n"
		"> priority       : %d\n"
		"> preempt_mode   : %d\n"
		"> accept_mode    : %d (v3 only)\n"
		"> adver usec     : %u\n"
		"> mstr adver usec: %u (v3 only)\n"
		"> skew usec      : %u\n"
		"> mstr down usec : %u\n", 
		app->if_name, 
		app->if_idx, 
		ipaddr_to_str(app->if_ipv4), 
		hwaddr_to_str((unsigned char *)app->if_mac),
		app->vrid, 
		app->priority, 
		app->preempt_mode, 
		app->accept_mode, 
		app->adver_usec, 
		app->mstr_adver_usec, 
		app->skew_usec, 
		app->mstr_down_usec); 
	for (int i = 0; i < app->num_of_vaddr; i++) {
		printf("%02d) %s\n",  i + 1, ipaddr_to_str(app->vaddrs[i]));
	}
	printf("***\n");
	return 0;
}

//! @brief Initialize VRRP PID file and socket
int vrrp_initialize(struct vrrp_app *app)
{
	// PID file
	if (check_pidfile(app->pidfile, PIDFILE_LEN, app->if_name) < 0) {
		return -1;
	}

	// Socket
	if ((app->sock = open_adver_socket(app->if_ipv4)) < 0) return -1;

	return 0;
}

extern struct vrrp_app app;
//! @brief Sniffing ARP on assgined interface
void* vrrp_arp_sniffer(void *arg)
{
	VRRPLOG("start sniffing\n");

	int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	assert(fd > 0);

	struct sockaddr_ll recv;
	memset(&recv, 0, sizeof(recv));
	recv.sll_hatype = ARPOP_REQUEST;
	recv.sll_pkttype = PACKET_OTHERHOST;

	struct sockaddr_ll send;
	memset(&send, 0, sizeof(send));
	send.sll_family = AF_PACKET;
	send.sll_ifindex = app.if_idx;
	send.sll_halen = 6;
	memcpy(send.sll_addr, app.vmac, 6);

	socklen_t recvlen;
	struct arppkt buff;
	struct arppkt reply = {
		.ethh = {
			.h_dest = {0},
			.h_source = {0},
			.h_proto = htons(ETH_P_ARP),
			},
		.arph = {
			.ar_hrd = htons(ARPHRD_ETHER),
			.ar_pro = htons(ETH_P_IP),
			.ar_hln = 6,
			.ar_pln = 4,
			.ar_op = htons(ARPOP_REPLY),
			},
		.sha = {0},
		.sip = {0},
		.dha = {0},
		.dip = {0},
	};
	while (1) {
		if (VRRP_MASTER != app.state) continue;
		memset(&buff, 0, sizeof(buff));
		if (recvfrom(fd, &buff, sizeof(buff), 0, 
			(struct sockaddr *)&recv, &recvlen) < 0) 
		{
			VRRPLOG("recv arp:%s", strerror(errno));
			close(fd);
			break;
		}

		// Inspect
		if (htons(ARPOP_REQUEST) != buff.arph.ar_op) continue;
		for (int i = 0; i < app.num_of_vaddr; ++i) {
			//uint32_t dip = *(uint32_t *)(buff.dip);
			uint32_t dip = *(buff.dip);
			if (app.if_ipv4 == dip) {
				// Kernel will handle it
				continue;
			}

			if (dip != htonl(app.vaddrs[i])) continue;

			// Reply it
			memcpy(reply.ethh.h_dest, buff.sha, 6);
			memcpy(reply.ethh.h_source, app.vmac, 6);
			memcpy(reply.sha, app.vmac, 6);
			memcpy(reply.sip, buff.dip, 4);
			memcpy(reply.dha, buff.sha, 6);
			memcpy(reply.dip, buff.sip, 4);
			if (sendto(fd, &reply, sizeof(reply), 0, 
				(struct sockaddr *)&send, sizeof(send)) < 0) 
			{
				VRRPLOG("reply arp:%s\n", strerror(errno));
			}
		}
	}
	pthread_exit(0);
}

//! @brief Set interface MAC and promiscuous
//! @param[in] ifname Which interface to set
//! @param[in] mac MAC to set
//! @param[in] flag For VRRP_MASTER ot VRRP_BACKUP
int set_iface_hw(const char *ifname, const char *mac, enum vrrp_state flag)
{
	struct rt_entry rt_table;
	memset(&rt_table, 0, sizeof(struct rt_entry));
	if (!rt_fetch(&rt_table)) VRRPLOG("Can't parse routing table\n");

	if (VRRP_MASTER == flag) {
		set_hwaddr(ifname, mac, 6);
		set_promiscuous(ifname);
	} else {
		assert(VRRP_BACKUP == flag);
		unset_promiscuous(ifname);
		set_hwaddr(ifname, mac, 6);
	}

	rt_restore(rt_table.next, ifname);
	return 0;
}

//! @brief Handling checksum
//! @param[in] addr The word to add to accumulator
//! @param[in] len  Indicate the length of |addr|
//! @param[in] csum The accumulator
//! @return The checksum value
unsigned short in_cksum(unsigned short *addr, int len, unsigned short csum)
{
	register int nleft = len;
	const unsigned short *w = addr;
	register unsigned short answer;
	register int sum = csum;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	// mop up an odd byte, if necessary
	if (nleft == 1) sum += htons(*(unsigned char *)w << 8);
	
	sum = (sum >> 16) + (sum & 0xffff);	// add hi 16 to low 16
	sum += (sum >> 16); 			// add carry
	answer = ~sum;				// truncate to 16 bits
	return (answer);
}

