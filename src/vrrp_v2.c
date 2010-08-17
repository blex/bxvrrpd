#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include "arp.h"
#include "vrrp_v2.h"
#include "ifconfig.h"

extern char *optarg;
extern int optind, opterr, optopt;

static int parse_args(int argc, char **argv);
static int state_machine(void);

struct vrrp_app app = {
	.daemonize = 		0,
	.pidfile =		{0},
	//
	.sock = 		-1,
	.vrid = 		-1,
	.vmac = 		"\x00\x00\x5E\x00\x01\x00",
	.state = 		VRRP_INIT,
	.preempt_mode = 	1,
	.accept_mode = 		0,
	.priority = 		VRRP_PRIO_DFT,
	.adver_usec = 		VRRP_ADVER_USEC_DFT,
	.mstr_adver_usec = 	VRRP_ADVER_USEC_DFT,
	.skew_usec = 		0,
	.mstr_down_usec = 	0,
	.adver_timer = 		0,
	.mstr_down_timer =	0,
	.num_of_vaddr =		0,
	.vaddrs = 		{0},
	.if_name = 		{0},
	.if_idx = 		0,
	.if_ipv4 = 		0,
	.if_mac = 		{0},
	//
	.parse_args = parse_args,
	.state_machine = state_machine,
};
volatile int evt_shutdown = 0;
static pthread_t sniff;

//! @brief Caculate the length of VRRP payload (including the variable parts)
//! @param[in] num_of_ip How many IP are included in
//! @return The number of bytes of VRRP payload
static inline unsigned long adver_len(int num_of_ip)
{
	return sizeof(struct vrrphdr_v2) + ((num_of_ip + 2)* sizeof(uint32_t));
}

//! @brief Send an advertisement packet
//! @param[in] prio The priority od this advertisement
static int send_adver(int prio)
{
	size_t vrrplen = adver_len(app.num_of_vaddr);
	size_t bufflen = vrrplen;
	char *buff = malloc(bufflen);
	struct vrrphdr_v2 *vrrp = (struct vrrphdr_v2 *)buff;
	uint32_t *vaddrs = (uint32_t *)(vrrp + 1);
	
	// Generate
	vrrp->vers_type = (VRRP_VERSION << 4) | VRRP_PKT_ADVER;
	vrrp->vrid = app.vrid;
	vrrp->priority = prio;
	vrrp->num_of_vaddr = app.num_of_vaddr;
	vrrp->auth_type = VRRP_AUTHEN_NO;
	vrrp->adver_sec = SEC_FROM_USEC(app.adver_usec);
	for (int i = 0; i < app.num_of_vaddr; i++) {
		vaddrs[i] = htonl(app.vaddrs[i]);
	}
	vaddrs[app.num_of_vaddr] = 0;
	vaddrs[app.num_of_vaddr + 1] = 0;
	vrrp->chksum = 0;
	vrrp->chksum = in_cksum((unsigned short *)vrrp, vrrplen, 0);

	// Send
	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = PF_INET;
	dst.sin_addr.s_addr = VRRP_MCAST_ADDR_NW;
	int ret = sendto(app.sock, buff, bufflen, 0,
		(struct sockaddr *)&dst, sizeof(struct sockaddr));
	if (ret < 0) {
		VRRPLOG("send adver:%s\n", strerror(errno));
	}
	
	free(buff);
	return 0;
}

//! @brief Receive and check the advertisement packet
//! @param[out] buff Where to store received data
//! @param[in]	bufsiz Size of |buff|
static int recv_adver(char *buff, size_t bufsiz)
{
	uint32_t next = 0xFFFFFFFF;
	int32_t delta = -1;
	if (app.adver_timer) {
		delta = (int32_t)(app.adver_timer - now_usec());
	} else {  // mstr_down_timer
		assert(app.mstr_down_timer);
		delta = (int32_t)(app.mstr_down_timer - now_usec());
	}
	if (delta < 0) delta = 0;
	next = (next < delta) ? next : delta;
	
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(app.sock, &readfds);
	struct timeval timeout = {
		.tv_sec = next / 1000000,
		.tv_usec = next % 1000000,
	};

	int vrrplen = adver_len(app.num_of_vaddr);
	int len = select((app.sock) + 1, &readfds, NULL, NULL, &timeout);
	if (len > 0) {
		read(app.sock, buff, RECV_BUFSIZ);
		struct iphdr *ip = (struct iphdr *)buff;
		struct vrrphdr_v2 *vrrp = (struct vrrphdr_v2 *)(ip + 1);
		
		if (ip->ttl != VRRP_IP_TTL) {
			VRRPLOG("wrong ttl %d\n", ip->ttl);
			goto err;
		}
		if ((vrrp->vers_type >> 4) != VRRP_VERSION)  {
			VRRPLOG("wrong version %d\n", vrrp->vers_type >> 4);
			goto err;
		}
		if ((ntohs(ip->tot_len) - ip->ihl) < vrrplen) {
			VRRPLOG("packet is too short\n");
			goto err;
		}
		if (in_cksum((unsigned short *)vrrp, vrrplen, 0)) {
			VRRPLOG("invalid checksum\n");
			goto err;
		}
		if (vrrp->vrid != app.vrid) {
			VRRPLOG("invalid vrid %d\n", vrrp->vrid);
			goto err;
		}
		if (vrrp->auth_type != VRRP_AUTHEN_NO) {
			VRRPLOG("authentication type %d missmatched\n", 
				vrrp->auth_type);
			goto err;
		}

		uint32_t *nw_vaddrs = (uint32_t *)(vrrp + 1);
		for (int i = 0; i < vrrp->num_of_vaddr; ++i) {
			if (ntohl(nw_vaddrs[i]) != app.vaddrs[i]) {
				VRRPLOG("vaddr missmatched %#x\n", 
					ntohl(nw_vaddrs[i]));
				goto err;
			}
		}

		if (vrrp->adver_sec != SEC_FROM_USEC(app.adver_usec)) {
			VRRPLOG("adver_interval %d sec, missmatched\n",
				 vrrp->adver_sec);
			goto err;
		}
		return len;
	}

err:
	return -1;
}

static inline uint32_t GEN_SKEW_USEC(void)
{
	return (USEC_FROM_SEC(256 - app.priority)) / 256;
}

static inline uint32_t GEN_MSTR_DOWN_USEC(void)
{
	return 3 * app.adver_usec + app.skew_usec;
}

//! @brief Transition to VRRP backup state
static int become_backup(void)
{
	app.adver_timer = 0;
	app.mstr_down_timer = SET_TIME(app.mstr_down_usec);
	app.state = VRRP_BACKUP;
	return 0;
}

//! @brief Transition to VRRP master state
static int become_master(void)
{
	// Set VMAC
	set_iface_hw(app.if_name, app.vmac, VRRP_MASTER);

	send_adver(app.priority);
	for (int i = 0; i < app.num_of_vaddr; ++i) {
		send_garp_request(app.if_idx, app.vmac, app.vaddrs[i]);
	}
	app.adver_timer = SET_TIME(app.adver_usec);
	app.mstr_down_timer = 0;
	app.state = VRRP_MASTER;
	return 0;
}

//! @brief Reset interface HW 
/*static int reset_iface_hw(void)
{
	// Restore real MAC
	//struct rt_entry rt_table;
	//memset(&rt_table, 0, sizeof(struct rt_entry));
	//if (!rt_fetch(&rt_table)) VRRPLOG("Can't parse routing table\n");
	//rt_restore(rt_table.next, app.if_name);
	
	return 0;
}*/

//! @brief Implement the behavir of VRRP master state
static int run_as_master(void)
{
	if (evt_shutdown) {
		set_iface_hw(app.if_name, app.if_mac, VRRP_BACKUP);
		// Directly shutdown 
		send_adver(VRRP_PRIO_SHUTDOWN);
		vrrp_shutdown(app.sock, app.pidfile);
		exit(0);
	}
	
	if (vrrp_timer_fires(app.adver_timer, app.adver_usec)) {
		send_adver(app.priority);
		app.adver_timer = SET_TIME(app.adver_usec);
		return 0;
	}

	char buff[RECV_BUFSIZ] = {0};
	int ret = recv_adver(buff, RECV_BUFSIZ);
	if (ret > 0) {
		struct iphdr *ip = (struct iphdr *)buff;
		struct vrrphdr_v2 *adver = (struct vrrphdr_v2 *)(ip + 1);
		if (VRRP_PRIO_SHUTDOWN == adver->priority) {
			VRRPLOG("Current master shutdown\n");
			send_adver(app.priority);
			app.adver_timer = SET_TIME(app.adver_usec);
		} else if (adver->priority > app.priority ||
			(adver->priority == app.priority &&
			ntohl(ip->saddr) > app.if_ipv4))
		{
			set_iface_hw(app.if_name, app.if_mac, VRRP_BACKUP);
			become_backup();
			VRRPLOG("MASTER to BACKUP\n");
		} else {
			//DISCARD
		}
	}
	return 0;
}

//! @brief Implement the behavir of VRRP backup state
static int run_as_backup(void)
{
	if (evt_shutdown) {
		// Directly shutdown 
		vrrp_shutdown(app.sock, app.pidfile);
		exit(0);
	}
	
	if (vrrp_timer_fires(app.mstr_down_timer, app.mstr_down_usec)) {
		become_master();
		VRRPLOG("BACKUP to MASTER\n");
		return 0;
	}

	char buff[RECV_BUFSIZ] = {0};
	int ret = recv_adver(buff, RECV_BUFSIZ);
	if (ret > 0) {
		struct iphdr *ip = (struct iphdr *)buff;
		struct vrrphdr_v2 *adver = (struct vrrphdr_v2 *)(ip + 1);
		if (VRRP_PRIO_SHUTDOWN == adver->priority) {
			VRRPLOG("Current Master shutdown\n");
			app.mstr_down_timer = SET_TIME(app.skew_usec);
		} else if (0 == app.preempt_mode || 
			adver->priority >= app.priority)
		{
			app.mstr_down_timer = SET_TIME(app.mstr_down_usec);
		} else {
			// Discard it
		}
	}

	return 0;
}

//! @brief Print usage
static int usage(void)
{
	printf(
"bxvrrpd version 0.1 (implementation of RFC 3768)\n"
"Usage: bxvrrpd -i ifname -v vrid [OPTIONS] ipaddr\n"
"	-d, --daemonize  : Run as daemon\n"
"	-i, --ifname     : the LAN interface name to run on\n"
"	-v, --vrid       : the id of the virtual server [1-255]\n"
"	-n, --no-preempt : Set non-preempt mode (dfl: preemptible)\n"
"	-p, --prio       : Set local priority (dfl: 100)\n"
"	-I, --interval   : Set the advertisement interval (in sec) (dfl: 1)\n"
"	-h, --help       : help message\n"
"	    --verbose    : (No implementation)\n"
"	ipaddr   : the ip address(es) of the virtual server\n");
	return 0;
}

//! @brief Parse command-line options
//! @param[in] argc The argument count
//! @param[in] argv The argument array
//! @retval 0 Success
//! @retval -1 Invalid arguments
static int parse_args(int argc, char **argv)
{
	struct option longopts[] = {
		{"daemonize",	0, 0, 'd'},
		{"ifname", 	1, 0, 'i'},
		{"vrid", 	1, 0, 'v'},
		{"no-preempt", 	0, 0, 'n'},
		{"prioity", 	1, 0, 'p'},
		{"interval", 	1, 0, 'I'},
		{"help", 	0, 0, 'h'},
		{"verbose", 	0, 0, 'h'},
		{0,0,0,0}
	};
	int opt_idx = 0;
	int c = EOF;
	int input_check = 0;

	while (1) {
		c = getopt_long(argc, argv, "h?di:v:np:I:", longopts, &opt_idx);
		if (EOF == c) break;
		switch (c) {
		case 'd':
			app.daemonize = 1;
			break;
		case 'i':
			snprintf(app.if_name, IFNAMSIZ, "%s", optarg);
			input_check |= HAS_IFNAME;
			if ((get_hwaddr(app.if_name, app.if_mac) < 0) ||
			 (get_ipaddr(app.if_name, &app.if_ipv4) < 0))
			{
				VRRPLOG("Get interface address failed\n");
				goto err;
			}
			app.if_idx = if_nametoindex(app.if_name);
			if (app.if_idx == 0) {
				VRRPLOG("Get interface index failed\n");
				goto err;
			}
			break;
		case 'v':
			app.vrid = atoi(optarg);
			app.vmac[5] = app.vrid;
			input_check |= HAS_VRID;
			break;
		case 'n':
			app.preempt_mode = 0;
			break;
		case 'p':
			app.priority = atoi(optarg);
			break;
		case 'I': 
			app.adver_usec = USEC_FROM_SEC(atoi(optarg));
			break;
		case ':':
		case '?':
		case 'h':
		default:
			usage();
			goto err;
		}
	}
	if (!(input_check & HAS_IFNAME)) {
		VRRPLOG("Missing interface name\n");
		goto err;
	}
	if (!(input_check & HAS_VRID)) {
		VRRPLOG("Missing VRID\n");
		goto err;
	}

	// Add ip(s) associated to virtual router and
	// 1. Check if it is the IP owner.
	// 2. If it is IP owner, set the order.
	for (int i = optind; argv[i]; i++) {
		struct in_addr addr;
		if (!inet_aton(argv[i], &addr)) {
			VRRPLOG("Invalid address:%s\n", argv[i]);
			goto err;
		}

		if (app.if_ipv4 == ntohl(addr.s_addr)) {
			app.priority = VRRP_PRIO_OWNER;
		}

		app.vaddrs[app.num_of_vaddr] = ntohl(addr.s_addr);
		++app.num_of_vaddr;
		input_check |= HAS_IP;
	}
	if (!(input_check & HAS_IP)) {
		VRRPLOG("Missing ip of virtual router\n");
		goto err;
	}
	app.skew_usec = GEN_SKEW_USEC();
	app.mstr_down_usec = GEN_MSTR_DOWN_USEC();

	return 0;
err:
	return -1;
}

static int state_machine(void)
{
	// We need to handle ARP. *sigh*
	pthread_create(&sniff, NULL, vrrp_arp_sniffer, NULL);
	pthread_detach(sniff);
	
	// State machine
	while (1) {
		switch (app.state) {
		case VRRP_INIT:
			//run_as_init();
			if (VRRP_PRIO_OWNER == app.priority) {
				become_master();
				VRRPLOG("INIT to MASTER\n");
			} else {
				become_backup();
				VRRPLOG("INIT to BACKUP\n");
			}
			break;
		case VRRP_MASTER:
			run_as_master();
			break;
		case VRRP_BACKUP:
			run_as_backup();
			break;
		default:
			VRRPLOG("unknown VRRP state\n");
			return -1;
		}
	}

	return 0;
}
