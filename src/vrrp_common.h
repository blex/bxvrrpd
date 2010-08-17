#ifndef VRRP_COMMON_H
#define VRRP_COMMON_H

#include <stdint.h>
#include <syslog.h>
#include <net/if.h>

// Protocal-level constants
enum vrrp_state {
	VRRP_INIT = 0,
	VRRP_MASTER,
	VRRP_BACKUP,
	VRRP_UNKNOWN
};
#define IPPROTO_VRRP 		112
#define VRRP_PRIO_SHUTDOWN 	0
#define VRRP_PRIO_DFT 		100
#define VRRP_PRIO_OWNER 	255
#define VRRP_PKT_ADVER		1
#define VRRP_IP_TTL 		255
#define VRRP_MCAST_ADDR_STR	"224.0.0.18"
#define VRRP_MCAST_ADDR_NW	0x120000E0
#define VRRP_AUTHEN_NO		0
#define VRRP_AUTHEN_PW		1
#define VRRP_AUTHEN_AH		2
#define VRRP_ADVER_USEC_DFT 	1000000	//usec

// Implementation-level constants
#define OWNER_MAX_NUM 		16
#define RECV_BUFSIZ 		128
#define PIDFILE_LEN		(IFNAMSIZ + 32) // full path
#define PIDFILE_DIR		"/var/run"

#define	HAS_IFNAME	1
#define	HAS_VRID 	2
#define	HAS_IP		4

#define MACSIZ 			6

//! @brief The setting of a VRRP virtual router
struct vrrp_app {
	int 		daemonize;
	char		pidfile[PIDFILE_LEN];
	int 		use_ipv4;
	//
	int 		sock;
	int 		vrid;
	char 		vmac[MACSIZ];
	volatile int 	state;	// shared between two threads
	int 		preempt_mode;
	int 		accept_mode;		// v3
	int 		priority;
	uint32_t	adver_usec;
	uint32_t	mstr_adver_usec;
	uint32_t	skew_usec;
	uint32_t	mstr_down_usec;
	uint32_t 	adver_timer;
	uint32_t 	mstr_down_timer;
	int 		num_of_vaddr;
	uint32_t 	vaddrs[OWNER_MAX_NUM];
	char 		if_name[IFNAMSIZ];
	int 		if_idx;
	uint32_t 	if_ipv4;
	char 		if_mac[MACSIZ];

	// Functions
	int (*parse_args)(int argc, char **argv);
	int (*state_machine)(void);
};

#ifdef DMSG
#define VRRPLOG(f, s...) {printf(f, ## s); syslog(LOG_ERR, f, ## s);}
#else
#define VRRPLOG(f, s...) syslog(LOG_ERR, f, ## s)
#endif

uint32_t now_usec(void);
int check_pidfile(char *buff, size_t buffsiz, const char *tag);
unsigned short in_cksum(unsigned short *addr, int len, unsigned short csum);

void* vrrp_arp_sniffer(void *arg);
int vrrp_dump(struct vrrp_app *app);
int vrrp_initialize(struct vrrp_app *app);
int vrrp_shutdown(int sock, const char *pidfile);
int vrrp_timer_fires(uint32_t value, uint32_t upbound);
int set_iface_hw(const char *ifname, const char *mac, enum vrrp_state flag);

#define USEC_FROM_SEC(s) ((s) * 1000000)
#define SEC_FROM_USEC(u) ((u) / 1000000)
#define USEC_FROM_CSEC(c) ((c) * 10000)
#define CSEC_FROM_USEC(u) ((u) / 10000)
#define SET_TIME(usec)	(now_usec() + (usec))

#endif //VRRP_COMMON_H
