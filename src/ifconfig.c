#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include "ifconfig.h"

//! @brief Get HW address by the given interface name 
//! @param[in]  ifname The given interface name
//! @param[out] hwaddr Where to store HW address
//! @retval 0 Success
//! @retval -1 Failed
int get_hwaddr(const char *ifname, char *hwaddr)
{
	int fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;

	struct ifreq req_hwaddr;
	strcpy(req_hwaddr.ifr_name, ifname);
	if (ioctl(fd, SIOCGIFHWADDR, &req_hwaddr) < 0) goto err;

	//XXX: There may be '\0' in MAC
	memcpy((void *)hwaddr, req_hwaddr.ifr_hwaddr.sa_data, 
		sizeof(char) * 6);

	close(fd);
	return 0;
err:
	close(fd);
	return -1;
}

//! @brief Get IPv4 address by the given interface name (in host byteorder)
//! @param[in]  ifname The given interface name
//! @param[out] n_ipaddr Where to store ipaddr
//! @retval 0 Success 
//! @retval -1 Failure
int get_ipaddr(const char *ifname, uint32_t *ipaddr)
{
	int fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;

	struct ifreq req_ipaddr;
	req_ipaddr.ifr_addr.sa_family = PF_INET;
	strcpy(req_ipaddr.ifr_name, ifname);
	if (ioctl(fd, SIOCGIFADDR, &req_ipaddr) < 0) goto err;

	*ipaddr = ntohl(((struct sockaddr_in *)
		&req_ipaddr.ifr_addr)->sin_addr.s_addr);
	close(fd);
	return 0;
err:
	close(fd);
	return -1;
}

//! @brief Set hwaddr by given hardware address and interface name
//! @param[in] ifname The given interface name
//! @param[in] hwaddr The given hardware address
//! @param[in] addrlen The length of given address
//! @retval 0 Success
//! @retval -1 Failure
int set_hwaddr(const char *ifname, const char *hwaddr, const size_t addrlen)
{
	int fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;

	struct ifreq req;
	strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
	if (ioctl(fd, SIOCGIFFLAGS, (char *)&req) < 0) goto err;

	unsigned long flags = req.ifr_flags;

	req.ifr_flags &= ~IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, (char *)&req) < 0) goto err;

	memcpy(req.ifr_hwaddr.sa_data, hwaddr, addrlen);
	req.ifr_hwaddr.sa_family = PF_UNIX;
	if (ioctl(fd, SIOCSIFHWADDR, (char *)&req) < 0) goto err;

	req.ifr_flags = flags;
	if (ioctl(fd, SIOCSIFFLAGS, (char *)&req) < 0) goto err;
	
	close(fd);
	return 0;
err:
	close(fd);
	return -1;
}

//! @brief Set the promiscuous flag by given interface name
//! @param[in] ifname The given interface name
//! @retval 0 Success
//! @retval -1 Failure
int set_promiscuous(const char *ifname)
{
	struct ifreq req;
	int fd;
	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;

	strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

	if (ioctl(fd, SIOCGIFFLAGS, (char *)&req) < 0) goto err;
	
	req.ifr_flags |= IFF_PROMISC;
	if (ioctl(fd, SIOCSIFFLAGS, (char *)&req) < 0) goto err;
	
	close(fd);
	return 0;
err:
	close(fd);
	return -1;
}

//! @brief Unset the promiscuous flag by given interface name
//! @param[in] ifname The given interface name
//! @retval 0 Success
//! @retval -1 Failure
int unset_promiscuous(const char *ifname)
{
	struct ifreq req;
	int fd;
	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;

	strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

	if (ioctl(fd, SIOCGIFFLAGS, (char *)&req) < 0) goto err;
	
	req.ifr_flags &= ~IFF_PROMISC;
	if (ioctl(fd, SIOCSIFFLAGS, (char *)&req) < 0) goto err;
	
	close(fd);
	return 0;

err:
	close(fd);
	return -1;
}

