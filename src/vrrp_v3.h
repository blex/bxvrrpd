#ifndef VRRP_V3_H
#define VRRP_V3_H

#include "vrrp_common.h"

#define VRRP_VERSION 3

//! @brief The fixed part of VRRPv3 advertisement packet
struct vrrphdr_v3 {
	uint8_t 	vers_type;
	uint8_t 	vrid;
	uint8_t 	priority;
	uint8_t 	num_of_vaddr;
	uint16_t 	max_adver_csec; // The first 4 bits are reserved
	uint16_t 	chksum;
	// Append ip addresses (4 bytes*n)
};

/*struct pseudohdr_ipv4 {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t	z0; //
	uint8_t	z1; // These three are always 0
	uint8_t	z2; //
	uint8_t next_hdr;
};*/
struct pseudohdr_ipv4 {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t	zero; 		// These three are always 0
	uint8_t	protocol;
	uint16_t upper_len;
};

#endif //VRRP_V2_H
