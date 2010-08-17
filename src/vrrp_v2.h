#ifndef VRRP_V2_H
#define VRRP_V2_H

#include "vrrp_common.h"

#define VRRP_VERSION 2

//! @brief The fixed part of VRRP advertisement packet
struct vrrphdr_v2 {
	uint8_t 	vers_type;
	uint8_t 	vrid;
	uint8_t 	priority;
	uint8_t 	num_of_vaddr;
	uint8_t 	auth_type;
	uint8_t 	adver_sec;
	uint16_t 	chksum;
	// Append ip addresses (4 bytes*n)
	// Append authentication data (8 bytes)
};

#endif //VRRP_V2_H
