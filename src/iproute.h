/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Version:     $Id: iproute.h,v 0.6 2001/05/23 16:25:32 acassen Exp $
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *              
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *              
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#ifndef _IPROUTE_H
#define _IPROUTE_H

/* global includes */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

/* local includes */
#include "libnetlink.h"
#include "ll_map.h"

/* macro definitions */
#define VRRP_RT(X) ((X))

/* specify a routing entry */
struct rt_entry {
  struct rtmsg *rtm;

  uint32_t psrc;
  uint32_t src;
  uint32_t dest;
  uint32_t gate;
  uint32_t flow;
  int iif;
  int oif;
  int prio;
  int metrics;

  struct rt_entry *next;
};

/* prototypes */

extern struct rt_entry *rt_fetch(struct rt_entry *r);
extern void rt_dump(struct rt_entry *r);
extern void rt_clear(struct rt_entry *lstentry);
extern int rt_restore(struct rt_entry *lstentry, const char *dev);
extern struct rt_entry *rt_sort(struct rt_entry *entry);

#endif
