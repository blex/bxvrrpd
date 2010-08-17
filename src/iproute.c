#include "iproute.h"

/* Allocation function */
struct rt_entry * rt_new()
{
	struct rt_entry *entry;

	entry = (struct rt_entry *)malloc(sizeof(struct rt_entry));
	memset(entry, 0, sizeof(struct rt_entry));

	entry->rtm = (struct rtmsg *)malloc(sizeof(struct rtmsg));
	memset(entry->rtm, 0, sizeof(struct rtmsg));

	return entry;
}

/* free memory */
void rt_del(struct rt_entry *entry)
{
	free(entry->rtm);
	free(entry);
}

/* destroy functions */
struct rt_entry * clear_entry(struct rt_entry *entry)
{
	struct rt_entry *t;

	t = (struct rt_entry *)entry->next;
	rt_del(entry);
	return t;
}

void rt_clear(struct rt_entry *lstentry)
{
	while (lstentry)
		lstentry = clear_entry(lstentry);
}

/* Append rt entry function */
struct rt_entry * rt_append(struct rt_entry *lstentry, struct rt_entry *entry)
{
	struct rt_entry *ptr = lstentry;

	if (lstentry) {
		while (lstentry->next) lstentry = (struct rt_entry *)lstentry->next;
		lstentry->next = (struct rt_entry *)entry;
		return ptr;
	} else {
		lstentry = entry;
		return lstentry;
	}
}

/* Our rt netlink filter */
int rt_filter(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	struct rt_entry *rtarg;
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[RTA_MAX+1];
	struct rt_entry *entry;

	rtarg = (struct rt_entry *)arg;

	/* Just lookup the Main routing table */
	if (r->rtm_table != RT_TABLE_MAIN)
		return 0;

	/* init len value  */
	len -= NLMSG_LENGTH(sizeof(*r));
	if (len <0) {
		printf("BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	/* init the parse attribute space */
	memset(tb, 0, sizeof(tb));
	parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);

	/*
	 * we return from filter when route is
	 * cloned from another route, learn by an
	 * ICMP redirect or set by kernel.
	 * Return too when rt type != gateway or direct route.
	 */
	if (r->rtm_flags & RTM_F_CLONED)
		return 0;
	if (r->rtm_protocol == RTPROT_REDIRECT)
		return 0;
	if (r->rtm_protocol == RTPROT_KERNEL)
		return 0;
	if (r->rtm_type != RTN_UNICAST)
		return 0;

	if (tb[RTA_OIF]) {
		/* alloc new memory entry */
		entry = rt_new();

		/* copy the rtmsg infos */
		memcpy(entry->rtm, r, sizeof(struct rtmsg));

		/*
		 * can use RTA_PAYLOAD(tb[RTA_SRC])
		 * but ipv4 addr are 4 bytes coded
		 */
		entry->oif = *(int *) RTA_DATA(tb[RTA_OIF]);
		if (tb[RTA_SRC]) memcpy(&entry->src, RTA_DATA(tb[RTA_SRC]), 4);
		if (tb[RTA_PREFSRC]) memcpy(&entry->psrc, RTA_DATA(tb[RTA_PREFSRC]), 4);
		if (tb[RTA_DST]) memcpy(&entry->dest, RTA_DATA(tb[RTA_DST]), 4);
		if (tb[RTA_GATEWAY]) memcpy(&entry->gate, RTA_DATA(tb[RTA_GATEWAY]), 4);
		if (tb[RTA_FLOW]) memcpy(&entry->flow, RTA_DATA(tb[RTA_FLOW]), 4);
		if (tb[RTA_IIF]) entry->iif = *(int *) RTA_DATA(tb[RTA_IIF]);
		if (tb[RTA_PRIORITY]) entry->prio = *(int *) RTA_DATA(tb[RTA_PRIORITY]);
		if (tb[RTA_METRICS]) entry->metrics = *(int *) RTA_DATA(tb[RTA_METRICS]);

		/* save this entry */
		rtarg = rt_append(rtarg, entry);
	}


	return 0;
}

struct rt_entry * rt_fetch(struct rt_entry *r)
{
	struct rtnl_handle rth;

	// open netlink socket of NETLINK_ROUTE
	if (rtnl_open(&rth, 0) < 0) {
		printf("Can not initialize netlink interface...\n");
		return NULL;
	}

	ll_init_map(&rth);

	if (rtnl_wilddump_request(&rth, AF_INET, RTM_GETROUTE) < 0) {
		printf("Cannot send dump request\n");
		close(rth.fd);
		return NULL;
	}

	if (rtnl_dump_filter(&rth, rt_filter, r, NULL, NULL) < 0) {
		printf("Dump terminated.\n");
		close(rth.fd);
		return NULL;
	}

	close(rth.fd);
	return r;
}

int rt_restore_entry(struct rt_entry *r)
{
	struct rtnl_handle rth;

	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	} req;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
	req.n.nlmsg_type = RTM_NEWROUTE;

	memcpy(&req.r, r->rtm, sizeof(struct rtmsg));

	if (r->src)
		addattr_l(&req.n, sizeof(req), RTA_SRC, &r->src, 4);
	if (r->psrc)
		addattr_l(&req.n, sizeof(req), RTA_PREFSRC, &r->psrc, 4);
	if (r->dest)
		addattr_l(&req.n, sizeof(req), RTA_DST, &r->dest, 4);
	if (r->gate)
		addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &r->gate, 4);
	if (r->flow)
		addattr_l(&req.n, sizeof(req), RTA_FLOW, &r->flow, 4);

	if (r->oif)
		addattr32(&req.n, sizeof(req), RTA_OIF, r->oif);
	if (r->iif)
		addattr32(&req.n, sizeof(req), RTA_IIF, r->iif);
	if (r->prio)
		addattr32(&req.n, sizeof(req), RTA_PRIORITY, r->prio);
	if (r->metrics)
		addattr32(&req.n, sizeof(req), RTA_METRICS, r->metrics);

	if (rtnl_open(&rth, 0) < 0) {
		printf("Can not initialize netlink interface...\n");
		return -1;
	}

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0) {
		printf("Can not talk with netlink interface...\n");
		return -1;
	}

	return 0;
}

int rt_restore(struct rt_entry *lstentry, const char *dev)
{
	int idx = ll_name_to_index(dev);
	int ret = 0;
	
	lstentry = rt_sort(lstentry);

	while (lstentry) {
		if (lstentry->oif == idx) {
			ret = rt_restore_entry(lstentry);
			if (ret < 0) return ret;
		}

		lstentry = (struct rt_entry *)lstentry->next;
	}

	return 0;
}

char *ip_ntoa(uint32_t ip)
{
	static char buf[20];
	unsigned char *bytep;

	bytep = (unsigned char *) &(ip);
	sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
	return buf;
}

/* rt netlink dump function */
void rt_dump(struct rt_entry *r)
{
	while (r) {
		if (r->src) printf("src %s ", ip_ntoa(r->src));
		if (r->psrc) printf("prefsrc %s ", ip_ntoa(r->psrc));
		if (r->iif) printf("idev %s", ll_index_to_name(r->iif));

		if (r->dest) printf("dest %s ", ip_ntoa(r->dest));
		if (r->gate) printf("gateway %s ", ip_ntoa(r->gate));

		if (r->prio) printf("priority %d ", r->prio);
		if (r->metrics) printf("metrics %d ", r->metrics);

		if (r->oif) printf("odev %s ", ll_index_to_name(r->oif));

		/* rtmsg specifics */
		if (r->rtm->rtm_dst_len) printf("mask %d ", r->rtm->rtm_dst_len);
		if (r->rtm->rtm_scope == RT_SCOPE_LINK) printf("scope link");

		printf("\n");

		r = (struct rt_entry *)r->next;
	}
}

struct rt_entry *rt_sort(struct rt_entry *entry)
{
	struct rt_entry *previous, *start;

	previous = start = (struct rt_entry *)entry;
	while (entry) {
		/* select no gateway routing entry go to start */
		if (!entry->gate) {
			previous->next = (struct rt_entry *)entry->next;
			entry->next = (struct rt_entry *)start; 
			start = (struct rt_entry *)entry;
			entry = (struct rt_entry *)previous;
		}
	previous = (struct rt_entry *)entry;
	entry = (struct rt_entry *)entry->next;
	}

	return start;
}
