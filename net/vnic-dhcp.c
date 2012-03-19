/*
 * QEMU System Emulator
 * Solaris VNIC DHCP support
 *
 * Copyright (c) 2011 Joyent, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <arpa/inet.h>

#include "net/vnic-dhcp.h"

#include <slirp.h>  /* GodDAMN */
#include "ip.h"
#include "udp.h"
#include "qemu-error.h"

/* from slirp.c: */
#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/
/* from bootp.c: */
#define LEASE_TIME (24 * 3600)
/* from slirp/debug.h: */
#define dfd stderr
/* from bootp.c and modified: */
#ifdef VNIC_DHCP_DEBUG
#define DPRINTF(fmt, ...) \
do if (VNIC_DHCP_DEBUG) { fprintf(dfd, fmt, ##  __VA_ARGS__); fflush(dfd); } \
    while (0)
#else
#define DPRINTF(fmt, ...) do {} while(0)
#endif
/* from cksum.c: */
#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE {l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; \
	(void)ADDCARRY(sum);}

/* from bootp.c: */
static const uint8_t rfc1533_cookie[] = { RFC1533_COOKIE };
/* emulated hosts use the MAC addr 52:55:IP:IP:IP:IP */
static const uint8_t special_ethaddr[6] = {
	0x52, 0x55, 0x55, 0x55, 0x55, 0x55
};

static void
print_dhcp_info(const struct bootp_t *bp)
{
	char ip_str[INET_ADDRSTRLEN];
	char *macaddr;
	DPRINTF("  bp->bp_op=%d\n", bp->bp_op);

	inet_ntop(AF_INET, &(bp->ip.ip_src), ip_str, INET_ADDRSTRLEN);
	DPRINTF("  bp->ip_src=%s\n", ip_str);
	inet_ntop(AF_INET, &(bp->ip.ip_dst), ip_str, INET_ADDRSTRLEN);
	DPRINTF("  bp->ip_dst=%s\n", ip_str);
	DPRINTF("  bp->udp.uh_sport=%d\n", ntohs(bp->udp.uh_sport));
	DPRINTF("  bp->udp.uh_dport=%d\n", ntohs(bp->udp.uh_dport));

	macaddr = _link_ntoa(bp->bp_hwaddr, ip_str, ETH_ALEN, 0);
	DPRINTF("  bp->bp_hwaddr=%s\n", macaddr);
	free(macaddr);

	inet_ntop(AF_INET, &(bp->bp_yiaddr), ip_str, INET_ADDRSTRLEN);
	DPRINTF("  bp->bp_yiaddr=%s\n", ip_str);
	inet_ntop(AF_INET, &(bp->bp_siaddr), ip_str, INET_ADDRSTRLEN);
	DPRINTF("  bp->bp_siaddr=%s\n", ip_str);
	inet_ntop(AF_INET, &(bp->bp_giaddr), ip_str, INET_ADDRSTRLEN);
	DPRINTF("  bp->bp_giaddr=%s\n", ip_str);
	inet_ntop(AF_INET, &(bp->bp_ciaddr), ip_str, INET_ADDRSTRLEN);
	DPRINTF("  bp->bp_ciaddr=%s\n", ip_str);
}

/* from bootp.c: */
static void
dhcp_decode(const struct bootp_t *bp, int *pmsg_type,
    struct in_addr *preq_addr)
{
	const uint8_t *p, *p_end;
	int len, tag;

	*pmsg_type = 0;
	preq_addr->s_addr = htonl(0L);

	p = bp->bp_vend;
	p_end = p + DHCP_OPT_LEN;
	if (memcmp(p, rfc1533_cookie, 4) != 0)
		return;
	p += 4;
	while (p < p_end) {
		tag = p[0];
		if (tag == RFC1533_PAD) {
			p++;
		} else if (tag == RFC1533_END) {
			break;
		} else {
			p++;
			if (p >= p_end)
				break;
			len = *p++;
			DPRINTF("dhcp: tag=%d len=%d\n", tag, len);

			switch(tag) {
			case RFC2132_MSG_TYPE:
				if (len >= 1)
					*pmsg_type = p[0];
				break;
			case RFC2132_REQ_ADDR:
				if (len >= 4) {
					memcpy(&(preq_addr->s_addr), p, 4);
				}
				break;
			default:
				break;
			}
			p += len;
		}
	}
	if (*pmsg_type == DHCPREQUEST && preq_addr->s_addr == htonl(0L) &&
	    bp->bp_ciaddr.s_addr) {
		memcpy(&(preq_addr->s_addr), &bp->bp_ciaddr, 4);
	}
}

#if VNIC_DHCP_HEX_DUMP
/* from net.c: */
static void
hex_dump(FILE *f, const uint8_t *buf, int size)
{
	int len, i, j, c;

	for(i = 0; i < size; i += 16) {
		len = size - i;
		if (len > 16)
			len = 16;
		fprintf(f, "%08x ", i);
		for(j = 0; j < 16; j++) {
			if (j < len)
				fprintf(f, " %02x", buf[i + j]);
			else
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		for(j = 0; j < len; j++) {
			c = buf[i + j];
			if (c < ' ' || c > '~')
				c = '.';
			fprintf(f, "%c", c);
		}
		fprintf(f, "\n");
	}
}
#endif


/* from cksum.c, and modified to work on non-mbufs: */
static int
cksum2(uint16_t *m, int len)
{
	register uint16_t *w = m;
	register int sum = 0;
	register int mlen = len;
	int byte_swapped = 0;

	union {
		uint8_t  c[2];
		uint16_t s;
	} s_util;
	union {
		uint16_t s[2];
		uint32_t l;
	} l_util;

#ifdef DEBUG
	len -= mlen;
#endif
	/*
	 * Force to even boundary.
	 */
	if ((1 & (long) w) && (mlen > 0)) {
		REDUCE;
		sum <<= 8;
		s_util.c[0] = *(uint8_t *)w;
		w = (uint16_t *)((int8_t *)w + 1);
		mlen--;
		byte_swapped = 1;
	}
	/*
	 * Unroll the loop to make overhead from
	 * branches &c small.
	 */
	while ((mlen -= 32) >= 0) {
		sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
		sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
		sum += w[8]; sum += w[9]; sum += w[10]; sum += w[11];
		sum += w[12]; sum += w[13]; sum += w[14]; sum += w[15];
		w += 16;
	}
	mlen += 32;
	while ((mlen -= 8) >= 0) {
		sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
		w += 4;
	}
	mlen += 8;
	if (mlen == 0 && byte_swapped == 0)
		goto cont;
	REDUCE;
	while ((mlen -= 2) >= 0) {
		sum += *w++;
	}

	if (byte_swapped) {
		REDUCE;
		sum <<= 8;
		if (mlen == -1) {
			s_util.c[1] = *(uint8_t *)w;
			sum += s_util.s;
			mlen = 0;
		} else

			mlen = -1;
	} else if (mlen == -1)
		s_util.c[0] = *(uint8_t *)w;

cont:
#ifdef DEBUG
	if (len) {
		DPRINTF("cksum: out of data\n");
		DPRINTF(" len = %d\n", len);
	}
#endif
	if (mlen == -1) {
		/* The last mbuf has odd # of bytes. Follow the
	           standard (the odd byte may be shifted left by 8 bits
	           or not as determined by endian-ness of the machine) */
		s_util.c[1] = 0;
		sum += s_util.s;
	}
	REDUCE;
	return (~sum & 0xffff);
}

#ifdef VNIC_DHCP_DEBUG
void
debug_eth_frame(const uint8_t *buf_p, size_t size)
{
	int proto;
	char ip_str[INET_ADDRSTRLEN];
	struct ip *ip;
	char *macaddr;

	DPRINTF("ethernet frame: ");
#if VNIC_DHCP_HEX_DUMP
	DPRINTF("\n");
	hex_dump(dfd, buf_p, size);
#endif

	if (size < ETH_HLEN) {
		DPRINTF("size %d < ETH_HLEN\n", (int)size);
	}

	macaddr = _link_ntoa(((struct ethhdr *)buf_p)->h_source, ip_str,
	    ETH_ALEN, 0);
	DPRINTF("  src mac=%s", macaddr);
	free(macaddr);

	macaddr = _link_ntoa(((struct ethhdr *)buf_p)->h_dest, ip_str,
	    ETH_ALEN, 0);
	DPRINTF("  dst mac=%s", macaddr);
	free(macaddr);

	proto = ntohs(*(uint16_t *)(buf_p + 12));
	DPRINTF(" proto=%d ", proto);
	/* XXX: does this work with VLAN tags? */

	switch (proto) {
	case ETH_P_ARP:
		DPRINTF("(ETH_P_ARP)\n");
		break;
	case ETH_P_IP:
		DPRINTF("(ETH_P_IP)\n");
		break;
	default:
		DPRINTF("(unknown)\n");
		break;
	}

	if (size < sizeof(struct ip)) {
		DPRINTF("  (len < sizeof(struct ip))\n");
		return;
	}

	ip = (struct ip *)(buf_p + ETH_HLEN);
	DPRINTF("  ip version: %d\n", ip->ip_v);
	if (ip->ip_v != IPVERSION)
		return;

	inet_ntop(AF_INET, &(ip->ip_src), ip_str, INET_ADDRSTRLEN);
	DPRINTF("  ip_src=%s\n", ip_str);
	inet_ntop(AF_INET, &(ip->ip_dst), ip_str, INET_ADDRSTRLEN);
	DPRINTF("  ip_dst=%s\n", ip_str);

	DPRINTF("  ip_proto=");
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		DPRINTF("IPPROTO_TCP\n");
		break;
	case IPPROTO_UDP:
		DPRINTF("IPPROTO_UDP\n");
		break;
	case IPPROTO_ICMP:
		DPRINTF("IPPROTO_ICMP\n");
		break;
	default:
		DPRINTF("unknown protocol %d\n", ip->ip_p);
	}

	if (ip->ip_dst.s_addr == 0xffffffff && ip->ip_p == IPPROTO_UDP) {
		DPRINTF("  UDP broadcast\n");
	}

	if (ip->ip_p == IPPROTO_UDP) {
		struct udphdr *uh = (struct udphdr *)(buf_p + ETH_HLEN +
		    (ip->ip_hl << 2));
		DPRINTF("  uh_sport=%d\n", ntohs(uh->uh_sport));
		DPRINTF("  uh_dport=%d\n", ntohs(uh->uh_dport));
		DPRINTF("  uh_ulen=%d\n", uh->uh_ulen);

		if (ntohs(uh->uh_dport) == BOOTP_SERVER) {
			struct bootp_t bp;
			DPRINTF("  BOOTP_SERVER\n");
			memcpy(&bp, ip, sizeof(struct ip));
			memcpy(&(bp.udp), uh, sizeof(struct bootp_t) -
			    sizeof(struct ip));
			print_dhcp_info(&bp);
		}

		if (ntohs(uh->uh_dport) == TFTP_SERVER) {
			DPRINTF("  TFTP_SERVER\n");
		}
	}
}
#endif

static int
populate_dhcp_reply(const struct bootp_t *bp, struct bootp_t *rbp,
    struct sockaddr_in * saddr, struct sockaddr_in *daddr, VNICDHCPState *vdsp)
{
	uint8_t *q;
	struct in_addr preq_addr;
	int dhcp_msg_type, val, i;

	/* extract exact DHCP msg type */
	dhcp_decode(bp, &dhcp_msg_type, &preq_addr);
	DPRINTF("bootp packet op=%d msgtype=%d", bp->bp_op, dhcp_msg_type);
	if (preq_addr.s_addr != htonl(0L))
		DPRINTF(" req_addr=%08x\n", ntohl(preq_addr.s_addr));
	else
		DPRINTF("\n");

	if (dhcp_msg_type == 0)
		dhcp_msg_type = DHCPREQUEST; /* Force reply for old clients */

	if (dhcp_msg_type != DHCPDISCOVER &&
	    dhcp_msg_type != DHCPREQUEST)
		return (0);

	memset(rbp, 0, sizeof(struct bootp_t));

	rbp->bp_op = BOOTP_REPLY;
	rbp->bp_xid = bp->bp_xid;
	rbp->bp_htype = 1;
	rbp->bp_hlen = 6;
	memcpy(rbp->bp_hwaddr, bp->bp_hwaddr, 6);
	rbp->bp_yiaddr = daddr->sin_addr;
	rbp->bp_siaddr = saddr->sin_addr;
	q = rbp->bp_vend;
	memcpy(q, rfc1533_cookie, 4);
	q += 4;

	if (dhcp_msg_type == DHCPDISCOVER || dhcp_msg_type == DHCPREQUEST) {
		DPRINTF("%s addr=%08x\n",
		    (dhcp_msg_type == DHCPDISCOVER) ? "offered" : "ack'ed",
		    ntohl(daddr->sin_addr.s_addr));

		*q++ = RFC2132_MSG_TYPE;
		*q++ = 1;
		/* DHCPREQUEST */
		*q++ = (dhcp_msg_type == DHCPDISCOVER) ? DHCPOFFER : DHCPACK;

		*q++ = RFC2132_SRV_ID;
		*q++ = 4;
		memcpy(q, &saddr->sin_addr, 4);
		q += 4;

		// netmask
		*q++ = RFC1533_NETMASK;
		*q++ = 4;
		memcpy(q, &vdsp->vnds_netmask_addr, sizeof(struct in_addr));
		q += 4;

		// default gw
		if (vdsp->vnds_gw_addr.s_addr != 0) {
			*q++ = RFC1533_GATEWAY;
			*q++ = 4;
			memcpy(q, &vdsp->vnds_gw_addr, sizeof(struct in_addr));
			q += 4;
		}

		// dns server list
		if (vdsp->vnds_num_dns_addrs > 0) {
			*q++ = RFC1533_DNS;
			*q++ = 4 * vdsp->vnds_num_dns_addrs;
			for (i = 0; i < vdsp->vnds_num_dns_addrs; i++) {
				memcpy(q, &vdsp->vnds_dns_addrs[i], sizeof(struct in_addr));
				q += 4;
			}
		}

		// lease time
		*q++ = RFC2132_LEASE_TIME;
		*q++ = 4;
		memcpy(q, &vdsp->vnds_lease_time, 4);
		q += 4;

		// hostname
		val = strlen(vdsp->vnds_client_hostname);
		if (val > 0) {
			*q++ = RFC1533_HOSTNAME;
			*q++ = val;
			memcpy(q, &vdsp->vnds_client_hostname, val);
			q += val;
		}
	} else {
		static const char nak_msg[] = "requested address not available";

		DPRINTF("nak'ed addr=%08x\n", ntohl(preq_addr.s_addr));

		*q++ = RFC2132_MSG_TYPE;
		*q++ = 1;
		*q++ = DHCPNAK;

		*q++ = RFC2132_MESSAGE;
		*q++ = sizeof(nak_msg) - 1;
		memcpy(q, nak_msg, sizeof(nak_msg) - 1);
		q += sizeof(nak_msg) - 1;
	}
	*q = RFC1533_END;

	return (1);
}

static void
add_udpip_header(struct udpiphdr *ui, struct sockaddr_in *saddr,
    struct sockaddr_in *daddr)
{
	memset(&ui->ui_i.ih_mbuf, 0 , sizeof(struct mbuf_ptr));
	ui->ui_x1 = 0;
	ui->ui_pr = IPPROTO_UDP;
	ui->ui_len = htons(sizeof(struct bootp_t) - sizeof(struct ip));
	ui->ui_src = saddr->sin_addr;
	ui->ui_dst = daddr->sin_addr;
	ui->ui_sport = saddr->sin_port;
	ui->ui_dport = daddr->sin_port;
	ui->ui_ulen = htons(sizeof(struct bootp_t) - sizeof(struct ip));

	ui->ui_sum = 0;
	if ((ui->ui_sum = cksum2((uint16_t *)ui, sizeof(struct bootp_t))) == 0)
		ui->ui_sum = 0xffff;
}

static void
add_ip_header(struct ip *ip, VNICDHCPState *vdsp)
{
	register int ip_hlen = sizeof(struct ip);
	register int ip_len = sizeof(struct bootp_t);

	ip->ip_v = IPVERSION;
	ip->ip_off &= IP_DF;
	ip->ip_id = htons(vdsp->vnds_ip_id++);
	ip->ip_hl = ip_hlen >> 2;

	ip->ip_ttl = IPDEFTTL;
	ip->ip_tos = IPTOS_LOWDELAY;

	ip->ip_len = htons((uint16_t)ip_len);
	ip->ip_off = htons((uint16_t)ip->ip_off);
	ip->ip_sum = 0;
	ip->ip_sum = cksum2((uint16_t *) ip, ip_hlen);
}

static int
dhcp_reply(const struct bootp_t *bp, const unsigned char *src_mac,
    VNICDHCPState *vdsp)
{
	struct sockaddr_in saddr, daddr;
	struct ethhdr *eh;
	struct bootp_t *rbp = (struct bootp_t *)(vdsp->vnds_buf + ETH_HLEN);

	/* Client IP address */
	memcpy(&daddr.sin_addr, &vdsp->vnds_client_addr,
	    sizeof(struct in_addr));
	daddr.sin_port = htons(BOOTP_CLIENT);

	/* Server IP address */
	memcpy(&saddr.sin_addr, &vdsp->vnds_srv_addr, sizeof(struct in_addr));
	saddr.sin_port = htons(BOOTP_SERVER);

	/* Now set all of the DHCP options */
	if (!populate_dhcp_reply(bp, rbp, &saddr, &daddr, vdsp))
		return (0);

	daddr.sin_addr.s_addr = 0xffffffffu;

	/* Buffer Layout:
	 *
	 * | ethhdr | bootp_t                          |
	 *          | ip       | udphdr | dhcp payload |
	 *          | udpiphdr          |
	 *
      	 */

	/* Ethernet header */
	eh = (struct ethhdr *)vdsp->vnds_buf;
	memcpy(eh->h_dest, src_mac, ETH_ALEN);
	memcpy(eh->h_source, special_ethaddr, ETH_ALEN);
	eh->h_proto = htons(ETH_P_IP);

	/* IP pseudo header (for UDP checksum) */
	add_udpip_header((struct udpiphdr *)rbp, &saddr, &daddr);

	add_ip_header((struct ip *)rbp, vdsp);

#if VNIC_DHCP_DEBUG
	DPRINTF("= dhcp reply =\n");
	debug_eth_frame((const uint8_t *)vdsp->vnds_buf,
	    sizeof(struct bootp_t) + sizeof(struct ethhdr));
	DPRINTF("= dhcp reply end =\n");
#endif

	return (sizeof(struct bootp_t) + sizeof(struct ethhdr));
}

int
create_dhcp_response(const uint8_t *buf_p, int pkt_len, VNICDHCPState *vdsp)
{
	struct bootp_t bp;
	register struct udphdr *uh;
	register struct ip *ip = (struct ip *)(buf_p + ETH_HLEN);

	DPRINTF("create_dhcp_response()\n");

	if (ip->ip_p != IPPROTO_UDP) {
		return (0);
	}

	uh = (struct udphdr *) (buf_p + ETH_HLEN + (ip->ip_hl << 2));
	if (ntohs(uh->uh_dport) != BOOTP_SERVER) {
		return (0);
	}

	/* Trim out IP options (if any) */
	memcpy(&bp, ip, sizeof(struct ip));
	memcpy(&(bp.udp), uh, sizeof(struct bootp_t) - sizeof(struct ip));

	if (bp.bp_op != BOOTP_REQUEST) {
		return (0);
	}

	return (dhcp_reply(&bp, ((struct ethhdr *)buf_p)->h_dest, vdsp));
}

int
is_dhcp_request(const uint8_t *buf_p, size_t size)
{
	struct ip *ip;
	struct udphdr *uh;

	DPRINTF("is_dhcp_request(): ");
	if (size < ETH_HLEN || (ntohs(*(uint16_t *)(buf_p + 12)) != ETH_P_IP) ||
	    size < sizeof (struct ip)) {
		DPRINTF("packet too small\n");
		return (0);
	}

	ip = (struct ip *)(buf_p + ETH_HLEN);

	if (ip->ip_v != IPVERSION) {
		DPRINTF("not an IPv4 packet\n");
		return (0);
	}

	if (ip->ip_p != IPPROTO_UDP) {
		DPRINTF("not a UDP packet\n");
		return (0);
	}

	uh = (struct udphdr *)(buf_p + ETH_HLEN + (ip->ip_hl << 2));
	if (ntohs(uh->uh_dport) == BOOTP_SERVER) {
		DPRINTF("is a DHCP request\n");
		return (1);
	}

	DPRINTF("UDP packet, but not a DHCP request\n");
	return (0);
}

static int
qemu_ip_opt(QemuOpts *opts, const char *opt_name, struct in_addr *addr, int required)
{
	const char *opt;
	if ((opt = qemu_opt_get(opts, opt_name)) == NULL) {
		if (required)
			error_report("missing %s for vnic dhcp\n", opt_name);
		return (0);
	}

	if (inet_pton(AF_INET, opt, addr) != 1) {
		error_report("invalid %s '%s' for vnic dhcp\n", opt_name, opt);
		return (-1);
	}

	return (1);
}

int
vnic_dhcp_init(VNICDHCPState *vdsp, QemuOpts *opts)
{
	int ret, i;
	uint32_t lease_time;
	const char *hostname;
	char dns_opt[8];
	int num_dns_servers = 0;

	/* Use the ip option to determine if dhcp should be enabled */
	if (qemu_opt_get(opts, "ip") == NULL) {
		error_report("vnic dhcp disabled\n");
		vdsp->vnds_enabled = 0;
		return (1);
	}

	if (!qemu_ip_opt(opts, "ip", &(vdsp->vnds_client_addr), 1))
		return (0);

	if (!qemu_ip_opt(opts, "netmask", &(vdsp->vnds_netmask_addr), 1))
		return (0);

	if (!(ret = qemu_ip_opt(opts, "server_ip", &(vdsp->vnds_srv_addr), 0))) {
		if (ret == 0) {
			/* default DHCP server address */
			inet_pton(AF_INET, "169.254.169.254",
			    &(vdsp->vnds_srv_addr));
		} else {
			return (0);
		}
	}

	if (!qemu_ip_opt(opts, "gateway_ip", &(vdsp->vnds_gw_addr), 0)) {
		vdsp->vnds_gw_addr.s_addr = 0;
	}

	if ((ret = qemu_ip_opt(opts, "dns_ip", &(vdsp->vnds_dns_addrs[0]), 0)) != 0) {
		if (ret == -1)
			return (0);
		num_dns_servers = 1;
	}

	for(i = 0; i < VNIC_DHCP_NUM_RESOLVERS; i++) {
		sprintf(dns_opt, "dns_ip%d", i);
		if (!(ret = qemu_ip_opt(opts, dns_opt, &(vdsp->vnds_dns_addrs[i]), 0))) {
			if (ret == 0) {
				break;
			} else {
				return (0);
			}
		}
		num_dns_servers = i + 1;
	}
	vdsp->vnds_num_dns_addrs = num_dns_servers;

	if ((hostname = qemu_opt_get(opts, "hostname")) != NULL) {
		ret = strlen(hostname);
		if (ret > sizeof(vdsp->vnds_client_hostname)) {
			error_report("hostname is too long\n");
			return (0);
		}
		memcpy(&vdsp->vnds_client_hostname, hostname, ret);
	} else {
		vdsp->vnds_client_hostname[0] = '\0';
	}

	lease_time = qemu_opt_get_number(opts, "lease_time", LEASE_TIME);
	vdsp->vnds_lease_time = htonl(lease_time);

	vdsp->vnds_ip_id = 0;
	vdsp->vnds_enabled = 1;

	return (1);
}
