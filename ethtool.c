/*
 * ethtool.c: Linux ethernet device configuration tool.
 *
 * Copyright (C) 1998 David S. Miller (davem@dm.cobaltmicro.com)
 * Portions Copyright 2001 Sun Microsystems
 * Kernel 2.4 update Copyright 2001 Jeff Garzik <jgarzik@mandrakesoft.com>
 * Wake-on-LAN,natsemi,misc support by Tim Hockin <thockin@sun.com>
 * Portions Copyright 2002 Intel
 * Portions Copyright (C) Sun Microsystems 2008
 * do_test support by Eli Kupermann <eli.kupermann@intel.com>
 * ETHTOOL_PHYS_ID support by Chris Leech <christopher.leech@intel.com>
 * e1000 support by Scott Feldman <scott.feldman@intel.com>
 * e100 support by Wen Tao <wen-hwa.tao@intel.com>
 * ixgb support by Nicholas Nunley <Nicholas.d.nunley@intel.com>
 * amd8111e support by Reeja John <reeja.john@amd.com>
 * long arguments by Andi Kleen.
 * SMSC LAN911x support by Steve Glendinning <steve.glendinning@smsc.com>
 * Rx Network Flow Control configuration support <santwona.behera@sun.com>
 * Various features by Ben Hutchings <bhutchings@solarflare.com>;
 *	Copyright 2009, 2010 Solarflare Communications
 *
 * TODO:
 *   * show settings for all devices
 */

#include "internal.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
#include <sys/utsname.h>
#include <limits.h>
#include <ctype.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/sockios.h>

#ifndef MAX_ADDR_LEN
#define MAX_ADDR_LEN	32
#endif

#ifndef HAVE_NETIF_MSG
enum {
	NETIF_MSG_DRV		= 0x0001,
	NETIF_MSG_PROBE		= 0x0002,
	NETIF_MSG_LINK		= 0x0004,
	NETIF_MSG_TIMER		= 0x0008,
	NETIF_MSG_IFDOWN	= 0x0010,
	NETIF_MSG_IFUP		= 0x0020,
	NETIF_MSG_RX_ERR	= 0x0040,
	NETIF_MSG_TX_ERR	= 0x0080,
	NETIF_MSG_TX_QUEUED	= 0x0100,
	NETIF_MSG_INTR		= 0x0200,
	NETIF_MSG_TX_DONE	= 0x0400,
	NETIF_MSG_RX_STATUS	= 0x0800,
	NETIF_MSG_PKTDATA	= 0x1000,
	NETIF_MSG_HW		= 0x2000,
	NETIF_MSG_WOL		= 0x4000,
};
#endif

static void exit_bad_args(void) __attribute__((noreturn));

static void exit_bad_args(void)
{
	fprintf(stderr,
		"ethtool: bad command line argument(s)\n"
		"For more information run ethtool -h\n");
	exit(1);
}

typedef enum {
	CMDL_NONE,
	CMDL_BOOL,
	CMDL_S32,
	CMDL_U8,
	CMDL_U16,
	CMDL_U32,
	CMDL_U64,
	CMDL_BE16,
	CMDL_IP4,
	CMDL_STR,
	CMDL_FLAG,
	CMDL_MAC,
} cmdline_type_t;

struct cmdline_info {
	const char *name;
	cmdline_type_t type;
	/* Points to int (BOOL), s32, u16, u32 (U32/FLAG/IP4), u64,
	 * char * (STR) or u8[6] (MAC).  For FLAG, the value accumulates
	 * all flags to be set. */
	void *wanted_val;
	void *ioctl_val;
	/* For FLAG, the flag value to be set/cleared */
	u32 flag_val;
	/* For FLAG, points to u32 and accumulates all flags seen.
	 * For anything else, points to int and is set if the option is
	 * seen. */
	void *seen_val;
};

struct flag_info {
	const char *name;
	u32 value;
};

static const struct flag_info flags_msglvl[] = {
	{ "drv",	NETIF_MSG_DRV },
	{ "probe",	NETIF_MSG_PROBE },
	{ "link",	NETIF_MSG_LINK },
	{ "timer",	NETIF_MSG_TIMER },
	{ "ifdown",	NETIF_MSG_IFDOWN },
	{ "ifup",	NETIF_MSG_IFUP },
	{ "rx_err",	NETIF_MSG_RX_ERR },
	{ "tx_err",	NETIF_MSG_TX_ERR },
	{ "tx_queued",	NETIF_MSG_TX_QUEUED },
	{ "intr",	NETIF_MSG_INTR },
	{ "tx_done",	NETIF_MSG_TX_DONE },
	{ "rx_status",	NETIF_MSG_RX_STATUS },
	{ "pktdata",	NETIF_MSG_PKTDATA },
	{ "hw",		NETIF_MSG_HW },
	{ "wol",	NETIF_MSG_WOL },
};

static long long
get_int_range(char *str, int base, long long min, long long max)
{
	long long v;
	char *endp;

	if (!str)
		exit_bad_args();
	errno = 0;
	v = strtoll(str, &endp, base);
	if (errno || *endp || v < min || v > max)
		exit_bad_args();
	return v;
}

static unsigned long long
get_uint_range(char *str, int base, unsigned long long max)
{
	unsigned long long v;
	char *endp;

	if (!str)
		exit_bad_args();
	errno = 0;
	v = strtoull(str, &endp, base);
	if ( errno || *endp || v > max)
		exit_bad_args();
	return v;
}

static int get_int(char *str, int base)
{
	return get_int_range(str, base, INT_MIN, INT_MAX);
}

static u32 get_u32(char *str, int base)
{
	return get_uint_range(str, base, 0xffffffff);
}

static void get_mac_addr(char *src, unsigned char *dest)
{
	int count;
	int i;
	int buf[ETH_ALEN];

	count = sscanf(src, "%2x:%2x:%2x:%2x:%2x:%2x",
		&buf[0], &buf[1], &buf[2], &buf[3], &buf[4], &buf[5]);
	if (count != ETH_ALEN)
		exit_bad_args();

	for (i = 0; i < count; i++) {
		dest[i] = buf[i];
	}
}

static void parse_generic_cmdline(struct cmd_context *ctx,
				  int *changed,
				  struct cmdline_info *info,
				  unsigned int n_info)
{
	int argc = ctx->argc;
	char **argp = ctx->argp;
	int i, idx;
	int found;

	for (i = 0; i < argc; i++) {
		found = 0;
		for (idx = 0; idx < n_info; idx++) {
			if (!strcmp(info[idx].name, argp[i])) {
				found = 1;
				*changed = 1;
				if (info[idx].type != CMDL_FLAG &&
				    info[idx].seen_val)
					*(int *)info[idx].seen_val = 1;
				i += 1;
				if (i >= argc)
					exit_bad_args();
				switch (info[idx].type) {
				case CMDL_BOOL: {
					int *p = info[idx].wanted_val;
					if (!strcmp(argp[i], "on"))
						*p = 1;
					else if (!strcmp(argp[i], "off"))
						*p = 0;
					else
						exit_bad_args();
					break;
				}
				case CMDL_S32: {
					s32 *p = info[idx].wanted_val;
					*p = get_int_range(argp[i], 0,
							   -0x80000000LL,
							   0x7fffffff);
					break;
				}
				case CMDL_U8: {
					u8 *p = info[idx].wanted_val;
					*p = get_uint_range(argp[i], 0, 0xff);
					break;
				}
				case CMDL_U16: {
					u16 *p = info[idx].wanted_val;
					*p = get_uint_range(argp[i], 0, 0xffff);
					break;
				}
				case CMDL_U32: {
					u32 *p = info[idx].wanted_val;
					*p = get_uint_range(argp[i], 0,
							    0xffffffff);
					break;
				}
				case CMDL_U64: {
					u64 *p = info[idx].wanted_val;
					*p = get_uint_range(
						argp[i], 0,
						0xffffffffffffffffLL);
					break;
				}
				case CMDL_BE16: {
					u16 *p = info[idx].wanted_val;
					*p = cpu_to_be16(
						get_uint_range(argp[i], 0,
							       0xffff));
					break;
				}
				case CMDL_IP4: {
					u32 *p = info[idx].wanted_val;
					struct in_addr in;
					if (!inet_aton(argp[i], &in))
						exit_bad_args();
					*p = in.s_addr;
					break;
				}
				case CMDL_MAC:
					get_mac_addr(argp[i],
						     info[idx].wanted_val);
					break;
				case CMDL_FLAG: {
					u32 *p;
					p = info[idx].seen_val;
					*p |= info[idx].flag_val;
					if (!strcmp(argp[i], "on")) {
						p = info[idx].wanted_val;
						*p |= info[idx].flag_val;
					} else if (strcmp(argp[i], "off")) {
						exit_bad_args();
					}
					break;
				}
				case CMDL_STR: {
					char **s = info[idx].wanted_val;
					*s = strdup(argp[i]);
					break;
				}
				default:
					exit_bad_args();
				}
				break;
			}
		}
		if( !found)
			exit_bad_args();
	}
}

static void flag_to_cmdline_info(const char *name, u32 value,
				 u32 *wanted, u32 *mask,
				 struct cmdline_info *cli)
{
	memset(cli, 0, sizeof(*cli));
	cli->name = name;
	cli->type = CMDL_FLAG;
	cli->flag_val = value;
	cli->wanted_val = wanted;
	cli->seen_val = mask;
}

static void
print_flags(const struct flag_info *info, unsigned int n_info, u32 value)
{
	const char *sep = "";

	while (n_info) {
		if (value & info->value) {
			printf("%s%s", sep, info->name);
			sep = " ";
			value &= ~info->value;
		}
		++info;
		--n_info;
	}

	/* Print any unrecognised flags in hex */
	if (value)
		printf("%s%#x", sep, value);
}

static int rxflow_str_to_type(const char *str)
{
	int flow_type = 0;

	if (!strcmp(str, "tcp4"))
		flow_type = TCP_V4_FLOW;
	else if (!strcmp(str, "udp4"))
		flow_type = UDP_V4_FLOW;
	else if (!strcmp(str, "ah4") || !strcmp(str, "esp4"))
		flow_type = AH_ESP_V4_FLOW;
	else if (!strcmp(str, "sctp4"))
		flow_type = SCTP_V4_FLOW;
	else if (!strcmp(str, "tcp6"))
		flow_type = TCP_V6_FLOW;
	else if (!strcmp(str, "udp6"))
		flow_type = UDP_V6_FLOW;
	else if (!strcmp(str, "ah6") || !strcmp(str, "esp6"))
		flow_type = AH_ESP_V6_FLOW;
	else if (!strcmp(str, "sctp6"))
		flow_type = SCTP_V6_FLOW;
	else if (!strcmp(str, "ether"))
		flow_type = ETHER_FLOW;

	return flow_type;
}

static int do_version(struct cmd_context *ctx)
{
	fprintf(stdout,
		PACKAGE " version " VERSION "\n");
	return 0;
}

static void dump_link_caps(const char *prefix, const char *an_prefix, u32 mask);

static void dump_supported(struct ethtool_cmd *ep)
{
	u32 mask = ep->supported;

	fprintf(stdout, "	Supported ports: [ ");
	if (mask & SUPPORTED_TP)
		fprintf(stdout, "TP ");
	if (mask & SUPPORTED_AUI)
		fprintf(stdout, "AUI ");
	if (mask & SUPPORTED_BNC)
		fprintf(stdout, "BNC ");
	if (mask & SUPPORTED_MII)
		fprintf(stdout, "MII ");
	if (mask & SUPPORTED_FIBRE)
		fprintf(stdout, "FIBRE ");
	fprintf(stdout, "]\n");

	dump_link_caps("Supported", "Supports", mask);
}

/* Print link capability flags (supported, advertised or lp_advertised).
 * Assumes that the corresponding SUPPORTED and ADVERTISED flags are equal.
 */
static void
dump_link_caps(const char *prefix, const char *an_prefix, u32 mask)
{
	int indent;
	int did1;

	/* Indent just like the separate functions used to */
	indent = strlen(prefix) + 14;
	if (indent < 24)
		indent = 24;

	fprintf(stdout, "	%s link modes:%*s", prefix,
		indent - (int)strlen(prefix) - 12, "");
	did1 = 0;
	if (mask & ADVERTISED_10baseT_Half) {
		did1++; fprintf(stdout, "10baseT/Half ");
	}
	if (mask & ADVERTISED_10baseT_Full) {
		did1++; fprintf(stdout, "10baseT/Full ");
	}
	if (did1 && (mask & (ADVERTISED_100baseT_Half|ADVERTISED_100baseT_Full))) {
		fprintf(stdout, "\n");
		fprintf(stdout, "	%*s", indent, "");
	}
	if (mask & ADVERTISED_100baseT_Half) {
		did1++; fprintf(stdout, "100baseT/Half ");
	}
	if (mask & ADVERTISED_100baseT_Full) {
		did1++; fprintf(stdout, "100baseT/Full ");
	}
	if (did1 && (mask & (ADVERTISED_1000baseT_Half|ADVERTISED_1000baseT_Full))) {
		fprintf(stdout, "\n");
		fprintf(stdout, "	%*s", indent, "");
	}
	if (mask & ADVERTISED_1000baseT_Half) {
		did1++; fprintf(stdout, "1000baseT/Half ");
	}
	if (mask & ADVERTISED_1000baseT_Full) {
		did1++; fprintf(stdout, "1000baseT/Full ");
	}
	if (did1 && (mask & ADVERTISED_2500baseX_Full)) {
		fprintf(stdout, "\n");
		fprintf(stdout, "	%*s", indent, "");
	}
	if (mask & ADVERTISED_2500baseX_Full) {
		did1++; fprintf(stdout, "2500baseX/Full ");
	}
	if (did1 && (mask & ADVERTISED_10000baseT_Full)) {
		fprintf(stdout, "\n");
		fprintf(stdout, "	%*s", indent, "");
	}
	if (mask & ADVERTISED_10000baseT_Full) {
		did1++; fprintf(stdout, "10000baseT/Full ");
	}
	if (did1 && (mask & ADVERTISED_20000baseMLD2_Full)) {
		fprintf(stdout, "\n");
		fprintf(stdout, "	%*s", indent, "");
	}
	if (mask & ADVERTISED_20000baseMLD2_Full) {
		did1++; fprintf(stdout, "20000baseMLD2/Full ");
	}
	if (did1 && (mask & ADVERTISED_20000baseKR2_Full)) {
		fprintf(stdout, "\n");
		fprintf(stdout, "	%*s", indent, "");
	}
	if (mask & ADVERTISED_20000baseKR2_Full) {
		did1++; fprintf(stdout, "20000baseKR2/Full ");
	}
	if (did1 == 0)
		 fprintf(stdout, "Not reported");
	fprintf(stdout, "\n");

	fprintf(stdout, "	%s pause frame use: ", prefix);
	if (mask & ADVERTISED_Pause) {
		fprintf(stdout, "Symmetric");
		if (mask & ADVERTISED_Asym_Pause)
			fprintf(stdout, " Receive-only");
		fprintf(stdout, "\n");
	} else {
		if (mask & ADVERTISED_Asym_Pause)
			fprintf(stdout, "Transmit-only\n");
		else
			fprintf(stdout, "No\n");
	}

	fprintf(stdout, "	%s auto-negotiation: ", an_prefix);
	if (mask & ADVERTISED_Autoneg)
		fprintf(stdout, "Yes\n");
	else
		fprintf(stdout, "No\n");
}

static int dump_ecmd(struct ethtool_cmd *ep)
{
	u32 speed;

	dump_supported(ep);
	dump_link_caps("Advertised", "Advertised", ep->advertising);
	if (ep->lp_advertising)
		dump_link_caps("Link partner advertised",
			       "Link partner advertised", ep->lp_advertising);

	fprintf(stdout, "	Speed: ");
	speed = ethtool_cmd_speed(ep);
	if (speed == 0 || speed == (u16)(-1) || speed == (u32)(-1))
		fprintf(stdout, "Unknown!\n");
	else
		fprintf(stdout, "%uMb/s\n", speed);

	fprintf(stdout, "	Duplex: ");
	switch (ep->duplex) {
	case DUPLEX_HALF:
		fprintf(stdout, "Half\n");
		break;
	case DUPLEX_FULL:
		fprintf(stdout, "Full\n");
		break;
	default:
		fprintf(stdout, "Unknown! (%i)\n", ep->duplex);
		break;
	};

	fprintf(stdout, "	Port: ");
	switch (ep->port) {
	case PORT_TP:
		fprintf(stdout, "Twisted Pair\n");
		break;
	case PORT_AUI:
		fprintf(stdout, "AUI\n");
		break;
	case PORT_BNC:
		fprintf(stdout, "BNC\n");
		break;
	case PORT_MII:
		fprintf(stdout, "MII\n");
		break;
	case PORT_FIBRE:
		fprintf(stdout, "FIBRE\n");
		break;
	case PORT_DA:
		fprintf(stdout, "Direct Attach Copper\n");
		break;
	case PORT_NONE:
		fprintf(stdout, "None\n");
		break;
	case PORT_OTHER:
		fprintf(stdout, "Other\n");
		break;
	default:
		fprintf(stdout, "Unknown! (%i)\n", ep->port);
		break;
	};

	fprintf(stdout, "	PHYAD: %d\n", ep->phy_address);
	fprintf(stdout, "	Transceiver: ");
	switch (ep->transceiver) {
	case XCVR_INTERNAL:
		fprintf(stdout, "internal\n");
		break;
	case XCVR_EXTERNAL:
		fprintf(stdout, "external\n");
		break;
	default:
		fprintf(stdout, "Unknown!\n");
		break;
	};

	fprintf(stdout, "	Auto-negotiation: %s\n",
		(ep->autoneg == AUTONEG_DISABLE) ?
		"off" : "on");

	if (ep->port == PORT_TP) {
		fprintf(stdout, "	MDI-X: ");
		switch (ep->eth_tp_mdix) {
		case ETH_TP_MDI:
			fprintf(stdout, "off\n");
			break;
		case ETH_TP_MDI_X:
			fprintf(stdout, "on\n");
			break;
		default:
			fprintf(stdout, "Unknown\n");
			break;
		}
	}

	return 0;
}

static int dump_drvinfo(struct ethtool_drvinfo *info)
{
	fprintf(stdout,
		"driver: %s\n"
		"version: %s\n"
		"firmware-version: %s\n"
		"bus-info: %s\n"
		"supports-statistics: %s\n"
		"supports-test: %s\n"
		"supports-eeprom-access: %s\n"
		"supports-register-dump: %s\n"
		"supports-priv-flags: %s\n",
		info->driver,
		info->version,
		info->fw_version,
		info->bus_info,
		info->n_stats ? "yes" : "no",
		info->testinfo_len ? "yes" : "no",
		info->eedump_len ? "yes" : "no",
		info->regdump_len ? "yes" : "no",
		info->n_priv_flags ? "yes" : "no");

	return 0;
}

static int parse_wolopts(char *optstr, u32 *data)
{
	*data = 0;
	while (*optstr) {
		switch (*optstr) {
			case 'p':
				*data |= WAKE_PHY;
				break;
			case 'u':
				*data |= WAKE_UCAST;
				break;
			case 'm':
				*data |= WAKE_MCAST;
				break;
			case 'b':
				*data |= WAKE_BCAST;
				break;
			case 'a':
				*data |= WAKE_ARP;
				break;
			case 'g':
				*data |= WAKE_MAGIC;
				break;
			case 's':
				*data |= WAKE_MAGICSECURE;
				break;
			case 'd':
				*data = 0;
				break;
			default:
				return -1;
		}
		optstr++;
	}
	return 0;
}

static char *unparse_wolopts(int wolopts)
{
	static char buf[16];
	char *p = buf;

	memset(buf, 0, sizeof(buf));

	if (wolopts) {
		if (wolopts & WAKE_PHY)
			*p++ = 'p';
		if (wolopts & WAKE_UCAST)
			*p++ = 'u';
		if (wolopts & WAKE_MCAST)
			*p++ = 'm';
		if (wolopts & WAKE_BCAST)
			*p++ = 'b';
		if (wolopts & WAKE_ARP)
			*p++ = 'a';
		if (wolopts & WAKE_MAGIC)
			*p++ = 'g';
		if (wolopts & WAKE_MAGICSECURE)
			*p++ = 's';
	} else {
		*p = 'd';
	}

	return buf;
}

static int dump_wol(struct ethtool_wolinfo *wol)
{
	fprintf(stdout, "	Supports Wake-on: %s\n",
		unparse_wolopts(wol->supported));
	fprintf(stdout, "	Wake-on: %s\n",
		unparse_wolopts(wol->wolopts));
	if (wol->supported & WAKE_MAGICSECURE) {
		int i;
		int delim = 0;
		fprintf(stdout, "        SecureOn password: ");
		for (i = 0; i < SOPASS_MAX; i++) {
			fprintf(stdout, "%s%02x", delim?":":"", wol->sopass[i]);
			delim=1;
		}
		fprintf(stdout, "\n");
	}

	return 0;
}

static int parse_rxfhashopts(char *optstr, u32 *data)
{
	*data = 0;
	while (*optstr) {
		switch (*optstr) {
			case 'm':
				*data |= RXH_L2DA;
				break;
			case 'v':
				*data |= RXH_VLAN;
				break;
			case 't':
				*data |= RXH_L3_PROTO;
				break;
			case 's':
				*data |= RXH_IP_SRC;
				break;
			case 'd':
				*data |= RXH_IP_DST;
				break;
			case 'f':
				*data |= RXH_L4_B_0_1;
				break;
			case 'n':
				*data |= RXH_L4_B_2_3;
				break;
			case 'r':
				*data |= RXH_DISCARD;
				break;
			default:
				return -1;
		}
		optstr++;
	}
	return 0;
}

static char *unparse_rxfhashopts(u64 opts)
{
	static char buf[300];

	memset(buf, 0, sizeof(buf));

	if (opts) {
		if (opts & RXH_L2DA) {
			strcat(buf, "L2DA\n");
		}
		if (opts & RXH_VLAN) {
			strcat(buf, "VLAN tag\n");
		}
		if (opts & RXH_L3_PROTO) {
			strcat(buf, "L3 proto\n");
		}
		if (opts & RXH_IP_SRC) {
			strcat(buf, "IP SA\n");
		}
		if (opts & RXH_IP_DST) {
			strcat(buf, "IP DA\n");
		}
		if (opts & RXH_L4_B_0_1) {
			strcat(buf, "L4 bytes 0 & 1 [TCP/UDP src port]\n");
		}
		if (opts & RXH_L4_B_2_3) {
			strcat(buf, "L4 bytes 2 & 3 [TCP/UDP dst port]\n");
		}
	} else {
		sprintf(buf, "None");
	}

	return buf;
}

static const struct {
	const char *name;
	int (*func)(struct ethtool_drvinfo *info, struct ethtool_regs *regs);

} driver_list[] = {
	{ "8139cp", realtek_dump_regs },
	{ "8139too", realtek_dump_regs },
	{ "r8169", realtek_dump_regs },
	{ "de2104x", de2104x_dump_regs },
	{ "e1000", e1000_dump_regs },
	{ "e1000e", e1000_dump_regs },
	{ "igb", igb_dump_regs },
	{ "ixgb", ixgb_dump_regs },
	{ "ixgbe", ixgbe_dump_regs },
	{ "natsemi", natsemi_dump_regs },
	{ "e100", e100_dump_regs },
	{ "amd8111e", amd8111e_dump_regs },
	{ "pcnet32", pcnet32_dump_regs },
	{ "fec_8xx", fec_8xx_dump_regs },
	{ "ibm_emac", ibm_emac_dump_regs },
	{ "tg3", tg3_dump_regs },
	{ "skge", skge_dump_regs },
	{ "sky2", sky2_dump_regs },
        { "vioc", vioc_dump_regs },
        { "smsc911x", smsc911x_dump_regs },
        { "at76c50x-usb", at76c50x_usb_dump_regs },
        { "sfc", sfc_dump_regs },
	{ "st_mac100", st_mac100_dump_regs },
	{ "st_gmac", st_gmac_dump_regs },
};

static int dump_regs(int gregs_dump_raw, int gregs_dump_hex,
		     const char *gregs_dump_file,
		     struct ethtool_drvinfo *info, struct ethtool_regs *regs)
{
	int i;

	if (gregs_dump_raw) {
		fwrite(regs->data, regs->len, 1, stdout);
		return 0;
	}

	if (gregs_dump_file) {
		FILE *f = fopen(gregs_dump_file, "r");
		struct stat st;

		if (!f || fstat(fileno(f), &st) < 0) {
			fprintf(stderr, "Can't open '%s': %s\n",
				gregs_dump_file, strerror(errno));
			return -1;
		}

		regs = realloc(regs, sizeof(*regs) + st.st_size);
		regs->len = st.st_size;
		fread(regs->data, regs->len, 1, f);
		fclose(f);
	}

	if (!gregs_dump_hex)
		for (i = 0; i < ARRAY_SIZE(driver_list); i++)
			if (!strncmp(driver_list[i].name, info->driver,
				     ETHTOOL_BUSINFO_LEN))
				return driver_list[i].func(info, regs);

	fprintf(stdout, "Offset\tValues\n");
	fprintf(stdout, "--------\t-----");
	for (i = 0; i < regs->len; i++) {
		if (i%16 == 0)
			fprintf(stdout, "\n%03x:\t", i);
		fprintf(stdout, " %02x", regs->data[i]);
	}
	fprintf(stdout, "\n\n");
	return 0;
}

static int dump_eeprom(int geeprom_dump_raw, struct ethtool_drvinfo *info,
		       struct ethtool_eeprom *ee)
{
	int i;

	if (geeprom_dump_raw) {
		fwrite(ee->data, 1, ee->len, stdout);
		return 0;
	}

	if (!strncmp("natsemi", info->driver, ETHTOOL_BUSINFO_LEN)) {
		return natsemi_dump_eeprom(info, ee);
	} else if (!strncmp("tg3", info->driver, ETHTOOL_BUSINFO_LEN)) {
		return tg3_dump_eeprom(info, ee);
	}

	fprintf(stdout, "Offset\t\tValues\n");
	fprintf(stdout, "------\t\t------");
	for (i = 0; i < ee->len; i++) {
		if(!(i%16)) fprintf(stdout, "\n0x%04x\t\t", i + ee->offset);
		fprintf(stdout, "%02x ", ee->data[i]);
	}
	fprintf(stdout, "\n");
	return 0;
}

static int dump_test(struct ethtool_test *test,
		     struct ethtool_gstrings *strings)
{
	int i, rc;

	rc = test->flags & ETH_TEST_FL_FAILED;
	fprintf(stdout, "The test result is %s\n", rc ? "FAIL" : "PASS");

	if (test->flags & ETH_TEST_FL_EXTERNAL_LB)
		fprintf(stdout, "External loopback test was %sexecuted\n",
			(test->flags & ETH_TEST_FL_EXTERNAL_LB_DONE) ?
			"" : "not ");

	if (strings->len)
		fprintf(stdout, "The test extra info:\n");

	for (i = 0; i < strings->len; i++) {
		fprintf(stdout, "%s\t %d\n",
			(char *)(strings->data + i * ETH_GSTRING_LEN),
			(u32) test->data[i]);
	}

	fprintf(stdout, "\n");
	return rc;
}

static int dump_pause(const struct ethtool_pauseparam *epause,
		      u32 advertising, u32 lp_advertising)
{
	fprintf(stdout,
		"Autonegotiate:	%s\n"
		"RX:		%s\n"
		"TX:		%s\n",
		epause->autoneg ? "on" : "off",
		epause->rx_pause ? "on" : "off",
		epause->tx_pause ? "on" : "off");

	if (lp_advertising) {
		int an_rx = 0, an_tx = 0;

		/* Work out negotiated pause frame usage per
		 * IEEE 802.3-2005 table 28B-3.
		 */
		if (advertising & lp_advertising & ADVERTISED_Pause) {
			an_tx = 1;
			an_rx = 1;
		} else if (advertising & lp_advertising &
			   ADVERTISED_Asym_Pause) {
			if (advertising & ADVERTISED_Pause)
				an_rx = 1;
			else if (lp_advertising & ADVERTISED_Pause)
				an_tx = 1;
		}

		fprintf(stdout,
			"RX negotiated:	%s\n"
			"TX negotiated:	%s\n",
			an_rx ? "on" : "off",
			an_tx ? "on" : "off");
	}

	fprintf(stdout, "\n");
	return 0;
}

static int dump_ring(const struct ethtool_ringparam *ering)
{
	fprintf(stdout,
		"Pre-set maximums:\n"
		"RX:		%u\n"
		"RX Mini:	%u\n"
		"RX Jumbo:	%u\n"
		"TX:		%u\n",
		ering->rx_max_pending,
		ering->rx_mini_max_pending,
		ering->rx_jumbo_max_pending,
		ering->tx_max_pending);

	fprintf(stdout,
		"Current hardware settings:\n"
		"RX:		%u\n"
		"RX Mini:	%u\n"
		"RX Jumbo:	%u\n"
		"TX:		%u\n",
		ering->rx_pending,
		ering->rx_mini_pending,
		ering->rx_jumbo_pending,
		ering->tx_pending);

	fprintf(stdout, "\n");
	return 0;
}

static int dump_channels(const struct ethtool_channels *echannels)
{
	fprintf(stdout,
		"Pre-set maximums:\n"
		"RX:		%u\n"
		"TX:		%u\n"
		"Other:		%u\n"
		"Combined:	%u\n",
		echannels->max_rx, echannels->max_tx,
		echannels->max_other,
		echannels->max_combined);

	fprintf(stdout,
		"Current hardware settings:\n"
		"RX:		%u\n"
		"TX:		%u\n"
		"Other:		%u\n"
		"Combined:	%u\n",
		echannels->rx_count, echannels->tx_count,
		echannels->other_count,
		echannels->combined_count);

	fprintf(stdout, "\n");
	return 0;
}

static int dump_coalesce(const struct ethtool_coalesce *ecoal)
{
	fprintf(stdout, "Adaptive RX: %s  TX: %s\n",
		ecoal->use_adaptive_rx_coalesce ? "on" : "off",
		ecoal->use_adaptive_tx_coalesce ? "on" : "off");

	fprintf(stdout,
		"stats-block-usecs: %u\n"
		"sample-interval: %u\n"
		"pkt-rate-low: %u\n"
		"pkt-rate-high: %u\n"
		"\n"
		"rx-usecs: %u\n"
		"rx-frames: %u\n"
		"rx-usecs-irq: %u\n"
		"rx-frames-irq: %u\n"
		"\n"
		"tx-usecs: %u\n"
		"tx-frames: %u\n"
		"tx-usecs-irq: %u\n"
		"tx-frames-irq: %u\n"
		"\n"
		"rx-usecs-low: %u\n"
		"rx-frame-low: %u\n"
		"tx-usecs-low: %u\n"
		"tx-frame-low: %u\n"
		"\n"
		"rx-usecs-high: %u\n"
		"rx-frame-high: %u\n"
		"tx-usecs-high: %u\n"
		"tx-frame-high: %u\n"
		"\n",
		ecoal->stats_block_coalesce_usecs,
		ecoal->rate_sample_interval,
		ecoal->pkt_rate_low,
		ecoal->pkt_rate_high,

		ecoal->rx_coalesce_usecs,
		ecoal->rx_max_coalesced_frames,
		ecoal->rx_coalesce_usecs_irq,
		ecoal->rx_max_coalesced_frames_irq,

		ecoal->tx_coalesce_usecs,
		ecoal->tx_max_coalesced_frames,
		ecoal->tx_coalesce_usecs_irq,
		ecoal->tx_max_coalesced_frames_irq,

		ecoal->rx_coalesce_usecs_low,
		ecoal->rx_max_coalesced_frames_low,
		ecoal->tx_coalesce_usecs_low,
		ecoal->tx_max_coalesced_frames_low,

		ecoal->rx_coalesce_usecs_high,
		ecoal->rx_max_coalesced_frames_high,
		ecoal->tx_coalesce_usecs_high,
		ecoal->tx_max_coalesced_frames_high);

	return 0;
}

static int dump_offload(int rx, int tx, int sg, int tso, int ufo, int gso,
			int gro, int lro, int rxvlan, int txvlan, int ntuple,
			int rxhash)
{
	fprintf(stdout,
		"rx-checksumming: %s\n"
		"tx-checksumming: %s\n"
		"scatter-gather: %s\n"
		"tcp-segmentation-offload: %s\n"
		"udp-fragmentation-offload: %s\n"
		"generic-segmentation-offload: %s\n"
		"generic-receive-offload: %s\n"
		"large-receive-offload: %s\n"
		"rx-vlan-offload: %s\n"
		"tx-vlan-offload: %s\n"
		"ntuple-filters: %s\n"
		"receive-hashing: %s\n",
		rx ? "on" : "off",
		tx ? "on" : "off",
		sg ? "on" : "off",
		tso ? "on" : "off",
		ufo ? "on" : "off",
		gso ? "on" : "off",
		gro ? "on" : "off",
		lro ? "on" : "off",
		rxvlan ? "on" : "off",
		txvlan ? "on" : "off",
		ntuple ? "on" : "off",
		rxhash ? "on" : "off");

	return 0;
}

static int dump_rxfhash(int fhash, u64 val)
{
	switch (fhash) {
	case TCP_V4_FLOW:
		fprintf(stdout, "TCP over IPV4 flows");
		break;
	case UDP_V4_FLOW:
		fprintf(stdout, "UDP over IPV4 flows");
		break;
	case SCTP_V4_FLOW:
		fprintf(stdout, "SCTP over IPV4 flows");
		break;
	case AH_ESP_V4_FLOW:
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
		fprintf(stdout, "IPSEC AH/ESP over IPV4 flows");
		break;
	case TCP_V6_FLOW:
		fprintf(stdout, "TCP over IPV6 flows");
		break;
	case UDP_V6_FLOW:
		fprintf(stdout, "UDP over IPV6 flows");
		break;
	case SCTP_V6_FLOW:
		fprintf(stdout, "SCTP over IPV6 flows");
		break;
	case AH_ESP_V6_FLOW:
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
		fprintf(stdout, "IPSEC AH/ESP over IPV6 flows");
		break;
	default:
		break;
	}

	if (val & RXH_DISCARD) {
		fprintf(stdout, " - All matching flows discarded on RX\n");
		return 0;
	}
	fprintf(stdout, " use these fields for computing Hash flow key:\n");

	fprintf(stdout, "%s\n", unparse_rxfhashopts(val));

	return 0;
}

static struct ethtool_gstrings *
get_stringset(struct cmd_context *ctx, enum ethtool_stringset set_id,
	      ptrdiff_t drvinfo_offset)
{
	struct {
		struct ethtool_sset_info hdr;
		u32 buf[1];
	} sset_info;
	struct ethtool_drvinfo drvinfo;
	u32 len;
	struct ethtool_gstrings *strings;

	sset_info.hdr.cmd = ETHTOOL_GSSET_INFO;
	sset_info.hdr.reserved = 0;
	sset_info.hdr.sset_mask = 1ULL << set_id;
	if (send_ioctl(ctx, &sset_info) == 0) {
		len = sset_info.hdr.sset_mask ? sset_info.hdr.data[0] : 0;
	} else if (errno == EOPNOTSUPP && drvinfo_offset != 0) {
		/* Fallback for old kernel versions */
		drvinfo.cmd = ETHTOOL_GDRVINFO;
		if (send_ioctl(ctx, &drvinfo))
			return NULL;
		len = *(u32 *)((char *)&drvinfo + drvinfo_offset);
	} else {
		return NULL;
	}

	strings = calloc(1, sizeof(*strings) + len * ETH_GSTRING_LEN);
	if (!strings)
		return NULL;

	strings->cmd = ETHTOOL_GSTRINGS;
	strings->string_set = set_id;
	strings->len = len;
	if (len != 0 && send_ioctl(ctx, strings)) {
		free(strings);
		return NULL;
	}

	return strings;
}

static int do_gdrv(struct cmd_context *ctx)
{
	int err;
	struct ethtool_drvinfo drvinfo;

	if (ctx->argc != 0)
		exit_bad_args();

	drvinfo.cmd = ETHTOOL_GDRVINFO;
	err = send_ioctl(ctx, &drvinfo);
	if (err < 0) {
		perror("Cannot get driver information");
		return 71;
	}
	return dump_drvinfo(&drvinfo);
}

static int do_gpause(struct cmd_context *ctx)
{
	struct ethtool_pauseparam epause;
	struct ethtool_cmd ecmd;
	int err;

	if (ctx->argc != 0)
		exit_bad_args();

	fprintf(stdout, "Pause parameters for %s:\n", ctx->devname);

	epause.cmd = ETHTOOL_GPAUSEPARAM;
	err = send_ioctl(ctx, &epause);
	if (err) {
		perror("Cannot get device pause settings");
		return 76;
	}

	if (epause.autoneg) {
		ecmd.cmd = ETHTOOL_GSET;
		err = send_ioctl(ctx, &ecmd);
		if (err) {
			perror("Cannot get device settings");
			return 1;
		}
		dump_pause(&epause, ecmd.advertising, ecmd.lp_advertising);
	} else {
		dump_pause(&epause, 0, 0);
	}

	return 0;
}

static void do_generic_set1(struct cmdline_info *info, int *changed_out)
{
	int wanted, *v1, *v2;

	v1 = info->wanted_val;
	wanted = *v1;

	if (wanted < 0)
		return;

	v2 = info->ioctl_val;
	if (wanted == *v2) {
		fprintf(stderr, "%s unmodified, ignoring\n", info->name);
	} else {
		*v2 = wanted;
		*changed_out = 1;
	}
}

static void do_generic_set(struct cmdline_info *info,
			   unsigned int n_info,
			   int *changed_out)
{
	unsigned int i;

	for (i = 0; i < n_info; i++)
		do_generic_set1(&info[i], changed_out);
}

static int do_spause(struct cmd_context *ctx)
{
	struct ethtool_pauseparam epause;
	int gpause_changed = 0;
	int pause_autoneg_wanted = -1;
	int pause_rx_wanted = -1;
	int pause_tx_wanted = -1;
	struct cmdline_info cmdline_pause[] = {
		{ "autoneg", CMDL_BOOL, &pause_autoneg_wanted,
		  &epause.autoneg },
		{ "rx", CMDL_BOOL, &pause_rx_wanted, &epause.rx_pause },
		{ "tx", CMDL_BOOL, &pause_tx_wanted, &epause.tx_pause },
	};
	int err, changed = 0;

	parse_generic_cmdline(ctx, &gpause_changed,
			      cmdline_pause, ARRAY_SIZE(cmdline_pause));

	epause.cmd = ETHTOOL_GPAUSEPARAM;
	err = send_ioctl(ctx, &epause);
	if (err) {
		perror("Cannot get device pause settings");
		return 77;
	}

	do_generic_set(cmdline_pause, ARRAY_SIZE(cmdline_pause), &changed);

	if (!changed) {
		fprintf(stderr, "no pause parameters changed, aborting\n");
		return 78;
	}

	epause.cmd = ETHTOOL_SPAUSEPARAM;
	err = send_ioctl(ctx, &epause);
	if (err) {
		perror("Cannot set device pause parameters");
		return 79;
	}

	return 0;
}

static int do_sring(struct cmd_context *ctx)
{
	struct ethtool_ringparam ering;
	int gring_changed = 0;
	s32 ring_rx_wanted = -1;
	s32 ring_rx_mini_wanted = -1;
	s32 ring_rx_jumbo_wanted = -1;
	s32 ring_tx_wanted = -1;
	struct cmdline_info cmdline_ring[] = {
		{ "rx", CMDL_S32, &ring_rx_wanted, &ering.rx_pending },
		{ "rx-mini", CMDL_S32, &ring_rx_mini_wanted,
		  &ering.rx_mini_pending },
		{ "rx-jumbo", CMDL_S32, &ring_rx_jumbo_wanted,
		  &ering.rx_jumbo_pending },
		{ "tx", CMDL_S32, &ring_tx_wanted, &ering.tx_pending },
	};
	int err, changed = 0;

	parse_generic_cmdline(ctx, &gring_changed,
			      cmdline_ring, ARRAY_SIZE(cmdline_ring));

	ering.cmd = ETHTOOL_GRINGPARAM;
	err = send_ioctl(ctx, &ering);
	if (err) {
		perror("Cannot get device ring settings");
		return 76;
	}

	do_generic_set(cmdline_ring, ARRAY_SIZE(cmdline_ring), &changed);

	if (!changed) {
		fprintf(stderr, "no ring parameters changed, aborting\n");
		return 80;
	}

	ering.cmd = ETHTOOL_SRINGPARAM;
	err = send_ioctl(ctx, &ering);
	if (err) {
		perror("Cannot set device ring parameters");
		return 81;
	}

	return 0;
}

static int do_gring(struct cmd_context *ctx)
{
	struct ethtool_ringparam ering;
	int err;

	if (ctx->argc != 0)
		exit_bad_args();

	fprintf(stdout, "Ring parameters for %s:\n", ctx->devname);

	ering.cmd = ETHTOOL_GRINGPARAM;
	err = send_ioctl(ctx, &ering);
	if (err == 0) {
		err = dump_ring(&ering);
		if (err)
			return err;
	} else {
		perror("Cannot get device ring settings");
		return 76;
	}

	return 0;
}

static int do_schannels(struct cmd_context *ctx)
{
	struct ethtool_channels echannels;
	int gchannels_changed;
	s32 channels_rx_wanted = -1;
	s32 channels_tx_wanted = -1;
	s32 channels_other_wanted = -1;
	s32 channels_combined_wanted = -1;
	struct cmdline_info cmdline_channels[] = {
		{ "rx", CMDL_S32, &channels_rx_wanted, &echannels.rx_count },
		{ "tx", CMDL_S32, &channels_tx_wanted, &echannels.tx_count },
		{ "other", CMDL_S32, &channels_other_wanted,
		  &echannels.other_count },
		{ "combined", CMDL_S32, &channels_combined_wanted,
		  &echannels.combined_count },
	};
	int err, changed = 0;

	parse_generic_cmdline(ctx, &gchannels_changed,
			      cmdline_channels, ARRAY_SIZE(cmdline_channels));

	echannels.cmd = ETHTOOL_GCHANNELS;
	err = send_ioctl(ctx, &echannels);
	if (err) {
		perror("Cannot get device channel parameters");
		return 1;
	}

	do_generic_set(cmdline_channels, ARRAY_SIZE(cmdline_channels),
			&changed);

	if (!changed) {
		fprintf(stderr, "no channel parameters changed, aborting\n");
		fprintf(stderr, "current values: tx %u rx %u other %u"
			"combined %u\n", echannels.rx_count,
			echannels.tx_count, echannels.other_count,
			echannels.combined_count);
		return 1;
	}

	echannels.cmd = ETHTOOL_SCHANNELS;
	err = send_ioctl(ctx, &echannels);
	if (err) {
		perror("Cannot set device channel parameters");
		return 1;
	}

	return 0;
}

static int do_gchannels(struct cmd_context *ctx)
{
	struct ethtool_channels echannels;
	int err;

	if (ctx->argc != 0)
		exit_bad_args();

	fprintf(stdout, "Channel parameters for %s:\n", ctx->devname);

	echannels.cmd = ETHTOOL_GCHANNELS;
	err = send_ioctl(ctx, &echannels);
	if (err == 0) {
		err = dump_channels(&echannels);
		if (err)
			return err;
	} else {
		perror("Cannot get device channel parameters\n");
		return 1;
	}
	return 0;

}

static int do_gcoalesce(struct cmd_context *ctx)
{
	struct ethtool_coalesce ecoal;
	int err;

	if (ctx->argc != 0)
		exit_bad_args();

	fprintf(stdout, "Coalesce parameters for %s:\n", ctx->devname);

	ecoal.cmd = ETHTOOL_GCOALESCE;
	err = send_ioctl(ctx, &ecoal);
	if (err == 0) {
		err = dump_coalesce(&ecoal);
		if (err)
			return err;
	} else {
		perror("Cannot get device coalesce settings");
		return 82;
	}

	return 0;
}

static int do_scoalesce(struct cmd_context *ctx)
{
	struct ethtool_coalesce ecoal;
	int gcoalesce_changed = 0;
	s32 coal_stats_wanted = -1;
	int coal_adaptive_rx_wanted = -1;
	int coal_adaptive_tx_wanted = -1;
	s32 coal_sample_rate_wanted = -1;
	s32 coal_pkt_rate_low_wanted = -1;
	s32 coal_pkt_rate_high_wanted = -1;
	s32 coal_rx_usec_wanted = -1;
	s32 coal_rx_frames_wanted = -1;
	s32 coal_rx_usec_irq_wanted = -1;
	s32 coal_rx_frames_irq_wanted = -1;
	s32 coal_tx_usec_wanted = -1;
	s32 coal_tx_frames_wanted = -1;
	s32 coal_tx_usec_irq_wanted = -1;
	s32 coal_tx_frames_irq_wanted = -1;
	s32 coal_rx_usec_low_wanted = -1;
	s32 coal_rx_frames_low_wanted = -1;
	s32 coal_tx_usec_low_wanted = -1;
	s32 coal_tx_frames_low_wanted = -1;
	s32 coal_rx_usec_high_wanted = -1;
	s32 coal_rx_frames_high_wanted = -1;
	s32 coal_tx_usec_high_wanted = -1;
	s32 coal_tx_frames_high_wanted = -1;
	struct cmdline_info cmdline_coalesce[] = {
		{ "adaptive-rx", CMDL_BOOL, &coal_adaptive_rx_wanted,
		  &ecoal.use_adaptive_rx_coalesce },
		{ "adaptive-tx", CMDL_BOOL, &coal_adaptive_tx_wanted,
		  &ecoal.use_adaptive_tx_coalesce },
		{ "sample-interval", CMDL_S32, &coal_sample_rate_wanted,
		  &ecoal.rate_sample_interval },
		{ "stats-block-usecs", CMDL_S32, &coal_stats_wanted,
		  &ecoal.stats_block_coalesce_usecs },
		{ "pkt-rate-low", CMDL_S32, &coal_pkt_rate_low_wanted,
		  &ecoal.pkt_rate_low },
		{ "pkt-rate-high", CMDL_S32, &coal_pkt_rate_high_wanted,
		  &ecoal.pkt_rate_high },
		{ "rx-usecs", CMDL_S32, &coal_rx_usec_wanted,
		  &ecoal.rx_coalesce_usecs },
		{ "rx-frames", CMDL_S32, &coal_rx_frames_wanted,
		  &ecoal.rx_max_coalesced_frames },
		{ "rx-usecs-irq", CMDL_S32, &coal_rx_usec_irq_wanted,
		  &ecoal.rx_coalesce_usecs_irq },
		{ "rx-frames-irq", CMDL_S32, &coal_rx_frames_irq_wanted,
		  &ecoal.rx_max_coalesced_frames_irq },
		{ "tx-usecs", CMDL_S32, &coal_tx_usec_wanted,
		  &ecoal.tx_coalesce_usecs },
		{ "tx-frames", CMDL_S32, &coal_tx_frames_wanted,
		  &ecoal.tx_max_coalesced_frames },
		{ "tx-usecs-irq", CMDL_S32, &coal_tx_usec_irq_wanted,
		  &ecoal.tx_coalesce_usecs_irq },
		{ "tx-frames-irq", CMDL_S32, &coal_tx_frames_irq_wanted,
		  &ecoal.tx_max_coalesced_frames_irq },
		{ "rx-usecs-low", CMDL_S32, &coal_rx_usec_low_wanted,
		  &ecoal.rx_coalesce_usecs_low },
		{ "rx-frames-low", CMDL_S32, &coal_rx_frames_low_wanted,
		  &ecoal.rx_max_coalesced_frames_low },
		{ "tx-usecs-low", CMDL_S32, &coal_tx_usec_low_wanted,
		  &ecoal.tx_coalesce_usecs_low },
		{ "tx-frames-low", CMDL_S32, &coal_tx_frames_low_wanted,
		  &ecoal.tx_max_coalesced_frames_low },
		{ "rx-usecs-high", CMDL_S32, &coal_rx_usec_high_wanted,
		  &ecoal.rx_coalesce_usecs_high },
		{ "rx-frames-high", CMDL_S32, &coal_rx_frames_high_wanted,
		  &ecoal.rx_max_coalesced_frames_high },
		{ "tx-usecs-high", CMDL_S32, &coal_tx_usec_high_wanted,
		  &ecoal.tx_coalesce_usecs_high },
		{ "tx-frames-high", CMDL_S32, &coal_tx_frames_high_wanted,
		  &ecoal.tx_max_coalesced_frames_high },
	};
	int err, changed = 0;

	parse_generic_cmdline(ctx, &gcoalesce_changed,
			      cmdline_coalesce, ARRAY_SIZE(cmdline_coalesce));

	ecoal.cmd = ETHTOOL_GCOALESCE;
	err = send_ioctl(ctx, &ecoal);
	if (err) {
		perror("Cannot get device coalesce settings");
		return 76;
	}

	do_generic_set(cmdline_coalesce, ARRAY_SIZE(cmdline_coalesce),
		       &changed);

	if (!changed) {
		fprintf(stderr, "no coalesce parameters changed, aborting\n");
		return 80;
	}

	ecoal.cmd = ETHTOOL_SCOALESCE;
	err = send_ioctl(ctx, &ecoal);
	if (err) {
		perror("Cannot set device coalesce parameters");
		return 81;
	}

	return 0;
}

static int do_goffload(struct cmd_context *ctx)
{
	struct ethtool_value eval;
	int err, allfail = 1, rx = 0, tx = 0, sg = 0;
	int tso = 0, ufo = 0, gso = 0, gro = 0, lro = 0, rxvlan = 0, txvlan = 0,
	    ntuple = 0, rxhash = 0;

	if (ctx->argc != 0)
		exit_bad_args();

	fprintf(stdout, "Offload parameters for %s:\n", ctx->devname);

	eval.cmd = ETHTOOL_GRXCSUM;
	err = send_ioctl(ctx, &eval);
	if (err)
		perror("Cannot get device rx csum settings");
	else {
		rx = eval.data;
		allfail = 0;
	}

	eval.cmd = ETHTOOL_GTXCSUM;
	err = send_ioctl(ctx, &eval);
	if (err)
		perror("Cannot get device tx csum settings");
	else {
		tx = eval.data;
		allfail = 0;
	}

	eval.cmd = ETHTOOL_GSG;
	err = send_ioctl(ctx, &eval);
	if (err)
		perror("Cannot get device scatter-gather settings");
	else {
		sg = eval.data;
		allfail = 0;
	}

	eval.cmd = ETHTOOL_GTSO;
	err = send_ioctl(ctx, &eval);
	if (err)
		perror("Cannot get device tcp segmentation offload settings");
	else {
		tso = eval.data;
		allfail = 0;
	}

	eval.cmd = ETHTOOL_GUFO;
	err = send_ioctl(ctx, &eval);
	if (err)
		perror("Cannot get device udp large send offload settings");
	else {
		ufo = eval.data;
		allfail = 0;
	}

	eval.cmd = ETHTOOL_GGSO;
	err = send_ioctl(ctx, &eval);
	if (err)
		perror("Cannot get device generic segmentation offload settings");
	else {
		gso = eval.data;
		allfail = 0;
	}

	eval.cmd = ETHTOOL_GFLAGS;
	err = send_ioctl(ctx, &eval);
	if (err) {
		perror("Cannot get device flags");
	} else {
		lro = (eval.data & ETH_FLAG_LRO) != 0;
		rxvlan = (eval.data & ETH_FLAG_RXVLAN) != 0;
		txvlan = (eval.data & ETH_FLAG_TXVLAN) != 0;
		ntuple = (eval.data & ETH_FLAG_NTUPLE) != 0;
		rxhash = (eval.data & ETH_FLAG_RXHASH) != 0;
		allfail = 0;
	}

	eval.cmd = ETHTOOL_GGRO;
	err = send_ioctl(ctx, &eval);
	if (err)
		perror("Cannot get device GRO settings");
	else {
		gro = eval.data;
		allfail = 0;
	}

	if (allfail) {
		fprintf(stdout, "no offload info available\n");
		return 83;
	}

	return dump_offload(rx, tx, sg, tso, ufo, gso, gro, lro, rxvlan, txvlan,
			    ntuple, rxhash);
}

static int do_soffload(struct cmd_context *ctx)
{
	int goffload_changed = 0;
	int off_csum_rx_wanted = -1;
	int off_csum_tx_wanted = -1;
	int off_sg_wanted = -1;
	int off_tso_wanted = -1;
	int off_ufo_wanted = -1;
	int off_gso_wanted = -1;
	u32 off_flags_wanted = 0;
	u32 off_flags_mask = 0;
	int off_gro_wanted = -1;
	struct cmdline_info cmdline_offload[] = {
		{ "rx", CMDL_BOOL, &off_csum_rx_wanted, NULL },
		{ "tx", CMDL_BOOL, &off_csum_tx_wanted, NULL },
		{ "sg", CMDL_BOOL, &off_sg_wanted, NULL },
		{ "tso", CMDL_BOOL, &off_tso_wanted, NULL },
		{ "ufo", CMDL_BOOL, &off_ufo_wanted, NULL },
		{ "gso", CMDL_BOOL, &off_gso_wanted, NULL },
		{ "lro", CMDL_FLAG, &off_flags_wanted, NULL,
		  ETH_FLAG_LRO, &off_flags_mask },
		{ "gro", CMDL_BOOL, &off_gro_wanted, NULL },
		{ "rxvlan", CMDL_FLAG, &off_flags_wanted, NULL,
		  ETH_FLAG_RXVLAN, &off_flags_mask },
		{ "txvlan", CMDL_FLAG, &off_flags_wanted, NULL,
		  ETH_FLAG_TXVLAN, &off_flags_mask },
		{ "ntuple", CMDL_FLAG, &off_flags_wanted, NULL,
		  ETH_FLAG_NTUPLE, &off_flags_mask },
		{ "rxhash", CMDL_FLAG, &off_flags_wanted, NULL,
		  ETH_FLAG_RXHASH, &off_flags_mask },
	};
	struct ethtool_value eval;
	int err, changed = 0;

	parse_generic_cmdline(ctx, &goffload_changed,
			      cmdline_offload, ARRAY_SIZE(cmdline_offload));

	if (off_csum_rx_wanted >= 0) {
		changed = 1;
		eval.cmd = ETHTOOL_SRXCSUM;
		eval.data = (off_csum_rx_wanted == 1);
		err = send_ioctl(ctx, &eval);
		if (err) {
			perror("Cannot set device rx csum settings");
			return 84;
		}
	}

	if (off_csum_tx_wanted >= 0) {
		changed = 1;
		eval.cmd = ETHTOOL_STXCSUM;
		eval.data = (off_csum_tx_wanted == 1);
		err = send_ioctl(ctx, &eval);
		if (err) {
			perror("Cannot set device tx csum settings");
			return 85;
		}
	}

	if (off_sg_wanted >= 0) {
		changed = 1;
		eval.cmd = ETHTOOL_SSG;
		eval.data = (off_sg_wanted == 1);
		err = send_ioctl(ctx, &eval);
		if (err) {
			perror("Cannot set device scatter-gather settings");
			return 86;
		}
	}

	if (off_tso_wanted >= 0) {
		changed = 1;
		eval.cmd = ETHTOOL_STSO;
		eval.data = (off_tso_wanted == 1);
		err = send_ioctl(ctx, &eval);
		if (err) {
			perror("Cannot set device tcp segmentation offload settings");
			return 88;
		}
	}
	if (off_ufo_wanted >= 0) {
		changed = 1;
		eval.cmd = ETHTOOL_SUFO;
		eval.data = (off_ufo_wanted == 1);
		err = send_ioctl(ctx, &eval);
		if (err) {
			perror("Cannot set device udp large send offload settings");
			return 89;
		}
	}
	if (off_gso_wanted >= 0) {
		changed = 1;
		eval.cmd = ETHTOOL_SGSO;
		eval.data = (off_gso_wanted == 1);
		err = send_ioctl(ctx, &eval);
		if (err) {
			perror("Cannot set device generic segmentation offload settings");
			return 90;
		}
	}
	if (off_flags_mask) {
		changed = 1;
		eval.cmd = ETHTOOL_GFLAGS;
		eval.data = 0;
		err = send_ioctl(ctx, &eval);
		if (err) {
			perror("Cannot get device flag settings");
			return 91;
		}

		eval.cmd = ETHTOOL_SFLAGS;
		eval.data = ((eval.data & ~off_flags_mask) |
			     off_flags_wanted);

		err = send_ioctl(ctx, &eval);
		if (err) {
			perror("Cannot set device flag settings");
			return 92;
		}
	}
	if (off_gro_wanted >= 0) {
		changed = 1;
		eval.cmd = ETHTOOL_SGRO;
		eval.data = (off_gro_wanted == 1);
		err = send_ioctl(ctx, &eval);
		if (err) {
			perror("Cannot set device GRO settings");
			return 93;
		}
	}

	if (!changed) {
		fprintf(stdout, "no offload settings changed\n");
	}

	return 0;
}

static int do_gset(struct cmd_context *ctx)
{
	int err;
	struct ethtool_cmd ecmd;
	struct ethtool_wolinfo wolinfo;
	struct ethtool_value edata;
	int allfail = 1;

	if (ctx->argc != 0)
		exit_bad_args();

	fprintf(stdout, "Settings for %s:\n", ctx->devname);

	ecmd.cmd = ETHTOOL_GSET;
	err = send_ioctl(ctx, &ecmd);
	if (err == 0) {
		err = dump_ecmd(&ecmd);
		if (err)
			return err;
		allfail = 0;
	} else if (errno != EOPNOTSUPP) {
		perror("Cannot get device settings");
	}

	wolinfo.cmd = ETHTOOL_GWOL;
	err = send_ioctl(ctx, &wolinfo);
	if (err == 0) {
		err = dump_wol(&wolinfo);
		if (err)
			return err;
		allfail = 0;
	} else if (errno != EOPNOTSUPP) {
		perror("Cannot get wake-on-lan settings");
	}

	edata.cmd = ETHTOOL_GMSGLVL;
	err = send_ioctl(ctx, &edata);
	if (err == 0) {
		fprintf(stdout, "	Current message level: 0x%08x (%d)\n"
			"			       ",
			edata.data, edata.data);
		print_flags(flags_msglvl, ARRAY_SIZE(flags_msglvl),
			    edata.data);
		fprintf(stdout, "\n");
		allfail = 0;
	} else if (errno != EOPNOTSUPP) {
		perror("Cannot get message level");
	}

	edata.cmd = ETHTOOL_GLINK;
	err = send_ioctl(ctx, &edata);
	if (err == 0) {
		fprintf(stdout, "	Link detected: %s\n",
			edata.data ? "yes":"no");
		allfail = 0;
	} else if (errno != EOPNOTSUPP) {
		perror("Cannot get link status");
	}

	if (allfail) {
		fprintf(stdout, "No data available\n");
		return 75;
	}
	return 0;
}

static int do_sset(struct cmd_context *ctx)
{
	int speed_wanted = -1;
	int duplex_wanted = -1;
	int port_wanted = -1;
	int autoneg_wanted = -1;
	int phyad_wanted = -1;
	int xcvr_wanted = -1;
	int advertising_wanted = -1;
	int gset_changed = 0; /* did anything in GSET change? */
	u32 wol_wanted = 0;
	int wol_change = 0;
	u8 sopass_wanted[SOPASS_MAX];
	int sopass_change = 0;
	int gwol_changed = 0; /* did anything in GWOL change? */
	int msglvl_changed = 0;
	u32 msglvl_wanted = 0;
	u32 msglvl_mask = 0;
	struct cmdline_info cmdline_msglvl[ARRAY_SIZE(flags_msglvl)];
	int argc = ctx->argc;
	char **argp = ctx->argp;
	int i;
	int err;

	for (i = 0; i < ARRAY_SIZE(flags_msglvl); i++)
		flag_to_cmdline_info(flags_msglvl[i].name,
				     flags_msglvl[i].value,
				     &msglvl_wanted, &msglvl_mask,
				     &cmdline_msglvl[i]);

	for (i = 0; i < argc; i++) {
		if (!strcmp(argp[i], "speed")) {
			gset_changed = 1;
			i += 1;
			if (i >= argc)
				exit_bad_args();
			speed_wanted = get_int(argp[i],10);
		} else if (!strcmp(argp[i], "duplex")) {
			gset_changed = 1;
			i += 1;
			if (i >= argc)
				exit_bad_args();
			if (!strcmp(argp[i], "half"))
				duplex_wanted = DUPLEX_HALF;
			else if (!strcmp(argp[i], "full"))
				duplex_wanted = DUPLEX_FULL;
			else
				exit_bad_args();
		} else if (!strcmp(argp[i], "port")) {
			gset_changed = 1;
			i += 1;
			if (i >= argc)
				exit_bad_args();
			if (!strcmp(argp[i], "tp"))
				port_wanted = PORT_TP;
			else if (!strcmp(argp[i], "aui"))
				port_wanted = PORT_AUI;
			else if (!strcmp(argp[i], "bnc"))
				port_wanted = PORT_BNC;
			else if (!strcmp(argp[i], "mii"))
				port_wanted = PORT_MII;
			else if (!strcmp(argp[i], "fibre"))
				port_wanted = PORT_FIBRE;
			else
				exit_bad_args();
		} else if (!strcmp(argp[i], "autoneg")) {
			i += 1;
			if (i >= argc)
				exit_bad_args();
			if (!strcmp(argp[i], "on")) {
				gset_changed = 1;
				autoneg_wanted = AUTONEG_ENABLE;
			} else if (!strcmp(argp[i], "off")) {
				gset_changed = 1;
				autoneg_wanted = AUTONEG_DISABLE;
			} else {
				exit_bad_args();
			}
		} else if (!strcmp(argp[i], "advertise")) {
			gset_changed = 1;
			i += 1;
			if (i >= argc)
				exit_bad_args();
			advertising_wanted = get_int(argp[i], 16);
		} else if (!strcmp(argp[i], "phyad")) {
			gset_changed = 1;
			i += 1;
			if (i >= argc)
				exit_bad_args();
			phyad_wanted = get_int(argp[i], 0);
		} else if (!strcmp(argp[i], "xcvr")) {
			gset_changed = 1;
			i += 1;
			if (i >= argc)
				exit_bad_args();
			if (!strcmp(argp[i], "internal"))
				xcvr_wanted = XCVR_INTERNAL;
			else if (!strcmp(argp[i], "external"))
				xcvr_wanted = XCVR_EXTERNAL;
			else
				exit_bad_args();
		} else if (!strcmp(argp[i], "wol")) {
			gwol_changed = 1;
			i++;
			if (i >= argc)
				exit_bad_args();
			if (parse_wolopts(argp[i], &wol_wanted) < 0)
				exit_bad_args();
			wol_change = 1;
		} else if (!strcmp(argp[i], "sopass")) {
			gwol_changed = 1;
			i++;
			if (i >= argc)
				exit_bad_args();
			get_mac_addr(argp[i], sopass_wanted);
			sopass_change = 1;
		} else if (!strcmp(argp[i], "msglvl")) {
			i++;
			if (i >= argc)
				exit_bad_args();
			if (isdigit((unsigned char)argp[i][0])) {
				msglvl_changed = 1;
				msglvl_mask = ~0;
				msglvl_wanted =
					get_uint_range(argp[i], 0,
						       0xffffffff);
			} else {
				ctx->argc -= i;
				ctx->argp += i;
				parse_generic_cmdline(
					ctx, &msglvl_changed,
					cmdline_msglvl,
					ARRAY_SIZE(cmdline_msglvl));
				break;
			}
		} else {
			exit_bad_args();
		}
	}

	if (advertising_wanted < 0) {
		if (speed_wanted == SPEED_10 && duplex_wanted == DUPLEX_HALF)
			advertising_wanted = ADVERTISED_10baseT_Half;
		else if (speed_wanted == SPEED_10 &&
			 duplex_wanted == DUPLEX_FULL)
			advertising_wanted = ADVERTISED_10baseT_Full;
		else if (speed_wanted == SPEED_100 &&
			 duplex_wanted == DUPLEX_HALF)
			advertising_wanted = ADVERTISED_100baseT_Half;
		else if (speed_wanted == SPEED_100 &&
			 duplex_wanted == DUPLEX_FULL)
			advertising_wanted = ADVERTISED_100baseT_Full;
		else if (speed_wanted == SPEED_1000 &&
			 duplex_wanted == DUPLEX_HALF)
			advertising_wanted = ADVERTISED_1000baseT_Half;
		else if (speed_wanted == SPEED_1000 &&
			 duplex_wanted == DUPLEX_FULL)
			advertising_wanted = ADVERTISED_1000baseT_Full;
		else if (speed_wanted == SPEED_2500 &&
			 duplex_wanted == DUPLEX_FULL)
			advertising_wanted = ADVERTISED_2500baseX_Full;
		else if (speed_wanted == SPEED_10000 &&
			 duplex_wanted == DUPLEX_FULL)
			advertising_wanted = ADVERTISED_10000baseT_Full;
		else
			/* auto negotiate without forcing,
			 * all supported speed will be assigned below
			 */
			advertising_wanted = 0;
	}

	if (gset_changed) {
		struct ethtool_cmd ecmd;

		ecmd.cmd = ETHTOOL_GSET;
		err = send_ioctl(ctx, &ecmd);
		if (err < 0) {
			perror("Cannot get current device settings");
		} else {
			/* Change everything the user specified. */
			if (speed_wanted != -1)
				ethtool_cmd_speed_set(&ecmd, speed_wanted);
			if (duplex_wanted != -1)
				ecmd.duplex = duplex_wanted;
			if (port_wanted != -1)
				ecmd.port = port_wanted;
			if (autoneg_wanted != -1)
				ecmd.autoneg = autoneg_wanted;
			if (phyad_wanted != -1)
				ecmd.phy_address = phyad_wanted;
			if (xcvr_wanted != -1)
				ecmd.transceiver = xcvr_wanted;
			/* XXX If the user specified speed or duplex
			 * then we should mask the advertised modes
			 * accordingly.  For now, warn that we aren't
			 * doing that.
			 */
			if ((speed_wanted != -1 || duplex_wanted != -1) &&
			    ecmd.autoneg && advertising_wanted == 0) {
				fprintf(stderr, "Cannot advertise");
				if (speed_wanted >= 0)
					fprintf(stderr, " speed %d",
						speed_wanted);
				if (duplex_wanted >= 0)
					fprintf(stderr, " duplex %s",
						duplex_wanted ? 
						"full" : "half");
				fprintf(stderr,	"\n");
			}
			if (autoneg_wanted == AUTONEG_ENABLE &&
			    advertising_wanted == 0) {
				ecmd.advertising = ecmd.supported &
					(ADVERTISED_10baseT_Half |
					 ADVERTISED_10baseT_Full |
					 ADVERTISED_100baseT_Half |
					 ADVERTISED_100baseT_Full |
					 ADVERTISED_1000baseT_Half |
					 ADVERTISED_1000baseT_Full |
					 ADVERTISED_2500baseX_Full |
					 ADVERTISED_10000baseT_Full |
					 ADVERTISED_20000baseMLD2_Full |
					 ADVERTISED_20000baseKR2_Full);
			} else if (advertising_wanted > 0) {
				ecmd.advertising = advertising_wanted;
			}

			/* Try to perform the update. */
			ecmd.cmd = ETHTOOL_SSET;
			err = send_ioctl(ctx, &ecmd);
			if (err < 0)
				perror("Cannot set new settings");
		}
		if (err < 0) {
			if (speed_wanted != -1)
				fprintf(stderr, "  not setting speed\n");
			if (duplex_wanted != -1)
				fprintf(stderr, "  not setting duplex\n");
			if (port_wanted != -1)
				fprintf(stderr, "  not setting port\n");
			if (autoneg_wanted != -1)
				fprintf(stderr, "  not setting autoneg\n");
			if (phyad_wanted != -1)
				fprintf(stderr, "  not setting phy_address\n");
			if (xcvr_wanted != -1)
				fprintf(stderr, "  not setting transceiver\n");
		}
	}

	if (gwol_changed) {
		struct ethtool_wolinfo wol;

		wol.cmd = ETHTOOL_GWOL;
		err = send_ioctl(ctx, &wol);
		if (err < 0) {
			perror("Cannot get current wake-on-lan settings");
		} else {
			/* Change everything the user specified. */
			if (wol_change) {
				wol.wolopts = wol_wanted;
			}
			if (sopass_change) {
				int i;
				for (i = 0; i < SOPASS_MAX; i++) {
					wol.sopass[i] = sopass_wanted[i];
				}
			}

			/* Try to perform the update. */
			wol.cmd = ETHTOOL_SWOL;
			err = send_ioctl(ctx, &wol);
			if (err < 0)
				perror("Cannot set new wake-on-lan settings");
		}
		if (err < 0) {
			if (wol_change)
				fprintf(stderr, "  not setting wol\n");
			if (sopass_change)
				fprintf(stderr, "  not setting sopass\n");
		}
	}

	if (msglvl_changed) {
		struct ethtool_value edata;

		edata.cmd = ETHTOOL_GMSGLVL;
		err = send_ioctl(ctx, &edata);
		if (err < 0) {
			perror("Cannot get msglvl");
		} else {
			edata.cmd = ETHTOOL_SMSGLVL;
			edata.data = ((edata.data & ~msglvl_mask) |
				      msglvl_wanted);
			err = send_ioctl(ctx, &edata);
			if (err < 0)
				perror("Cannot set new msglvl");
		}
	}

	return 0;
}

static int do_gregs(struct cmd_context *ctx)
{
	int gregs_changed = 0;
	int gregs_dump_raw = 0;
	int gregs_dump_hex = 0;
	char *gregs_dump_file = NULL;
	struct cmdline_info cmdline_gregs[] = {
		{ "raw", CMDL_BOOL, &gregs_dump_raw, NULL },
		{ "hex", CMDL_BOOL, &gregs_dump_hex, NULL },
		{ "file", CMDL_STR, &gregs_dump_file, NULL },
	};
	int err;
	struct ethtool_drvinfo drvinfo;
	struct ethtool_regs *regs;

	parse_generic_cmdline(ctx, &gregs_changed,
			      cmdline_gregs, ARRAY_SIZE(cmdline_gregs));

	drvinfo.cmd = ETHTOOL_GDRVINFO;
	err = send_ioctl(ctx, &drvinfo);
	if (err < 0) {
		perror("Cannot get driver information");
		return 72;
	}

	regs = calloc(1, sizeof(*regs)+drvinfo.regdump_len);
	if (!regs) {
		perror("Cannot allocate memory for register dump");
		return 73;
	}
	regs->cmd = ETHTOOL_GREGS;
	regs->len = drvinfo.regdump_len;
	err = send_ioctl(ctx, regs);
	if (err < 0) {
		perror("Cannot get register dump");
		free(regs);
		return 74;
	}
	if (dump_regs(gregs_dump_raw, gregs_dump_hex, gregs_dump_file,
		      &drvinfo, regs) < 0) {
		perror("Cannot dump registers");
		free(regs);
		return 75;
	}
	free(regs);

	return 0;
}

static int do_nway_rst(struct cmd_context *ctx)
{
	struct ethtool_value edata;
	int err;

	if (ctx->argc != 0)
		exit_bad_args();

	edata.cmd = ETHTOOL_NWAY_RST;
	err = send_ioctl(ctx, &edata);
	if (err < 0)
		perror("Cannot restart autonegotiation");

	return err;
}

static int do_geeprom(struct cmd_context *ctx)
{
	int geeprom_changed = 0;
	int geeprom_dump_raw = 0;
	u32 geeprom_offset = 0;
	u32 geeprom_length = -1;
	struct cmdline_info cmdline_geeprom[] = {
		{ "offset", CMDL_U32, &geeprom_offset, NULL },
		{ "length", CMDL_U32, &geeprom_length, NULL },
		{ "raw", CMDL_BOOL, &geeprom_dump_raw, NULL },
	};
	int err;
	struct ethtool_drvinfo drvinfo;
	struct ethtool_eeprom *eeprom;

	parse_generic_cmdline(ctx, &geeprom_changed,
			      cmdline_geeprom, ARRAY_SIZE(cmdline_geeprom));

	drvinfo.cmd = ETHTOOL_GDRVINFO;
	err = send_ioctl(ctx, &drvinfo);
	if (err < 0) {
		perror("Cannot get driver information");
		return 74;
	}

	if (geeprom_length == -1)
		geeprom_length = drvinfo.eedump_len;

	if (drvinfo.eedump_len < geeprom_offset + geeprom_length)
		geeprom_length = drvinfo.eedump_len - geeprom_offset;

	eeprom = calloc(1, sizeof(*eeprom)+geeprom_length);
	if (!eeprom) {
		perror("Cannot allocate memory for EEPROM data");
		return 75;
	}
	eeprom->cmd = ETHTOOL_GEEPROM;
	eeprom->len = geeprom_length;
	eeprom->offset = geeprom_offset;
	err = send_ioctl(ctx, eeprom);
	if (err < 0) {
		perror("Cannot get EEPROM data");
		free(eeprom);
		return 74;
	}
	err = dump_eeprom(geeprom_dump_raw, &drvinfo, eeprom);
	free(eeprom);

	return err;
}

static int do_seeprom(struct cmd_context *ctx)
{
	int seeprom_changed = 0;
	u32 seeprom_magic = 0;
	u32 seeprom_length = -1;
	u32 seeprom_offset = 0;
	u8 seeprom_value = 0;
	int seeprom_value_seen = 0;
	struct cmdline_info cmdline_seeprom[] = {
		{ "magic", CMDL_U32, &seeprom_magic, NULL },
		{ "offset", CMDL_U32, &seeprom_offset, NULL },
		{ "length", CMDL_U32, &seeprom_length, NULL },
		{ "value", CMDL_U8, &seeprom_value, NULL,
		  0, &seeprom_value_seen },
	};
	int err;
	struct ethtool_drvinfo drvinfo;
	struct ethtool_eeprom *eeprom;

	parse_generic_cmdline(ctx, &seeprom_changed,
			      cmdline_seeprom, ARRAY_SIZE(cmdline_seeprom));

	drvinfo.cmd = ETHTOOL_GDRVINFO;
	err = send_ioctl(ctx, &drvinfo);
	if (err < 0) {
		perror("Cannot get driver information");
		return 74;
	}

	if (seeprom_value_seen)
		seeprom_length = 1;

	if (seeprom_length == -1)
		seeprom_length = drvinfo.eedump_len;

	if (drvinfo.eedump_len < seeprom_offset + seeprom_length)
		seeprom_length = drvinfo.eedump_len - seeprom_offset;

	eeprom = calloc(1, sizeof(*eeprom)+seeprom_length);
	if (!eeprom) {
		perror("Cannot allocate memory for EEPROM data");
		return 75;
	}

	eeprom->cmd = ETHTOOL_SEEPROM;
	eeprom->len = seeprom_length;
	eeprom->offset = seeprom_offset;
	eeprom->magic = seeprom_magic;
	eeprom->data[0] = seeprom_value;

	/* Multi-byte write: read input from stdin */
	if (!seeprom_value_seen)
		eeprom->len = fread(eeprom->data, 1, eeprom->len, stdin);

	err = send_ioctl(ctx, eeprom);
	if (err < 0) {
		perror("Cannot set EEPROM data");
		err = 87;
	}
	free(eeprom);

	return err;
}

static int do_test(struct cmd_context *ctx)
{
	enum {
		ONLINE=0,
		OFFLINE,
		EXTERNAL_LB,
	} test_type;
	int err;
	struct ethtool_test *test;
	struct ethtool_gstrings *strings;

	if (ctx->argc > 1)
		exit_bad_args();
	if (ctx->argc == 1) {
		if (!strcmp(ctx->argp[0], "online")) {
			test_type = ONLINE;
	 	} else if (!strcmp(*ctx->argp, "offline")) {
			test_type = OFFLINE;
		} else if (!strcmp(*ctx->argp, "external_lb")) {
			test_type = EXTERNAL_LB;
		} else {
			exit_bad_args();
		}
	} else {
		test_type = OFFLINE;
	}

	strings = get_stringset(ctx, ETH_SS_TEST,
				offsetof(struct ethtool_drvinfo, testinfo_len));
	if (!strings) {
		perror("Cannot get strings");
		return 74;
	}

	test = calloc(1, sizeof(*test) + strings->len * sizeof(u64));
	if (!test) {
		perror("Cannot allocate memory for test info");
		free(strings);
		return 73;
	}
	memset(test->data, 0, strings->len * sizeof(u64));
	test->cmd = ETHTOOL_TEST;
	test->len = strings->len;
	if (test_type == EXTERNAL_LB)
		test->flags = (ETH_TEST_FL_OFFLINE | ETH_TEST_FL_EXTERNAL_LB);
	else if (test_type == OFFLINE)
		test->flags = ETH_TEST_FL_OFFLINE;
	else
		test->flags = 0;
	err = send_ioctl(ctx, test);
	if (err < 0) {
		perror("Cannot test");
		free (test);
		free(strings);
		return 74;
	}

	err = dump_test(test, strings);
	free(test);
	free(strings);

	return err;
}

static int do_phys_id(struct cmd_context *ctx)
{
	int err;
	struct ethtool_value edata;
	int phys_id_time;

	if (ctx->argc > 1)
		exit_bad_args();
	if (ctx->argc == 1)
		phys_id_time = get_int(*ctx->argp, 0);
	else
		phys_id_time = 0;

	edata.cmd = ETHTOOL_PHYS_ID;
	edata.data = phys_id_time;
	err = send_ioctl(ctx, &edata);
	if (err < 0)
		perror("Cannot identify NIC");

	return err;
}

static int do_gstats(struct cmd_context *ctx)
{
	struct ethtool_gstrings *strings;
	struct ethtool_stats *stats;
	unsigned int n_stats, sz_stats, i;
	int err;

	if (ctx->argc != 0)
		exit_bad_args();

	strings = get_stringset(ctx, ETH_SS_STATS,
				offsetof(struct ethtool_drvinfo, n_stats));
	if (!strings) {
		perror("Cannot get stats strings information");
		return 96;
	}

	n_stats = strings->len;
	if (n_stats < 1) {
		fprintf(stderr, "no stats available\n");
		free(strings);
		return 94;
	}

	sz_stats = n_stats * sizeof(u64);

	stats = calloc(1, sz_stats + sizeof(struct ethtool_stats));
	if (!stats) {
		fprintf(stderr, "no memory available\n");
		free(strings);
		return 95;
	}

	stats->cmd = ETHTOOL_GSTATS;
	stats->n_stats = n_stats;
	err = send_ioctl(ctx, stats);
	if (err < 0) {
		perror("Cannot get stats information");
		free(strings);
		free(stats);
		return 97;
	}

	/* todo - pretty-print the strings per-driver */
	fprintf(stdout, "NIC statistics:\n");
	for (i = 0; i < n_stats; i++) {
		fprintf(stdout, "     %.*s: %llu\n",
			ETH_GSTRING_LEN,
			&strings->data[i * ETH_GSTRING_LEN],
			stats->data[i]);
	}
	free(strings);
	free(stats);

	return 0;
}


static int do_srxclass(struct cmd_context *ctx)
{
	int err;

	if (ctx->argc == 3 && !strcmp(ctx->argp[0], "rx-flow-hash")) {
		int rx_fhash_set;
		u32 rx_fhash_val;
		struct ethtool_rxnfc nfccmd;

		rx_fhash_set = rxflow_str_to_type(ctx->argp[1]);
		if (!rx_fhash_set)
			exit_bad_args();
		if (parse_rxfhashopts(ctx->argp[2], &rx_fhash_val) < 0)
			exit_bad_args();

		nfccmd.cmd = ETHTOOL_SRXFH;
		nfccmd.flow_type = rx_fhash_set;
		nfccmd.data = rx_fhash_val;

		err = send_ioctl(ctx, &nfccmd);
		if (err < 0)
			perror("Cannot change RX network flow hashing options");
	} else {
		exit_bad_args();
	}

	return 0;
}

static int do_grxclass(struct cmd_context *ctx)
{
	struct ethtool_rxnfc nfccmd;
	int err;

	if (ctx->argc == 2 && !strcmp(ctx->argp[0], "rx-flow-hash")) {
		int rx_fhash_get;

		rx_fhash_get = rxflow_str_to_type(ctx->argp[1]);
		if (!rx_fhash_get)
			exit_bad_args();

		nfccmd.cmd = ETHTOOL_GRXFH;
		nfccmd.flow_type = rx_fhash_get;
		err = send_ioctl(ctx, &nfccmd);
		if (err < 0)
			perror("Cannot get RX network flow hashing options");
		else
			dump_rxfhash(rx_fhash_get, nfccmd.data);
	} else {
		exit_bad_args();
	}

	return 0;
}

static int do_grxfhindir(struct cmd_context *ctx)
{
	struct ethtool_rxnfc ring_count;
	struct ethtool_rxfh_indir indir_head;
	struct ethtool_rxfh_indir *indir;
	u32 i;
	int err;

	ring_count.cmd = ETHTOOL_GRXRINGS;
	err = send_ioctl(ctx, &ring_count);
	if (err < 0) {
		perror("Cannot get RX ring count");
		return 102;
	}

	indir_head.cmd = ETHTOOL_GRXFHINDIR;
	indir_head.size = 0;
	err = send_ioctl(ctx, &indir_head);
	if (err < 0) {
		perror("Cannot get RX flow hash indirection table size");
		return 103;
	}

	indir = malloc(sizeof(*indir) +
		       indir_head.size * sizeof(*indir->ring_index));
	indir->cmd = ETHTOOL_GRXFHINDIR;
	indir->size = indir_head.size;
	err = send_ioctl(ctx, indir);
	if (err < 0) {
		perror("Cannot get RX flow hash indirection table");
		return 103;
	}

	printf("RX flow hash indirection table for %s with %llu RX ring(s):\n",
	       ctx->devname, ring_count.data);
	for (i = 0; i < indir->size; i++) {
		if (i % 8 == 0)
			printf("%5u: ", i);
		printf(" %5u", indir->ring_index[i]);
		if (i % 8 == 7)
			fputc('\n', stdout);
	}
	return 0;
}

static int do_srxfhindir(struct cmd_context *ctx)
{
	int rxfhindir_equal = 0;
	char **rxfhindir_weight = NULL;
	struct ethtool_rxfh_indir indir_head;
	struct ethtool_rxfh_indir *indir;
	u32 i;
	int err;

	if (ctx->argc < 2)
		exit_bad_args();
	if (!strcmp(ctx->argp[0], "equal")) {
		if (ctx->argc != 2)
			exit_bad_args();
		rxfhindir_equal = get_int_range(ctx->argp[1], 0, 1, INT_MAX);
	} else if (!strcmp(ctx->argp[0], "weight")) {
		rxfhindir_weight = ctx->argp + 1;
	} else {
		exit_bad_args();
	}

	indir_head.cmd = ETHTOOL_GRXFHINDIR;
	indir_head.size = 0;
	err = send_ioctl(ctx, &indir_head);
	if (err < 0) {
		perror("Cannot get RX flow hash indirection table size");
		return 104;
	}

	indir = malloc(sizeof(*indir) +
		       indir_head.size * sizeof(*indir->ring_index));
	indir->cmd = ETHTOOL_SRXFHINDIR;
	indir->size = indir_head.size;

	if (rxfhindir_equal) {
		for (i = 0; i < indir->size; i++)
			indir->ring_index[i] = i % rxfhindir_equal;
	} else {
		u32 j, weight, sum = 0, partial = 0;

		for (j = 0; rxfhindir_weight[j]; j++) {
			weight = get_u32(rxfhindir_weight[j], 0);
			sum += weight;
		}

		if (sum == 0) {
			fprintf(stderr,
				"At least one weight must be non-zero\n");
			exit(1);
		}

		if (sum > indir->size) {
			fprintf(stderr,
				"Total weight exceeds the size of the "
				"indirection table\n");
			exit(1);
		}

		j = -1;
		for (i = 0; i < indir->size; i++) {
			while (i >= indir->size * partial / sum) {
				j += 1;
				weight = get_u32(rxfhindir_weight[j], 0);
				partial += weight;
			}
			indir->ring_index[i] = j;
		}
	}

	err = send_ioctl(ctx, indir);
	if (err < 0) {
		perror("Cannot set RX flow hash indirection table");
		return 105;
	}

	return 0;
}

static int do_flash(struct cmd_context *ctx)
{
	char *flash_file;
	int flash_region;
	struct ethtool_flash efl;
	int err;

	if (ctx->argc < 1 || ctx->argc > 2)
		exit_bad_args();
	flash_file = ctx->argp[0];
	if (ctx->argc == 2) {
		flash_region = strtol(ctx->argp[1], NULL, 0);
		if (flash_region < 0)
			exit_bad_args();
	} else {
		flash_region = -1;
	}

	if (strlen(flash_file) > ETHTOOL_FLASH_MAX_FILENAME - 1) {
		fprintf(stdout, "Filename too long\n");
		return 99;
	}

	efl.cmd = ETHTOOL_FLASHDEV;
	strcpy(efl.data, flash_file);

	if (flash_region < 0)
		efl.region = ETHTOOL_FLASH_ALL_REGIONS;
	else
		efl.region = flash_region;

	err = send_ioctl(ctx, &efl);
	if (err < 0)
		perror("Flashing failed");

	return err;
}

static int do_permaddr(struct cmd_context *ctx)
{
	int i, err;
	struct ethtool_perm_addr *epaddr;

	epaddr = malloc(sizeof(struct ethtool_perm_addr) + MAX_ADDR_LEN);
	epaddr->cmd = ETHTOOL_GPERMADDR;
	epaddr->size = MAX_ADDR_LEN;

	err = send_ioctl(ctx, epaddr);
	if (err < 0)
		perror("Cannot read permanent address");
	else {
		printf("Permanent address:");
		for (i = 0; i < epaddr->size; i++)
			printf("%c%02x", (i == 0) ? ' ' : ':',
			       epaddr->data[i]);
		printf("\n");
	}
	free(epaddr);

	return err;
}

static int flow_spec_to_ntuple(struct ethtool_rx_flow_spec *fsp,
			       struct ethtool_rx_ntuple_flow_spec *ntuple)
{
	size_t i;

	/* verify location is not specified */
	if (fsp->location != RX_CLS_LOC_ANY)
		return -1;

	/* verify ring cookie can transfer to action */
	if (fsp->ring_cookie > INT_MAX && fsp->ring_cookie < (u64)(-2))
		return -1;

	/* verify only one field is setting data field */
	if ((fsp->flow_type & FLOW_EXT) &&
	    (fsp->m_ext.data[0] || fsp->m_ext.data[1]) &&
	    fsp->m_ext.vlan_etype)
		return -1;

	/* Set entire ntuple to ~0 to guarantee all masks are set */
	memset(ntuple, ~0, sizeof(*ntuple));

	/* set non-filter values */
	ntuple->flow_type = fsp->flow_type;
	ntuple->action = fsp->ring_cookie;

	/*
	 * Copy over header union, they are identical in layout however
	 * the ntuple union contains additional padding on the end
	 */
	memcpy(&ntuple->h_u, &fsp->h_u, sizeof(fsp->h_u));

	/*
	 * The same rule mentioned above applies to the mask union.  However,
	 * in addition we need to invert the mask bits to match the ntuple
	 * mask which is 1 for masked, versus 0 for masked as seen in nfc.
	 */
	memcpy(&ntuple->m_u, &fsp->m_u, sizeof(fsp->m_u));
	for (i = 0; i < sizeof(fsp->m_u); i++)
		ntuple->m_u.hdata[i] ^= 0xFF;

	/* copy extended fields */
	if (fsp->flow_type & FLOW_EXT) {
		ntuple->vlan_tag =
			ntohs(fsp->h_ext.vlan_tci);
		ntuple->vlan_tag_mask =
			~ntohs(fsp->m_ext.vlan_tci);
		if (fsp->m_ext.vlan_etype) {
			/*
			 * vlan_etype and user data are mutually exclusive
			 * in ntuple configuration as they occupy the same
			 * space.
			 */
			if (fsp->m_ext.data[0] || fsp->m_ext.data[1])
				return -1;
			ntuple->data =
				ntohl(fsp->h_ext.vlan_etype);
			ntuple->data_mask =
				~(u64)ntohl(fsp->m_ext.vlan_etype);
		} else {
			ntuple->data =
				(u64)ntohl(fsp->h_ext.data[0]) << 32;
			ntuple->data |=
				(u64)ntohl(fsp->h_ext.data[1]);
			ntuple->data_mask =
				(u64)ntohl(~fsp->m_ext.data[0]) << 32;
			ntuple->data_mask |=
				(u64)ntohl(~fsp->m_ext.data[1]);
		}
	}

	/* Mask out the extended bit, because ntuple does not know it! */
	ntuple->flow_type &= ~FLOW_EXT;

	return 0;
}

static int do_srxntuple(struct cmd_context *ctx,
			struct ethtool_rx_flow_spec *rx_rule_fs)
{
	struct ethtool_rx_ntuple ntuplecmd;
	struct ethtool_value eval;
	int err;

	/* attempt to convert the flow classifier to an ntuple classifier */
	err = flow_spec_to_ntuple(rx_rule_fs, &ntuplecmd.fs);
	if (err)
		return -1;

	/*
	 * Check to see if the flag is set for N-tuple, this allows
	 * us to avoid the possible EINVAL response for the N-tuple
	 * flag not being set on the device
	 */
	eval.cmd = ETHTOOL_GFLAGS;
	err = send_ioctl(ctx, &eval);
	if (err || !(eval.data & ETH_FLAG_NTUPLE))
		return -1;

	/* send rule via N-tuple */
	ntuplecmd.cmd = ETHTOOL_SRXNTUPLE;
	err = send_ioctl(ctx, &ntuplecmd);

	/*
	 * Display error only if reponse is something other than op not
	 * supported.  It is possible that the interface uses the network
	 * flow classifier interface instead of N-tuple. 
	 */ 
	if (err < 0) {
		if (errno != EOPNOTSUPP)
			perror("Cannot add new rule via N-tuple");
		return -1;
	}

	return 0;
}

static int do_srxclsrule(struct cmd_context *ctx)
{
	int err;

	if (ctx->argc < 2)
		exit_bad_args();

	if (!strcmp(ctx->argp[0], "flow-type")) {	
		struct ethtool_rx_flow_spec rx_rule_fs;

		ctx->argc--;
		ctx->argp++;
		if (rxclass_parse_ruleopts(ctx, &rx_rule_fs) < 0)
			exit_bad_args();

		/* attempt to add rule via N-tuple specifier */
		err = do_srxntuple(ctx, &rx_rule_fs);
		if (!err)
			return 0;

		/* attempt to add rule via network flow classifier */
		err = rxclass_rule_ins(ctx, &rx_rule_fs);
		if (err < 0) {
			fprintf(stderr, "Cannot insert"
				" classification rule\n");
			return 1;
		}
	} else if (!strcmp(ctx->argp[0], "delete")) {
		int rx_class_rule_del =
			get_uint_range(ctx->argp[1], 0, INT_MAX);

		err = rxclass_rule_del(ctx, rx_class_rule_del);

		if (err < 0) {
			fprintf(stderr, "Cannot delete"
				" classification rule\n");
			return 1;
		}
	} else {
		exit_bad_args();
	}

	return 0;
}

static int do_grxclsrule(struct cmd_context *ctx)
{
	struct ethtool_rxnfc nfccmd;
	int err;

	if (ctx->argc == 2 && !strcmp(ctx->argp[0], "rule")) {
		int rx_class_rule_get =
			get_uint_range(ctx->argp[1], 0, INT_MAX);

		err = rxclass_rule_get(ctx, rx_class_rule_get);
		if (err < 0)
			fprintf(stderr, "Cannot get RX classification rule\n");
		return err ? 1 : 0;
	}

	if (ctx->argc != 0)
		exit_bad_args();

	nfccmd.cmd = ETHTOOL_GRXRINGS;
	err = send_ioctl(ctx, &nfccmd);
	if (err < 0)
		perror("Cannot get RX rings");
	else
		fprintf(stdout, "%d RX rings available\n",
			(int)nfccmd.data);

	err = rxclass_rule_getall(ctx);
	if (err < 0)
		fprintf(stderr, "RX classification rule retrieval failed\n");

	return err ? 1 : 0;
}

static int do_writefwdump(struct ethtool_dump *dump, const char *dump_file)
{
	int err = 0;
	FILE *f;
	size_t bytes;

	f = fopen(dump_file, "wb+");

	if (!f) {
		fprintf(stderr, "Can't open file %s: %s\n",
			dump_file, strerror(errno));
		return 1;
	}
	bytes = fwrite(dump->data, 1, dump->len, f);
	if (bytes != dump->len) {
		fprintf(stderr, "Can not write all of dump data\n");
		err = 1;
	}
	if (fclose(f)) {
		fprintf(stderr, "Can't close file %s: %s\n",
			dump_file, strerror(errno));
		err = 1;
	}
	return err;
}

static int do_getfwdump(struct cmd_context *ctx)
{
	u32 dump_flag;
	char *dump_file;
	int err;
	struct ethtool_dump edata;
	struct ethtool_dump *data;

	if (ctx->argc == 2 && !strcmp(ctx->argp[0], "data")) {
		dump_flag = ETHTOOL_GET_DUMP_DATA;
		dump_file = ctx->argp[1];
	} else if (ctx->argc == 0) {
		dump_flag = 0;
		dump_file = NULL;
	} else {
		exit_bad_args();
	}

	edata.cmd = ETHTOOL_GET_DUMP_FLAG;

	err = send_ioctl(ctx, &edata);
	if (err < 0) {
		perror("Can not get dump level\n");
		return 1;
	}
	if (dump_flag != ETHTOOL_GET_DUMP_DATA) {
		fprintf(stdout, "flag: %u, version: %u, length: %u\n",
			edata.flag, edata.version, edata.len);
		return 0;
	}
	data = calloc(1, offsetof(struct ethtool_dump, data) + edata.len);
	if (!data) {
		perror("Can not allocate enough memory\n");
		return 1;
	}
	data->cmd = ETHTOOL_GET_DUMP_DATA;
	data->len = edata.len;
	err = send_ioctl(ctx, data);
	if (err < 0) {
		perror("Can not get dump data\n");
		err = 1;
		goto free;
	}
	err = do_writefwdump(data, dump_file);
free:
	free(data);
	return err;
}

static int do_setfwdump(struct cmd_context *ctx)
{
	u32 dump_flag;
	int err;
	struct ethtool_dump dump;

	if (ctx->argc != 1)
		exit_bad_args();
	dump_flag = get_u32(ctx->argp[0], 0);

	dump.cmd = ETHTOOL_SET_DUMP;
	dump.flag = dump_flag;
	err = send_ioctl(ctx, &dump);
	if (err < 0) {
		perror("Can not set dump level\n");
		return 1;
	}
	return 0;
}

static int do_gprivflags(struct cmd_context *ctx)
{
	struct ethtool_gstrings *strings;
	struct ethtool_value flags;
	unsigned int i;

	if (ctx->argc != 0)
		exit_bad_args();

	strings = get_stringset(ctx, ETH_SS_PRIV_FLAGS,
				offsetof(struct ethtool_drvinfo, n_priv_flags));
	if (!strings) {
		perror("Cannot get private flag names");
		return 1;
	}
	if (strings->len == 0) {
		fprintf(stderr, "No private flags defined\n");
		return 1;
	}
	if (strings->len > 32) {
		/* ETHTOOL_GPFLAGS can only cover 32 flags */
		fprintf(stderr, "Only showing first 32 private flags\n");
		strings->len = 32;
	}

	flags.cmd = ETHTOOL_GPFLAGS;
	if (send_ioctl(ctx, &flags)) {
		perror("Cannot get private flags");
		return 1;
	}

	printf("Private flags for %s:\n", ctx->devname);
	for (i = 0; i < strings->len; i++)
		printf("%s: %s\n",
		       (const char *)strings->data + i * ETH_GSTRING_LEN,
		       (flags.data & (1U << i)) ? "on" : "off");

	return 0;
}

static int do_sprivflags(struct cmd_context *ctx)
{
	struct ethtool_gstrings *strings;
	struct cmdline_info *cmdline;
	struct ethtool_value flags;
	u32 wanted_flags = 0, seen_flags = 0;
	int any_changed;
	unsigned int i;

	strings = get_stringset(ctx, ETH_SS_PRIV_FLAGS,
				offsetof(struct ethtool_drvinfo, n_priv_flags));
	if (!strings) {
		perror("Cannot get private flag names");
		return 1;
	}
	if (strings->len == 0) {
		fprintf(stderr, "No private flags defined\n");
		return 1;
	}
	if (strings->len > 32) {
		/* ETHTOOL_{G,S}PFLAGS can only cover 32 flags */
		fprintf(stderr, "Only setting first 32 private flags\n");
		strings->len = 32;
	}

	cmdline = calloc(strings->len, sizeof(*cmdline));
	if (!cmdline) {
		perror("Cannot parse arguments");
		return 1;
	}
	for (i = 0; i < strings->len; i++) {
		cmdline[i].name = ((const char *)strings->data +
				   i * ETH_GSTRING_LEN);
		cmdline[i].type = CMDL_FLAG;
		cmdline[i].wanted_val = &wanted_flags;
		cmdline[i].flag_val = 1U << i;
		cmdline[i].seen_val = &seen_flags;
	}
	parse_generic_cmdline(ctx, &any_changed, cmdline, strings->len);

	flags.cmd = ETHTOOL_GPFLAGS;
	if (send_ioctl(ctx, &flags)) {
		perror("Cannot get private flags");
		return 1;
	}

	flags.cmd = ETHTOOL_SPFLAGS;
	flags.data = (flags.data & ~seen_flags) | wanted_flags;
	if (send_ioctl(ctx, &flags)) {
		perror("Cannot set private flags");
		return 1;
	}

	return 0;
}

int send_ioctl(struct cmd_context *ctx, void *cmd)
{
#ifndef TEST_ETHTOOL
	ctx->ifr.ifr_data = cmd;
	return ioctl(ctx->fd, SIOCETHTOOL, &ctx->ifr);
#else
	/* If we get this far then parsing succeeded */
	exit(0);
#endif
}

static int show_usage(struct cmd_context *ctx);

static const struct option {
	const char *opts;
	int want_device;
	int (*func)(struct cmd_context *);
	char *help;
	char *opthelp;
} args[] = {
	{ "-s|--change", 1, do_sset, "Change generic options",
	  "		[ speed %d ]\n"
	  "		[ duplex half|full ]\n"
	  "		[ port tp|aui|bnc|mii|fibre ]\n"
	  "		[ autoneg on|off ]\n"
	  "		[ advertise %x ]\n"
	  "		[ phyad %d ]\n"
	  "		[ xcvr internal|external ]\n"
	  "		[ wol p|u|m|b|a|g|s|d... ]\n"
	  "		[ sopass %x:%x:%x:%x:%x:%x ]\n"
	  "		[ msglvl %d | msglvl type on|off ... ]\n" },
	{ "-a|--show-pause", 1, do_gpause, "Show pause options" },
	{ "-A|--pause", 1, do_spause, "Set pause options",
	  "		[ autoneg on|off ]\n"
	  "		[ rx on|off ]\n"
	  "		[ tx on|off ]\n" },
	{ "-c|--show-coalesce", 1, do_gcoalesce, "Show coalesce options" },
	{ "-C|--coalesce", 1, do_scoalesce, "Set coalesce options",
	  "		[adaptive-rx on|off]\n"
	  "		[adaptive-tx on|off]\n"
	  "		[rx-usecs N]\n"
	  "		[rx-frames N]\n"
	  "		[rx-usecs-irq N]\n"
	  "		[rx-frames-irq N]\n"
	  "		[tx-usecs N]\n"
	  "		[tx-frames N]\n"
	  "		[tx-usecs-irq N]\n"
	  "		[tx-frames-irq N]\n"
	  "		[stats-block-usecs N]\n"
	  "		[pkt-rate-low N]\n"
	  "		[rx-usecs-low N]\n"
	  "		[rx-frames-low N]\n"
	  "		[tx-usecs-low N]\n"
	  "		[tx-frames-low N]\n"
	  "		[pkt-rate-high N]\n"
	  "		[rx-usecs-high N]\n"
	  "		[rx-frames-high N]\n"
	  "		[tx-usecs-high N]\n"
	  "		[tx-frames-high N]\n"
	  "		[sample-interval N]\n" },
	{ "-g|--show-ring", 1, do_gring, "Query RX/TX ring parameters" },
	{ "-G|--set-ring", 1, do_sring, "Set RX/TX ring parameters",
	  "		[ rx N ]\n"
	  "		[ rx-mini N ]\n"
	  "		[ rx-jumbo N ]\n"
	  "		[ tx N ]\n" },
	{ "-k|--show-offload", 1, do_goffload,
	  "Get protocol offload information" },
	{ "-K|--offload", 1, do_soffload, "Set protocol offload",
	  "		[ rx on|off ]\n"
	  "		[ tx on|off ]\n"
	  "		[ sg on|off ]\n"
	  "		[ tso on|off ]\n"
	  "		[ ufo on|off ]\n"
	  "		[ gso on|off ]\n"
	  "		[ gro on|off ]\n"
	  "		[ lro on|off ]\n"
	  "		[ rxvlan on|off ]\n"
	  "		[ txvlan on|off ]\n"
	  "		[ ntuple on|off ]\n"
	  "		[ rxhash on|off ]\n"
	},
	{ "-i|--driver", 1, do_gdrv, "Show driver information" },
	{ "-d|--register-dump", 1, do_gregs, "Do a register dump",
	  "		[ raw on|off ]\n"
	  "		[ file FILENAME ]\n" },
	{ "-e|--eeprom-dump", 1, do_geeprom, "Do a EEPROM dump",
	  "		[ raw on|off ]\n"
	  "		[ offset N ]\n"
	  "		[ length N ]\n" },
	{ "-E|--change-eeprom", 1, do_seeprom,
	  "Change bytes in device EEPROM",
	  "		[ magic N ]\n"
	  "		[ offset N ]\n"
	  "		[ length N ]\n"
	  "		[ value N ]\n" },
	{ "-r|--negotiate", 1, do_nway_rst, "Restart N-WAY negotiation" },
	{ "-p|--identify", 1, do_phys_id,
	  "Show visible port identification (e.g. blinking)",
	  "               [ TIME-IN-SECONDS ]\n" },
	{ "-t|--test", 1, do_test, "Execute adapter self test",
	  "               [ online | offline | external_lb ]\n" },
	{ "-S|--statistics", 1, do_gstats, "Show adapter statistics" },
	{ "-n|--show-nfc", 1, do_grxclass,
	  "Show Rx network flow classification options",
	  "		[ rx-flow-hash tcp4|udp4|ah4|esp4|sctp4|"
	  "tcp6|udp6|ah6|esp6|sctp6 ]\n" },
	{ "-N|--config-nfc", 1, do_srxclass,
	  "Configure Rx network flow classification options",
	  "		[ rx-flow-hash tcp4|udp4|ah4|esp4|sctp4|"
	  "tcp6|udp6|ah6|esp6|sctp6 m|v|t|s|d|f|n|r... ]\n" },
	{ "-x|--show-rxfh-indir", 1, do_grxfhindir,
	  "Show Rx flow hash indirection" },
	{ "-X|--set-rxfh-indir", 1, do_srxfhindir,
	  "Set Rx flow hash indirection",
	  "		equal N | weight W0 W1 ...\n" },
	{ "-f|--flash", 1, do_flash,
	  "Flash firmware image from the specified file to a region on the device",
	  "               FILENAME [ REGION-NUMBER-TO-FLASH ]\n" },
	{ "-U|--config-ntuple", 1, do_srxclsrule,
	  "Configure Rx ntuple filters and actions",
	  "		[ delete %d ] |\n"
	  "		[ flow-type ether|ip4|tcp4|udp4|sctp4|ah4|esp4\n"
	  "			[ src %x:%x:%x:%x:%x:%x [m %x:%x:%x:%x:%x:%x] ]\n"
	  "			[ dst %x:%x:%x:%x:%x:%x [m %x:%x:%x:%x:%x:%x] ]\n"
	  "			[ proto %d [m %x] ]\n"
	  "			[ src-ip %d.%d.%d.%d [m %d.%d.%d.%d] ]\n"
	  "			[ dst-ip %d.%d.%d.%d [m %d.%d.%d.%d] ]\n"
	  "			[ tos %d [m %x] ]\n"
	  "			[ l4proto %d [m %x] ]\n"
	  "			[ src-port %d [m %x] ]\n"
	  "			[ dst-port %d [m %x] ]\n"
	  "			[ spi %d [m %x] ]\n"
	  "			[ vlan-etype %x [m %x] ]\n"
	  "			[ vlan %x [m %x] ]\n"
	  "			[ user-def %x [m %x] ]\n"
	  "			[ action %d ]\n"
	  "			[ loc %d]]\n" },
	{ "-u|--show-ntuple", 1, do_grxclsrule,
	  "Get Rx ntuple filters and actions",
	  "		[ rule %d ]\n"},
	{ "-P|--show-permaddr", 1, do_permaddr,
	  "Show permanent hardware address" },
	{ "-w|--get-dump", 1, do_getfwdump,
	  "Get dump flag, data",
	  "		[ data FILENAME ]\n" },
	{ "-W|--set-dump", 1, do_setfwdump,
	  "Set dump flag of the device",
	  "		N\n"},
	{ "-l|--show-channels", 1, do_gchannels, "Query Channels" },
	{ "-L|--set-channels", 1, do_schannels, "Set Channels",
	  "               [ rx N ]\n"
	  "               [ tx N ]\n"
	  "               [ other N ]\n"
	  "               [ combined N ]\n" },
	{ "--show-priv-flags" , 1, do_gprivflags, "Query private flags" },
	{ "--set-priv-flags", 1, do_sprivflags, "Set private flags",
	  "		FLAG on|off ...\n" },
	{ "-h|--help", 0, show_usage, "Show this help" },
	{ "--version", 0, do_version, "Show version number" },
	{}
};

static int show_usage(struct cmd_context *ctx)
{
	int i;

	/* ethtool -h */
	fprintf(stdout, PACKAGE " version " VERSION "\n");
	fprintf(stdout,
		"Usage:\n"
		"        ethtool DEVNAME\t"
		"Display standard information about device\n");
	for (i = 0; args[i].opts; i++) {
		fputs("        ethtool ", stdout);
		fprintf(stdout, "%s %s\t%s\n",
			args[i].opts,
			args[i].want_device ? "DEVNAME" : "\t",
			args[i].help);
		if (args[i].opthelp)
			fputs(args[i].opthelp, stdout);
	}

	return 0;
}

int main(int argc, char **argp, char **envp)
{
	int (*func)(struct cmd_context *);
	int want_device;
	struct cmd_context ctx;
	int k;

	/* Skip command name */
	argp++;
	argc--;

	/* First argument must be either a valid option or a device
	 * name to get settings for (which we don't expect to begin
	 * with '-').
	 */
	if (argc == 0)
		exit_bad_args();
	for (k = 0; args[k].opts; k++) {
		const char *opt;
		size_t len;
		opt = args[k].opts;
		for (;;) {
			len = strcspn(opt, "|");
			if (strncmp(*argp, opt, len) == 0 &&
			    (*argp)[len] == 0) {
				argp++;
				argc--;
				func = args[k].func;
				want_device = args[k].want_device;
				goto opt_found;
			}
			if (opt[len] == 0)
				break;
			opt += len + 1;
		}
	}
	if ((*argp)[0] == '-')
		exit_bad_args();
	func = do_gset;
	want_device = 1;

opt_found:
	if (want_device) {
		ctx.devname = *argp++;
		argc--;

		if (ctx.devname == NULL)
			exit_bad_args();
		if (strlen(ctx.devname) >= IFNAMSIZ)
			exit_bad_args();

		/* Setup our control structures. */
		memset(&ctx.ifr, 0, sizeof(ctx.ifr));
		strcpy(ctx.ifr.ifr_name, ctx.devname);

		/* Open control socket. */
		ctx.fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (ctx.fd < 0) {
			perror("Cannot get control socket");
			return 70;
		}
	} else {
		ctx.fd = -1;
	}

	ctx.argc = argc;
	ctx.argp = argp;

	return func(&ctx);
}
