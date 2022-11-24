/*
 * ulp_ddp.c - netlink implementation of netdev ulp ddp commands
 *
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "strset.h"
#include "bitset.h"

/* ULP_DDP_GET */

struct ulp_ddp_results {
	uint32_t	*cap_hw;
	uint32_t	*cap_active;
	unsigned int	cap_count;
	unsigned int	cap_bitset_size;
	uint64_t	*stats;
	unsigned int	stat_count;
};

int prepare_ulp_ddp_stats(const struct nlattr *nest, struct ulp_ddp_results *res)
{
	const struct nlattr *tb[ETHTOOL_A_ULP_DDP_STATS_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	int ret;

	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
	if (ret < 0)
		goto err;

	if (!tb[ETHTOOL_A_ULP_DDP_STATS_COUNT]) {
		ret = -EFAULT;
		goto err;
	}

	res->stat_count = mnl_attr_get_u32(tb[ETHTOOL_A_ULP_DDP_STATS_COUNT]);
	res->stats = calloc(sizeof(uint64_t), res->stat_count);
	if (!res->stats) {
		ret = -ENOMEM;
		goto err;
	}

	if (tb[ETHTOOL_A_ULP_DDP_STATS_COMPACT_VALUES]) {
		unsigned int len = mnl_attr_get_payload_len(tb[ETHTOOL_A_ULP_DDP_STATS_COMPACT_VALUES]);
		void *buf = mnl_attr_get_payload(tb[ETHTOOL_A_ULP_DDP_STATS_COMPACT_VALUES]);

		if (res->stat_count * sizeof(uint64_t) != len) {
			ret = -EFAULT;
			goto err;
		}

		memcpy(res->stats, buf, len);
	} else {
		const struct nlattr *attr;
		unsigned int i = 0;

		if (!tb[ETHTOOL_A_ULP_DDP_STATS_MAP]) {
			ret = -EFAULT;
			goto err;
		}

		mnl_attr_for_each_nested(attr, tb[ETHTOOL_A_ULP_DDP_STATS_MAP]) {
			switch (mnl_attr_get_type(attr)) {
			case ETHTOOL_A_ULP_DDP_STATS_MAP_ITEM_VAL:
				if (i >= res->stat_count) {
					ret = -EFAULT;
					goto err;
				}
				res->stats[i++] = mnl_attr_get_u64(attr);
				break;
			case ETHTOOL_A_ULP_DDP_STATS_MAP_ITEM_NAME:
				/* TODO */
				break;
			}
		}
	}

	return 0;

err:
	free(res->stats);
	res->stats = NULL;
	res->stat_count = 0;
	return ret;
}


static int prepare_ulp_ddp_results(const struct nlattr **tb,
				   struct ulp_ddp_results *res)
{
	unsigned int count;
	int ret;

	memset(res, 0, sizeof(*res));
	if (!tb[ETHTOOL_A_ULP_DDP_HW] || !tb[ETHTOOL_A_ULP_DDP_ACTIVE])
		return -EFAULT;
	count = bitset_get_count(tb[ETHTOOL_A_ULP_DDP_HW], &ret);
	if (ret < 0)
		return -EFAULT;
	if (bitset_get_count(tb[ETHTOOL_A_ULP_DDP_ACTIVE], &ret) != count)
		return -EFAULT;
	res->cap_hw = get_compact_bitset_value(tb[ETHTOOL_A_ULP_DDP_HW]);
	res->cap_active = get_compact_bitset_value(tb[ETHTOOL_A_ULP_DDP_ACTIVE]);
	if (!res->cap_hw || !res->cap_active)
		return -EFAULT;
	res->cap_count = count;
	res->cap_bitset_size = DIV_ROUND_UP(count, 32);

	if (tb[ETHTOOL_A_ULP_DDP_STATS]) {
		ret = prepare_ulp_ddp_stats(tb[ETHTOOL_A_ULP_DDP_STATS], res);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static bool cap_on(const uint32_t *bitmap, unsigned int idx)
{
	return bitmap[idx / 32] & (1 << (idx % 32));
}

int dump_ulp_ddp(const char *devname,
		 const struct nlattr **tb,
		 const struct stringset *caps_names,
		 const struct stringset *stat_names)
{
	struct ulp_ddp_results results;
	unsigned int i;
	int ret;

	ret = prepare_ulp_ddp_results(tb, &results);
	if (ret < 0)
		return -EFAULT;

	printf("ULP DDP capabilities for %s:\n", devname);
	for (i = 0; i < results.cap_count; i++) {
		const char *name = get_string(caps_names, i);

		if (!name || !*name)
			continue;

		printf("%s: %s\n", name, cap_on(results.cap_active, i) ? "on" : "off");
	}

	if (results.stats) {
		printf("\nStats:\n");
		for (i = 0; i < results.stat_count; i++) {
			const char *name = get_string(stat_names, i);
			printf("%s: %lu\n", name, results.stats[i]);
		}
	}
	return 0;
}

int ulp_ddp_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_ULP_DDP_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	const struct stringset *caps_names;
	const struct stringset *stat_names = NULL;
	struct nl_context *nlctx = data;
	bool silent;
	int ret;

	silent = nlctx->is_dump || nlctx->is_monitor;
	if (!nlctx->is_monitor) {
		ret = netlink_init_ethnl2_socket(nlctx);
		if (ret < 0)
			return MNL_CB_ERROR;
	}
	caps_names = global_stringset(ETH_SS_ULP_DDP_CAPS, nlctx->ethnl2_socket);
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return silent ? MNL_CB_OK : MNL_CB_ERROR;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_ULP_DDP_HEADER]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	if (tb[ETHTOOL_A_ULP_DDP_STATS]) {
		stat_names = global_stringset(ETH_SS_ULP_DDP_STATS,
					      nlctx->ethnl2_socket);
	}

	ret = dump_ulp_ddp(nlctx->devname, tb, caps_names, stat_names);

	return (silent || !ret) ? MNL_CB_OK : MNL_CB_ERROR;
}

int nl_get_ulp_ddp(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	int flags = ETHTOOL_FLAG_COMPACT_BITSETS;
	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_ULP_DDP_GET, true))
		return -EOPNOTSUPP;
	if (ctx->argc > 0) {
		fprintf(stderr, "ethtool: unexpected parameter '%s'\n",
			*ctx->argp);
		return 1;
	}

	flags |= get_stats_flag(nlctx, ETHTOOL_MSG_ULP_DDP_GET,
			       ETHTOOL_A_ULP_DDP_HEADER);

	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_ULP_DDP_GET,
				      ETHTOOL_A_ULP_DDP_HEADER,
				      flags);
	if (ret < 0)
		return ret;

	ret = nlsock_send_get_request(nlsk, ulp_ddp_reply_cb);

	return ret;
}

/* ULP_DDP_SET */

struct set_ulp_ddp_context {
	bool			nothing_changed;
	size_t			count;
	size_t			words;
	uint32_t		req_mask[];
};

static int find_cap(const char *name,
		    const struct stringset *cap_names)
{
	const unsigned int count = get_count(cap_names);
	unsigned int i;

	for (i = 0; i < count; i++)
		if (!strcmp(name, get_string(cap_names, i)))
			return i;

	return -1;
}

static int fill_cap(struct nl_msg_buff *msgbuff, const char *name, bool val)
{
	struct nlattr *bit_attr;

	bit_attr = ethnla_nest_start(msgbuff, ETHTOOL_A_BITSET_BITS_BIT);
	if (!bit_attr)
		return -EMSGSIZE;
	if (ethnla_put_strz(msgbuff, ETHTOOL_A_BITSET_BIT_NAME, name))
		return -EMSGSIZE;
	if (ethnla_put_flag(msgbuff, ETHTOOL_A_BITSET_BIT_VALUE, val))
		return -EMSGSIZE;
	mnl_attr_nest_end(msgbuff->nlhdr, bit_attr);

	return 0;
}

static void set_sulp_req_mask(struct nl_context *nlctx, unsigned int idx)
{
	struct set_ulp_ddp_context *sulp_ctx = nlctx->cmd_private;

	sulp_ctx->req_mask[idx / 32] |= (1 << (idx % 32));
}

int fill_set_ulp_ddp_bitmap(struct nl_context *nlctx,
			  const struct stringset *cap_names)
{
	struct nl_msg_buff *msgbuff = &nlctx->ethnl_socket->msgbuff;
	struct nlattr *bitset_attr;
	struct nlattr *bits_attr;
	int ret;

	ret = -EMSGSIZE;
	bitset_attr = ethnla_nest_start(msgbuff, ETHTOOL_A_ULP_DDP_WANTED);
	if (!bitset_attr)
		return ret;
	bits_attr = ethnla_nest_start(msgbuff, ETHTOOL_A_BITSET_BITS);
	if (!bits_attr)
		goto err;

	while (nlctx->argc > 0) {
		bool val;

		if (!strcmp(*nlctx->argp, "--")) {
			nlctx->argp++;
			nlctx->argc--;
			break;
		}
		ret = -EINVAL;
		if (nlctx->argc < 2 ||
		    (strcmp(nlctx->argp[1], "on") &&
		     strcmp(nlctx->argp[1], "off"))) {
			fprintf(stderr,
				"ethtool (%s): flag '%s' for parameter '%s' is"
				" not followed by 'on' or 'off'\n",
				nlctx->cmd, nlctx->argp[1], nlctx->param);
			goto err;
		}

		val = !strcmp(nlctx->argp[1], "on");
		ret = fill_cap(msgbuff, nlctx->argp[0], val);
		if (ret == 0) {
			int idx = find_cap(nlctx->argp[0],
					   cap_names);
			if (idx >= 0)
				set_sulp_req_mask(nlctx, idx);
		}
		if (ret < 0)
			goto err;

		nlctx->argp += 2;
		nlctx->argc -= 2;
	}

	ethnla_nest_end(msgbuff, bits_attr);
	ethnla_nest_end(msgbuff, bitset_attr);
	return 0;
err:
	ethnla_nest_cancel(msgbuff, bitset_attr);
	return ret;
}

static void show_cap_changes(struct nl_context *nlctx,
			     const struct nlattr *const *tb)
{
	struct set_ulp_ddp_context *sulp_ctx = nlctx->cmd_private;
	const struct stringset *cap_names;
	const uint32_t *wanted_mask;
	const uint32_t *active_mask;
	const uint32_t *wanted_val;
	const uint32_t *active_val;
	unsigned int i;
	bool diff;
	int ret;

	cap_names = global_stringset(ETH_SS_ULP_DDP_CAPS, nlctx->ethnl_socket);

	if (!tb[ETHTOOL_A_ULP_DDP_WANTED] || !tb[ETHTOOL_A_ULP_DDP_ACTIVE])
		goto err;
	if (bitset_get_count(tb[ETHTOOL_A_ULP_DDP_WANTED], &ret) != sulp_ctx->count ||
	    ret < 0)
		goto err;
	if (bitset_get_count(tb[ETHTOOL_A_ULP_DDP_ACTIVE], &ret) != sulp_ctx->count ||
	    ret < 0)
		goto err;
	wanted_val = get_compact_bitset_value(tb[ETHTOOL_A_ULP_DDP_WANTED]);
	wanted_mask = get_compact_bitset_mask(tb[ETHTOOL_A_ULP_DDP_WANTED]);
	active_val = get_compact_bitset_value(tb[ETHTOOL_A_ULP_DDP_ACTIVE]);
	active_mask = get_compact_bitset_mask(tb[ETHTOOL_A_ULP_DDP_ACTIVE]);
	if (!wanted_val || !wanted_mask || !active_val || !active_mask)
		goto err;

	sulp_ctx->nothing_changed = true;
	diff = false;
	for (i = 0; i < sulp_ctx->words; i++) {
		if (wanted_mask[i] != sulp_ctx->req_mask[i])
			sulp_ctx->nothing_changed = false;
		if (wanted_mask[i] || (active_mask[i] & ~sulp_ctx->req_mask[i]))
			diff = true;
	}
	if (!diff)
		return;

	/* result is not exactly as requested, show differences */
	printf("Actual changes:\n");
	for (i = 0; i < sulp_ctx->count; i++) {
		const char *name = get_string(cap_names, i);

		if (!name)
			continue;
		if (!cap_on(wanted_mask, i) && !cap_on(active_mask, i))
			continue;
		printf("%s: ", name);
		if (cap_on(wanted_mask, i))
			/* we requested a value but result is different */
			printf("%s [requested %s]",
			       cap_on(wanted_val, i) ? "off" : "on",
			       cap_on(wanted_val, i) ? "on" : "off");
		else if (!cap_on(sulp_ctx->req_mask, i))
			/* not requested but changed anyway */
			printf("%s [not requested]",
			       cap_on(active_val, i) ? "on" : "off");
		else
			printf("%s", cap_on(active_val, i) ? "on" : "off");
		fputc('\n', stdout);
	}

	return;
err:
	fprintf(stderr, "malformed diff info from kernel\n");
}

int set_ulp_ddp_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct genlmsghdr *ghdr = (const struct genlmsghdr *)(nlhdr + 1);
	const struct nlattr *tb[ETHTOOL_A_ULP_DDP_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	const char *devname;
	int ret;

	if (ghdr->cmd != ETHTOOL_MSG_ULP_DDP_SET_REPLY) {
		fprintf(stderr, "warning: unexpected reply message type %u\n",
			ghdr->cmd);
		return MNL_CB_OK;
	}
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;
	devname = get_dev_name(tb[ETHTOOL_A_ULP_DDP_HEADER]);
	if (strcmp(devname, nlctx->devname)) {
		fprintf(stderr, "warning: unexpected message for device %s\n",
			devname);
		return MNL_CB_OK;
	}

	show_cap_changes(nlctx, tb);
	return MNL_CB_OK;
}

int nl_set_ulp_ddp(struct cmd_context *ctx)
{
	const struct stringset *cap_names;
	struct nl_context *nlctx = ctx->nlctx;
	struct set_ulp_ddp_context *sulp_ctx;
	size_t ctx_size;
	struct nl_msg_buff *msgbuff;
	struct nl_socket *nlsk;
	unsigned int words;

	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_ULP_DDP_SET, false))
		return -EOPNOTSUPP;

	nlctx->cmd = "-J";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	nlctx->cmd_private = &sulp_ctx;
	nlsk = nlctx->ethnl_socket;
	msgbuff = &nlsk->msgbuff;

	cap_names = global_stringset(ETH_SS_ULP_DDP_CAPS, nlctx->ethnl_socket);
	words = DIV_ROUND_UP(get_count(cap_names), 32);
	ctx_size = sizeof(*sulp_ctx) + words * sizeof(sulp_ctx->req_mask[0]);
	sulp_ctx = calloc(1, ctx_size);
	if (!sulp_ctx)
		return -ENOMEM;
	sulp_ctx->words = words;
	sulp_ctx->count = get_count(cap_names);
	nlctx->cmd_private = sulp_ctx;
	nlctx->devname = ctx->devname;
	ret = msg_init(nlctx, msgbuff, ETHTOOL_MSG_ULP_DDP_SET,
		       NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return 2;
	if (ethnla_fill_header(msgbuff, ETHTOOL_A_ULP_DDP_HEADER, ctx->devname,
			       ETHTOOL_FLAG_COMPACT_BITSETS))
		return -EMSGSIZE;
	ret = fill_set_ulp_ddp_bitmap(nlctx, cap_names);
	if (ret < 0)
		return ret;

	ret = nlsock_sendmsg(nlsk, NULL);
	if (ret < 0)
		return 92;
	ret = nlsock_process_reply(nlsk, set_ulp_ddp_reply_cb, nlctx);
	if (sulp_ctx->nothing_changed) {
		fprintf(stderr, "Could not change any device capabilities\n");
		return nlctx->exit_code ?: 1;
	}
	if (ret == 0)
		return 0;
	return nlctx->exit_code ?: 92;
}
