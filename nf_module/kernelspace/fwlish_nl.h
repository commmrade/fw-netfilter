#include "linux/netfilter.h"
#include "linux/skbuff.h"
#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include "fwlish_family.h"
#include <linux/string.h>

extern uint32_t ips[10];

int fwlish_cmd_set_ip(struct sk_buff* skb, struct genl_info* info);
int fwlish_cmd_get_ip(struct sk_buff* skb, struct genl_info* info);

static struct nla_policy fwlish_pols[FWLISH_A_MAX + 1] = {
    [FWLISH_A_IP] = { .type = NLA_BINARY, .len = ARRAY_SIZE(ips) * sizeof(*ips), }
};
static struct genl_ops fwlish_ops[] = {
    {
        .cmd = FWLISH_CMD_GET_IP,
        .doit = fwlish_cmd_get_ip,
    },
    {
        .cmd = FWLISH_CMD_SET_IP,
        .doit = fwlish_cmd_set_ip,
        .policy = fwlish_pols
    }
};

static struct genl_family fwlish_fam = {
    .name = FWLISH_FAMILY_NAME,
    .version = FWLISH_FAMILY_VER,
    .maxattr = FWLISH_A_MAX,
    .ops = fwlish_ops,
    .n_ops = ARRAY_SIZE(fwlish_ops),
};
