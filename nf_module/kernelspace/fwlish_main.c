#include "linux/netfilter.h"
#include "linux/skbuff.h"
#include "linux/slab.h"
#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/string.h>
#include "fwlish_nl.h"


static bool should_pass(const struct iphdr* ip, const struct tcphdr* tcp) {
    for (int i = 0; i < sizeof(ips) / sizeof(ips[0]); ++i) {
        const uint32_t ip_be = ips[i];
        if (ip_be != 0 && ip->saddr == ip_be) {
            return false;
        }
    }
    return true;
}

static unsigned int fw_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    const struct iphdr* ip = ip_hdr(skb);
    if (ip->protocol == IPPROTO_TCP) {
        const struct tcphdr* tcp = tcp_hdr(skb);
        if (!should_pass(ip, tcp)) {
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}


static struct nf_hook_ops nf_ops = {
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = -100,
    .hook = fw_hook
};

static int __init fw_init(void) {
    int ret = nf_register_net_hook(&init_net, &nf_ops);
    if (unlikely(ret)) {
        pr_err("nf_register_net_hook failed\n");
        return -1;
    }

    ret = genl_register_family(&fwlish_fam);
    if (unlikely(ret)) {
        pr_err("genl_register_family failed\n");
        return -1;
    }
    return 0;
}

static void __exit fw_deinit(void) {
    nf_unregister_net_hook(&init_net, &nf_ops);
    genl_unregister_family(&fwlish_fam);
}

module_init(fw_init);
module_exit(fw_deinit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple firewall kinda thing");
