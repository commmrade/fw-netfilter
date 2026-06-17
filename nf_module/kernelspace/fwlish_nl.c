#include "fwlish_nl.h"

uint32_t ips[10] = {
    0,0,0,0,0,0,0,0,0,0
};

int fwlish_cmd_set_ip(struct sk_buff* skb, struct genl_info* info) {
    pr_info("set ip called\n");
    if (!info->attrs[FWLISH_A_IP]) {
        pr_err("No IP attribute in attrs\n");
        return -EBADMSG;
    }

    const int pl_len = nla_len(info->attrs[FWLISH_A_IP]);
    if (pl_len != ARRAY_SIZE(ips) * sizeof(*ips)) {
        pr_err("Got fewer ips than 10\n");
        return -EBADMSG;
    }

    const uint32_t* new_ips = nla_data(info->attrs[FWLISH_A_IP]);
    memcpy(ips, new_ips, pl_len);

    for (int i = 0; i < 10; ++i) {
        pr_info("Ip: %pI4\n", &ips[i]);
    }

    pr_info("updated ips succesfuly\n");
    return 0;
}

int fwlish_cmd_get_ip(struct sk_buff* skb, struct genl_info* info) {
    struct sk_buff* buf = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("Could not alloc mem for nlmsg");
        return -ENOMEM;
    }

    void* hdr = genlmsg_put(buf, info->snd_portid, info->snd_seq, info->family, 0, FWLISH_CMD_GET_IP);
    if (!hdr) {
        pr_err("Could not put genlsg header\n");
        nlmsg_free(buf);
        return -EBADMSG;
    }

    int ret = nla_put(buf, FWLISH_A_IP, ARRAY_SIZE(ips) * sizeof(*ips), ips);
    if (ret) {
        pr_err("Could not put attribute IP\n");
        nlmsg_free(buf);
        return -EBADMSG;
    }

    genlmsg_end(buf, hdr);
    ret = genlmsg_reply(buf, info);

    pr_info("get ip reply sent\n");
    return 0;
}
