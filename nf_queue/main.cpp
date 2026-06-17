#include <cassert>
#include <cstdint>
#include <arpa/inet.h>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <limits>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <print>
#include <libmnl/libmnl.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <memory>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <vector>
#include <ranges>
#include <iostream>

constexpr auto QUEUE_NUM = 200;
const std::size_t BUF_SIZE = std::numeric_limits<std::uint16_t>::max();
constexpr std::string_view MAX_SNI = "max.ru";

struct Context {
    mnl_socket* nl_sock;
    std::vector<std::uint32_t> forbid_addrs;
    std::vector<std::uint16_t> forbid_ports;

    ~Context() {
        mnl_socket_close(nl_sock);
    }
};

int set_verdict(mnl_socket* sock, int packet_id, int verdict) {
    char buf[512];
    nlmsghdr* verd_msg = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, QUEUE_NUM);
    nfq_nlmsg_verdict_put(verd_msg, packet_id, verdict);

    int ret = mnl_socket_sendto(sock, verd_msg, verd_msg->nlmsg_len);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

bool should_pass(Context& ctx, const iphdr* ip, const tcphdr* tcp) {
    if (std::ranges::contains(ctx.forbid_addrs, ip->saddr) || std::ranges::contains(ctx.forbid_ports, ntohs(tcp->dest))) {
        return false;
    }
    return true;
}

int cb(const struct nlmsghdr *nlh, void *data) {
    Context* ctx = static_cast<Context*>(data);
    std::array<nlattr*, NFQA_MAX + 1> attrs{};

    int ret = nfq_nlmsg_parse(nlh, attrs.data());
    if (ret < 0) {
        perror("nlmsg parse failed");
        return MNL_CB_ERROR;
    }

    nfqnl_msg_packet_hdr* phdr = static_cast<nfqnl_msg_packet_hdr*>(mnl_attr_get_payload(attrs[NFQA_PACKET_HDR]));

    const auto plen = mnl_attr_get_payload_len(attrs[NFQA_PAYLOAD]);
    const auto* payload = mnl_attr_get_payload(attrs[NFQA_PAYLOAD]);

    const iphdr* ip = static_cast<const iphdr*>(payload);
    const auto ip_sz = ip->ihl * 4;
    if (ip->protocol == IPPROTO_TCP) {
        const tcphdr* tcp = reinterpret_cast<const tcphdr*>(static_cast<const char*>(payload) + ip_sz);
        const auto tcp_sz = tcp->doff * 4;

        if (!should_pass(*ctx, ip, tcp)) {
            char ip_str[INET_ADDRSTRLEN];
            const char* r = inet_ntop(AF_INET, &ip->daddr, ip_str, sizeof(ip_str));
            std::println(std::cerr, "Dropped packet with destination {}:{}", ip_str, ntohs(tcp->dest));
            return MNL_CB_OK;
        }
    }

    ret = set_verdict(ctx->nl_sock, ntohl(phdr->packet_id), NF_ACCEPT);
    if (ret < 0) {
        perror("set verdict failure");
        return MNL_CB_ERROR;
    }
    return MNL_CB_OK;
}

std::pair<std::vector<std::uint32_t>, std::vector<std::uint16_t>> parse_config(const std::filesystem::path& filepath) {
    std::ifstream file{filepath};
    if (!file.is_open()) {
        throw std::runtime_error("File was not found");
    }

    nlohmann::json json = nlohmann::json::parse(file);
    if (!json["ips"].is_array() || !json["ports"].is_array()) {
        throw std::runtime_error("Weird format");
    }

    std::vector<std::uint32_t> ips;
    ips.reserve(json["ips"].size());

    for (const auto& ip : json["ips"]) {
        const auto ip_str = ip.get<std::string>();

        std::uint32_t bin_ip;
        int ret = inet_pton(AF_INET, ip_str.data(), &bin_ip);
        if (ret < 0) {
            std::println(std::cerr, "Could not convert {} to binary IP", ip_str);
            continue;
        }

        ips.push_back(bin_ip);
    }

    std::vector<std::uint16_t> ports;
    ports.reserve(json["ports"].size());

    for (const auto& port_j : json["ports"]) {
        const auto port = port_j.get<std::uint16_t>();
        ports.push_back(port);
    }

    std::println("ips: {}, ports: {}", ips, ports);
    return {ips, ports};
}


int main(int argc, char** argv) {
    Context ctx;
    auto [ips, ports] = parse_config("../rules.json");
    ctx.forbid_addrs = std::move(ips);
    ctx.forbid_ports = std::move(ports);

    ctx.nl_sock = mnl_socket_open(NETLINK_NETFILTER);
    if (!ctx.nl_sock) {
        perror("netlink socket open failed");
        return -1;
    }

    int ret = mnl_socket_bind(ctx.nl_sock, 0, MNL_SOCKET_AUTOPID);
    if (ret < 0) {
        perror("netlink socket bind failed");
        return -1;
    }

    const auto portid = mnl_socket_get_portid(ctx.nl_sock); // netlink port id, usually == PID, but not the always the case

    std::unique_ptr<char[]> buf{new char[BUF_SIZE]};

    nlmsghdr* nlmsg = nfq_nlmsg_put(buf.get(), NFQNL_MSG_CONFIG, QUEUE_NUM);
    nfq_nlmsg_cfg_put_cmd(nlmsg, AF_INET, NFQNL_CFG_CMD_BIND);

    ret = mnl_socket_sendto(ctx.nl_sock, nlmsg, nlmsg->nlmsg_len);
    if (ret < 0) {
        perror("netlink socket send failed");
        return -1;
    }

    nlmsg = nfq_nlmsg_put(buf.get(), NFQNL_MSG_CONFIG, QUEUE_NUM);
    nfq_nlmsg_cfg_put_params(nlmsg, NFQNL_COPY_PACKET, 0xffff);

    mnl_attr_put_u32(nlmsg, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlmsg, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

    ret = mnl_socket_sendto(ctx.nl_sock, nlmsg, nlmsg->nlmsg_len);
    if (ret < 0) {
        perror("netlink socket send failed");
        return -1;
    }

    ret = 1;
    mnl_socket_setsockopt(ctx.nl_sock, NETLINK_NO_ENOBUFS, &ret, sizeof(ret));

    while (true) {
        ssize_t rd = mnl_socket_recvfrom(ctx.nl_sock, buf.get(), BUF_SIZE);
        if (rd < 0) {
            perror("netlink socket recv failed");
            return -1;
        }

        ret = mnl_cb_run(buf.get(), rd, 0, portid, cb, &ctx);
        if (ret < 0) {
            perror("cb run");
            return -1;
        }
    }

    return 0;
}
