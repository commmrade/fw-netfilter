#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <arpa/inet.h>
#include <iostream>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <cassert>
#include <print>
#include <format>
#include <memory>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <linux/genetlink.h>
#include <unistd.h>
#include "../kernelspace/fwlish_family.h"


static std::array<char, 4096> buf;

nlmsghdr* prepare_request(mnl_socket* nl_sock, const int type, const int cmd) {
    nlmsghdr* nl_hdr = mnl_nlmsg_put_header(buf.data());
    nl_hdr->nlmsg_type = type;
    nl_hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nl_hdr->nlmsg_pid = 0;
    nl_hdr->nlmsg_seq = 0;

    genlmsghdr* gen_hdr = static_cast<genlmsghdr*>(mnl_nlmsg_put_extra_header(nl_hdr, sizeof(genlmsghdr)));
    gen_hdr->cmd = cmd;
    gen_hdr->version = 1;
    return nl_hdr;
}

nlmsghdr* response(ssize_t rd) {
    nlmsghdr* reply = reinterpret_cast<nlmsghdr*>(buf.data());
    if (!mnl_nlmsg_ok(reply, rd)) {
        return nullptr;
    }
    return reply;
}

template<std::size_t SIZE>
void parse_attrs(const nlmsghdr* msg, std::array<nlattr*, SIZE>& attrs) {
    auto attr_cb = [](const struct nlattr *attr, void *data) -> int {
        auto *tb = static_cast<struct nlattr **>(data);
        tb[mnl_attr_get_type(attr)] = const_cast<struct nlattr *>(attr);
        return MNL_CB_OK;
    };

    mnl_attr_parse(msg, sizeof(genlmsghdr), attr_cb, attrs.data());
}

std::uint16_t get_family_id(mnl_socket* nl_sock, const std::string_view family_name) {
    auto* nl_hdr = prepare_request(nl_sock, GENL_ID_CTRL, CTRL_CMD_GETFAMILY);
    mnl_attr_put_strz(nl_hdr, CTRL_ATTR_FAMILY_NAME, FWLISH_FAMILY_NAME);


    std::cout << "Len is " << nl_hdr->nlmsg_len << " bytes\n";
    int ret = mnl_socket_sendto(nl_sock, nl_hdr, nl_hdr->nlmsg_len);
    if (ret < 0) {
        throw std::runtime_error(std::format("mnl socket sendto failed: {}", std::strerror(errno)));
    }

    ssize_t rd = mnl_socket_recvfrom(nl_sock, buf.data(), buf.size());
    if (rd < 0) {
        throw std::runtime_error(std::format("mnl socket recvfrom: {}", std::strerror(errno)));
    }

    const auto* reply = response(rd);
    assert(reply);

    if (reply->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)mnl_nlmsg_get_payload(reply);
        throw std::runtime_error(std::format("nlmsg error: {}", err->error));
    }

    std::array<nlattr*, CTRL_ATTR_MAX> attrs{};
    parse_attrs(reply, attrs);

    if (!attrs[CTRL_ATTR_FAMILY_ID]) {
        throw std::runtime_error("Response does not contain family id");
    }

    const auto id = mnl_attr_get_u16(attrs[CTRL_ATTR_FAMILY_ID]);
    return id;
}

std::vector<std::uint32_t> get_banlist(mnl_socket* nl_sock, std::uint16_t fam_id) {
    // get_ip
    auto* msg_hdr = prepare_request(nl_sock, fam_id, FWLISH_CMD_GET_IP);

    int ret = mnl_socket_sendto(nl_sock, msg_hdr, msg_hdr->nlmsg_len);
    if (ret < 0) {
        throw std::runtime_error(std::format("mnl socket sendto getip failed: {}", std::strerror(errno)));
    }

    // ignore whatever this first thing is
    ssize_t rd = mnl_socket_recvfrom(nl_sock, buf.data(), buf.size());
    if (rd < 0) {
        throw std::runtime_error(std::format("mnl socket recvfrom failed: {}", std::strerror(errno)));
    }

    rd = mnl_socket_recvfrom(nl_sock, buf.data(), buf.size());
    if (rd < 0) {
        throw std::runtime_error(std::format("mnl socet recvfrom failed: {}", std::strerror(errno)));
    }

    const auto* reply_hdr = response(rd);
    assert(reply_hdr);

    if (reply_hdr->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)mnl_nlmsg_get_payload(reply_hdr);
        throw std::runtime_error(std::format("nlmsg error: {}", err->error));
    }

    std::array<nlattr*, FWLISH_A_MAX + 1> attrs{};
    parse_attrs(reply_hdr, attrs);

    if (!attrs[FWLISH_A_IP]) {
        throw std::runtime_error("Get ip does not contain payload");
    }

    const auto pl_size = mnl_attr_get_payload_len(attrs[FWLISH_A_IP]);
    assert(pl_size == 40);
    const std::uint32_t* pl = static_cast<const std::uint32_t*>(mnl_attr_get_payload(attrs[FWLISH_A_IP]));

    std::vector<std::uint32_t> res;
    res.reserve(pl_size / sizeof(std::uint32_t));
    for (auto i = 0; i < pl_size / sizeof(std::uint32_t); ++i) {
        res.push_back(pl[i]);
    }

    return res;
}

int set_banlist(mnl_socket* nl_sock, const std::vector<std::uint32_t> ips, const int fam_id) {

    auto* msg_hdr = prepare_request(nl_sock, fam_id, FWLISH_CMD_SET_IP);
    mnl_attr_put(msg_hdr, FWLISH_A_IP, ips.size() * sizeof(ips[0]), ips.data());

    int ret = mnl_socket_sendto(nl_sock, msg_hdr, msg_hdr->nlmsg_len);
    if (ret < 0) {
        perror("mnl socket sendto failed");
        return -1;
    }

    ssize_t rd = mnl_socket_recvfrom(nl_sock, buf.data(), buf.size());
    if (rd < 0) {
        perror("recv error");
        return -1;
    }

    auto* reply_hdr = response(rd);
    assert(reply_hdr);

    if (reply_hdr->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)mnl_nlmsg_get_payload(reply_hdr);
        if (err->error != 0) {
            throw std::runtime_error(std::format("nlmsg error: {}", err->error));
        }
    }

    return 0;
}

int main() {
    std::unique_ptr<mnl_socket, decltype(&mnl_socket_close)> nl_sock{mnl_socket_open(NETLINK_GENERIC), mnl_socket_close};

    if (!nl_sock) {
        perror("mnl_socket_open failed");
        return -1;
    }

    if (mnl_socket_bind(nl_sock.get(), 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        return -1;
    }

    const auto fam_id = get_family_id(nl_sock.get(), FWLISH_FAMILY_NAME);
    get_banlist(nl_sock.get(), fam_id);

    std::vector<uint32_t> ips = {
        0x5DBAE1C2, // 93.186.225.194
        0x57F08443, // 87.240.132.67
        0x57F08185, // 87.240.129.133
        0x57F089A4, // 87.240.137.164
        0x57F08448, // 87.240.132.72
        0x57F0844E, // 87.240.132.78
    };
    for (auto& ip : ips) {
        ip = htonl(ip);
    }
    ips.resize(10);
    set_banlist(nl_sock.get(), ips, fam_id);

    mnl_socket_close(nl_sock.get());
    return 0;
}
