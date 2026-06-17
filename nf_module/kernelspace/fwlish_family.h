#include <linux/module.h>
// #include <net/genetlink.h>

#define FWLISH_FAMILY_NAME "fwlish"
#define FWLISH_FAMILY_VER 1

// attributes:
// ATTR_IP - byte-array of 4 byte-sized binary IPv4s (network byte order)
enum fwlish_family_attrs {
    FWLISH_A_UNSPEC,
    FWLISH_A_IP,

    __FWLISH_A_MAX
};

#define FWLISH_A_MAX (__FWLISH_A_MAX - 1)

// Commands:
// SET_IP - set banlist for ips (net byte order)
// GET_IP - return a banlist for ips (net byte order)
enum fwlish_family_cmds {
    FWLISH_CMD_UNSPEC,
    FWLISH_CMD_SET_IP,
    FWLISH_CMD_GET_IP,

    __FWLISH_CMD_MAX
};
#define FWLISH_CMD_MAX (__FWLISH_CMD_MAX - 1)
