/*************************************************************************
 * Copyright (c) 2015-2022, NVIDIA CORPORATION. All rights reserved.
 *
 * See LICENSE.txt for license information
 ************************************************************************/

#ifndef NCCL_ANP_BOOTSTRAP_H_
#define NCCL_ANP_BOOTSTRAP_H_

#include <iostream>
#include "nccl.h"
//#include "comm.h"

#include <boost/version.hpp>
#include "boost/foreach.hpp"
#include "boost/optional.hpp"
#include "boost/property_tree/ptree.hpp"
#include "boost/property_tree/json_parser.hpp"
#include <arpa/inet.h>
#include "anp_iptables_wrap.h"

namespace pt = boost::property_tree;

#define MAX_STR_LEN    64
#define MAX_INTERFACES 64
#define MAX_DEVICES    8

#define ANP_SUCCESS 0
#define ANP_FAILURE -1

// Logging macro
#ifndef ANP_LOG
#define ANP_LOG(fmt, ...) fprintf(stderr, "[ANP] [%s:%d] " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#define JKEY_HOST_NAME                 "host_name"
#define JKEY_HOST_IP                   "host_ip"
#define JKEY_HOST_DEVICES              "devices"
#define JKEY_VIRTUAL_INTERFACE         "virtual_intf"
#define JKEY_VIRTUAL_IP                "virtual_ip"
#define JKEY_PLANAR_INTERFACES         "planar_intfs"
#define JKEY_PLANAR_INTF_ID            "id"
#define JKEY_PLANAR_INTF_NAME          "name"
#define JKEY_PLANAR_INTF_IPV4_ADDR     "ipv4_addr"
#define JKEY_PLANAR_INTF_IPV6_ADDR     "ipv6_addr"

// planar interface details
typedef struct planar_interface_s {
    char            id[MAX_STR_LEN];
    char            name[MAX_STR_LEN];
    struct in_addr  ipv4_addr;
    struct in6_addr ipv6_addr;
} planar_interface_t;

// device details
typedef struct device_s {
    char               virtual_intf[MAX_STR_LEN];
    struct in_addr     virtual_ip;
    int                num_interfaces;
    planar_interface_t planar_intfs[MAX_INTERFACES];
} device_t;

// host details
typedef struct host_s {
    std::string   host_name;
    std::string   host_ip;
    int           num_devices;
    device_t      devices[MAX_DEVICES];
} host_t;

typedef struct host_db_s {
    std::string                             local_ip;
    std::unordered_map<std::string, host_t> all_hosts;
    std::unordered_map<uint32_t, struct in_addr> planar_to_virtual_map;
    std::unordered_map<uint32_t, std::vector<planar_interface_t>> virtual_to_planar_map;
} host_db_t;

int execute_iptables_if_not_exists(const std::string& command,
                                   const std::string& error_message) {
    std::stringstream check_command;
    check_command << "iptables -t nat -C " << command.substr(command.find("-A") + 3); // Extract the rule part

    int check_result = 1; //system(check_command.str().c_str());
    if (check_result != 0) {
        int result = system(command.c_str());
        if (result != 0) {
            std::cerr << error_message << ": " << command << std::endl;
            return -1;
        } else {
            std::cout << "Command executed: " << command << std::endl;
            return 0;
        }
    } else {
        std::cout << "Rule already exists: " << command << std::endl;
        return 0;
    }
}

int add_tx_snat_rules(const char* virtual_ip, const char* planar_ip, const std::string& planar_intf_name) {
    IptablesRule rule = {
        .action = "A",
        .table = "nat",
        .chain = "POSTROUTING",
        .match_type = "SIP",
        .match_value = virtual_ip,
        .iface_type = "out",
        .iface_name = planar_intf_name,
        .jump_target = "SNAT",
        .translate_ip = planar_ip
    };
    return execute_iptables_command(rule);
}

int add_tx_dnat_rules(const char* virtual_ip, const char* planar_ip, const std::string& planar_intf_name) {
    IptablesRule rule = {
        .action = "A",
        .table = "nat",
        .chain = "OUTPUT",
        .match_type = "DIP",
        .match_value = virtual_ip,
        .iface_type = "out",
        .iface_name = planar_intf_name,
        .jump_target = "DNAT",
        .translate_ip = planar_ip
    };
    return execute_iptables_command(rule);
}

int add_rx_snat_rules(const char* virtual_ip, const char* planar_ip, const std::string& planar_intf_name) {
    IptablesRule rule = { 
        .action = "A",
        .table = "nat",
        .chain = "INPUT",
        .match_type = "SIP",
        .match_value = planar_ip,
        .iface_type = "in",
        .iface_name = planar_intf_name,
        .jump_target = "SNAT",
        .translate_ip = virtual_ip
    };
    return execute_iptables_command(rule);
}

int add_rx_dnat_rules(const char* virtual_ip, const char* planar_ip, const std::string& planar_intf_name) {
    IptablesRule rule = { 
        .action = "A",
        .table = "nat",
        .chain = "OUTPUT",
        .match_type = "DIP",
        .match_value = planar_ip,
        .iface_type = "out",
        .iface_name = planar_intf_name,
        .jump_target = "DNAT",
        .translate_ip = virtual_ip
    };
    return execute_iptables_command(rule);
}

void apply_local_vip_iptables_rule(const host_db_t& host_db) {
    auto local_host_it = host_db.all_hosts.find(host_db.local_ip);
    if (local_host_it == host_db.all_hosts.end()) {
        std::cerr << "Local host not found in host_db." << std::endl;
        return;
    }
    const host_t& host = local_host_it->second;
    std::cerr << "Programming local vip ip table rules for " << host.host_name << ":" << host.host_ip << std::endl;
    for (int i = 0; i < host.num_devices; ++i) {
        const device_t& device = host.devices[i];
        for (int j = 0; j < device.num_interfaces; ++j) {
            char virtual_ip_str[INET_ADDRSTRLEN];
            const planar_interface_t& planar_intf = device.planar_intfs[j];

            inet_ntop(AF_INET, &device.virtual_ip, virtual_ip_str, INET_ADDRSTRLEN);
            if (planar_intf.ipv4_addr.s_addr != 0 && device.virtual_ip.s_addr != 0) {
                char planar_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &planar_intf.ipv4_addr, planar_ip_str, INET_ADDRSTRLEN);

                add_tx_snat_rules(virtual_ip_str, planar_ip_str, planar_intf.name);
                add_rx_dnat_rules(virtual_ip_str, planar_ip_str, planar_intf.name);
            }
        }
    }
}

void apply_remote_vip_iptables_rule(const host_db_t& host_db) {
    for (const auto& host_pair : host_db.all_hosts) {
        if (host_pair.first == host_db.local_ip) {
            // skip local host
            continue;
        }

        const host_t& host = host_pair.second;
        std::cerr << "Programming remote vip ip table rules for " << host.host_name << ":" << host.host_ip << std::endl;
        for (int i = 0; i < host.num_devices; ++i) {
            const device_t& device = host.devices[i];
            for (int j = 0; j < device.num_interfaces; ++j) {
                char virtual_ip_str[INET_ADDRSTRLEN];
                const planar_interface_t& planar_intf = device.planar_intfs[j];

                inet_ntop(AF_INET, &device.virtual_ip, virtual_ip_str, INET_ADDRSTRLEN);
                if (planar_intf.ipv4_addr.s_addr != 0 && device.virtual_ip.s_addr != 0) {
                    char planar_ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &planar_intf.ipv4_addr, planar_ip_str, INET_ADDRSTRLEN);

                    add_tx_dnat_rules(virtual_ip_str, planar_ip_str, planar_intf.name);
                    add_rx_snat_rules(virtual_ip_str, planar_ip_str, planar_intf.name);
                }
            }
        }
    }
}

// Lookup Virtual IP by Planar Interface IP
const struct in_addr* lookup_virtual_ip(host_db_t& host_db, const struct in_addr& planar_ip) {
    auto it = host_db.planar_to_virtual_map.find(planar_ip.s_addr);
    return (it != host_db.planar_to_virtual_map.end()) ? &it->second : nullptr;
}

// Lookup Planar Interface by Virtual IP
const std::vector<planar_interface_t>* lookup_planar_interfaces(host_db_t& host_db, const struct in_addr& virtual_ip) {
    auto it = host_db.virtual_to_planar_map.find(virtual_ip.s_addr);
    return (it != host_db.virtual_to_planar_map.end()) ? &it->second : nullptr;
}

void serialize_host(std::vector<uint8_t>& buffer, const host_t& host) {
    // Host name length and data
    uint32_t host_name_len = htonl(host.host_name.size());
    buffer.insert(buffer.end(), (uint8_t*)&host_name_len, (uint8_t*)&host_name_len + sizeof(host_name_len));
    buffer.insert(buffer.end(), host.host_name.begin(), host.host_name.end());

    // Host IP length and data
    uint32_t host_ip_len = htonl(host.host_ip.size());
    buffer.insert(buffer.end(), (uint8_t*)&host_ip_len, (uint8_t*)&host_ip_len + sizeof(host_ip_len));
    buffer.insert(buffer.end(), host.host_ip.begin(), host.host_ip.end());

    // Number of devices
    uint32_t num_devices = htonl(host.num_devices);
    buffer.insert(buffer.end(), (uint8_t*)&num_devices, (uint8_t*)&num_devices + sizeof(num_devices));

    for (int i = 0; i < host.num_devices; ++i) {
        const device_t& device = host.devices[i];

        // Virtual interface length and data
        uint32_t virtual_intf_len = htonl(strlen(device.virtual_intf));
        buffer.insert(buffer.end(), (uint8_t*)&virtual_intf_len, (uint8_t*)&virtual_intf_len + sizeof(virtual_intf_len));
        buffer.insert(buffer.end(), (uint8_t*)device.virtual_intf, (uint8_t*)device.virtual_intf + strlen(device.virtual_intf));

        // Virtual IP
        buffer.insert(buffer.end(), (uint8_t*)&device.virtual_ip, (uint8_t*)&device.virtual_ip + sizeof(device.virtual_ip));

        // Number of interfaces
        uint32_t num_interfaces = htonl(device.num_interfaces);
        buffer.insert(buffer.end(), (uint8_t*)&num_interfaces, (uint8_t*)&num_interfaces + sizeof(num_interfaces));

        for (int j = 0; j < device.num_interfaces; ++j) {
            const planar_interface_t& planar_intf = device.planar_intfs[j];

            // Planar interface ID length and data
            uint32_t planar_id_len = htonl(strlen(planar_intf.id));
            buffer.insert(buffer.end(), (uint8_t*)&planar_id_len, (uint8_t*)&planar_id_len + sizeof(planar_id_len));
            buffer.insert(buffer.end(), (uint8_t*)planar_intf.id, (uint8_t*)planar_intf.id + strlen(planar_intf.id));

            // Planar interface name length and data
            uint32_t planar_name_len = htonl(strlen(planar_intf.name));
            buffer.insert(buffer.end(), (uint8_t*)&planar_name_len, (uint8_t*)&planar_name_len + sizeof(planar_name_len));
            buffer.insert(buffer.end(), (uint8_t*)planar_intf.name, (uint8_t*)planar_intf.name + strlen(planar_intf.name));

            // Planar interface IPv4
            buffer.insert(buffer.end(), (uint8_t*)&planar_intf.ipv4_addr, (uint8_t*)&planar_intf.ipv4_addr + sizeof(planar_intf.ipv4_addr));

            // Planar interface IPv6
            buffer.insert(buffer.end(), (uint8_t*)&planar_intf.ipv6_addr, (uint8_t*)&planar_intf.ipv6_addr + sizeof(planar_intf.ipv6_addr));
        }
    }
}

std::vector<uint8_t> serialize_all_hosts(const host_db_t& host_db) {
    std::vector<uint8_t> buffer;
    auto& all_hosts = host_db.all_hosts;

    // Number of hosts
    uint32_t num_hosts = htonl(all_hosts.size());
    buffer.insert(buffer.end(), (uint8_t*)&num_hosts, (uint8_t*)&num_hosts + sizeof(num_hosts));

    for (const auto& pair : all_hosts) {
	const host_t& host = pair.second;
        serialize_host(buffer, host);
    }
    return buffer;
}

void deserialize_host(const std::vector<uint8_t>& buffer, host_t& host, size_t& offset) {
    std::string host_name;
    std::string host_ip;

    // Host name length and data
    uint32_t host_name_len = ntohl(*(uint32_t*)(buffer.data() + offset));
    offset += sizeof(host_name_len);
    host_name.assign((char*)(buffer.data() + offset), host_name_len);
    offset += host_name_len;

    // Host IP length and data
    uint32_t host_ip_len = ntohl(*(uint32_t*)(buffer.data() + offset));
    offset += sizeof(host_ip_len);
    host_ip.assign((char*)(buffer.data() + offset), host_ip_len);
    offset += host_ip_len;

    // Number of devices
    uint32_t num_devices = ntohl(*(uint32_t*)(buffer.data() + offset));
    offset += sizeof(num_devices);

    host.num_devices = num_devices; // Set the number of devices

    for (uint32_t j = 0; j < num_devices; ++j) {
        device_t& device = host.devices[j]; // Get a reference to the device

        // Virtual interface length and data
        uint32_t virtual_intf_len = ntohl(*(uint32_t*)(buffer.data() + offset));
        offset += sizeof(virtual_intf_len);
        memcpy(device.virtual_intf, (char*)(buffer.data() + offset), virtual_intf_len);
        device.virtual_intf[virtual_intf_len] = '\0'; // Null terminate
        offset += virtual_intf_len;

        // Virtual IP
        memcpy(&device.virtual_ip, buffer.data() + offset, sizeof(device.virtual_ip));
        offset += sizeof(device.virtual_ip);

        // Number of interfaces
        uint32_t num_interfaces = ntohl(*(uint32_t*)(buffer.data() + offset));
        offset += sizeof(num_interfaces);

        device.num_interfaces = num_interfaces; // Set the number of interfaces

        for (uint32_t k = 0; k < num_interfaces; ++k) {
            planar_interface_t& planar_intf = device.planar_intfs[k]; // Get reference to the planar interface

            // Planar interface ID length and data
            uint32_t planar_id_len = ntohl(*(uint32_t*)(buffer.data() + offset));
            offset += sizeof(planar_id_len);
            memcpy(planar_intf.id, (char*)(buffer.data() + offset), planar_id_len);
            planar_intf.id[planar_id_len] = '\0'; // Null terminate
            offset += planar_id_len;

            // Planar interface name length and data
            uint32_t planar_name_len = ntohl(*(uint32_t*)(buffer.data() + offset));
            offset += sizeof(planar_name_len);
            memcpy(planar_intf.name, (char*)(buffer.data() + offset), planar_name_len);
            planar_intf.name[planar_name_len] = '\0'; // Null terminate
            offset += planar_name_len;

            // Planar interface IPv4
            memcpy(&planar_intf.ipv4_addr, buffer.data() + offset, sizeof(planar_intf.ipv4_addr));
            offset += sizeof(planar_intf.ipv4_addr);

            // Planar interface IPv6
            memcpy(&planar_intf.ipv6_addr, buffer.data() + offset, sizeof(planar_intf.ipv6_addr));
            offset += sizeof(planar_intf.ipv6_addr);
        }
    }
    host.host_name = host_name;
    host.host_ip = host_ip;
}

host_t deserialize_host(const std::vector<uint8_t>& buffer) {
    host_t host;
    size_t offset = 0;

    deserialize_host(buffer, host, offset);
    return host;
}

void deserialize_all_hosts(host_db_t& host_db, const std::vector<uint8_t>& buffer) {
    auto& all_hosts = host_db.all_hosts;
    size_t offset = 0;

    // Number of hosts
    uint32_t num_hosts = ntohl(*(uint32_t*)(buffer.data() + offset));
    offset += sizeof(num_hosts);

    for (uint32_t i = 0; i < num_hosts; ++i) {
        host_t host;
        deserialize_host(buffer, host, offset);
        all_hosts[host.host_name] = host;
    }
}

int
print_planar_config (const host_t& host) {
    std::cout << "Host Name         : " << host.host_name << std::endl;
    std::cout << "Host IP           : " << host.host_ip << std::endl;
    std::cout << "Devices           : " << std::endl;

    for (const auto& dev : host.devices) {
        char virtual_ip_str[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &dev.virtual_ip, virtual_ip_str, INET_ADDRSTRLEN);
        std::cout << "\tVirtual Intf      : " << dev.virtual_intf << std::endl;
        std::cout << "\tVirtual IP        : " << virtual_ip_str << std::endl;
        std::cout << "\tPlanar Interfaces :" << std::endl;

        for (int j = 0; j < dev.num_interfaces; ++j) {
	    char ipv4_addr_str[INET_ADDRSTRLEN];
            char ipv6_addr_str[INET6_ADDRSTRLEN];

            std::cout << "    - ID: " << dev.planar_intfs[j].id << "\n";
            std::cout << "      Name: " << dev.planar_intfs[j].name << "\n";

            // IPv4
            if (dev.planar_intfs[j].ipv4_addr.s_addr != 0) { // Check if IPv4 address is set
                if (inet_ntop(AF_INET, &dev.planar_intfs[j].ipv4_addr, ipv4_addr_str, INET_ADDRSTRLEN) != nullptr) {
                    std::cout << "      IPv4 Address: " << ipv4_addr_str << std::endl;
                } else {
                    std::cerr << "inet_ntop (IPv4) failed: " << strerror(errno) << std::endl;
                }
            }

            // IPv6
            if (!IN6_IS_ADDR_UNSPECIFIED(&dev.planar_intfs[j].ipv6_addr)) { // Check if IPv6 address is set
                if (inet_ntop(AF_INET6, &dev.planar_intfs[j].ipv6_addr, ipv6_addr_str, INET6_ADDRSTRLEN) != nullptr) {
                    std::cout << "      IPv6 Address: " << ipv6_addr_str << std::endl;
                } else {
                    std::cerr << "inet_ntop (IPv6) failed: " << strerror(errno) << std::endl;
                }
            }
        }
        std::cout << std::endl;
    }
    return ANP_SUCCESS;
}

int
parse_planar_config (std::string planar_cfg_file, host_t& host) {
    int device_count = 0;
    boost::property_tree::ptree pt;

    try {
        if (planar_cfg_file.empty()) {
            std::cout << "Planar config json not specified" << std::endl;
            return ANP_FAILURE;
        }
        boost::property_tree::read_json(planar_cfg_file, pt);

        host.host_name = pt.get<std::string>(JKEY_HOST_NAME);
        host.host_ip = pt.get<std::string>(JKEY_HOST_IP);

        // loop through the cfg attributes and build cache
        for (const auto& devices_node : pt.get_child(JKEY_HOST_DEVICES)) {
            if (device_count >= MAX_DEVICES) break;

            device_t& dev = host.devices[device_count++];
            memset(&dev, 0, sizeof(device_t));
            strncpy(dev.virtual_intf, devices_node.second.get<std::string>(JKEY_VIRTUAL_INTERFACE).c_str(), MAX_STR_LEN - 1);
            inet_pton(AF_INET, devices_node.second.get<std::string>(JKEY_VIRTUAL_IP).c_str(), &dev.virtual_ip);

            // process planar intfs
            int iface_count = 0;
            for (const auto& intf_entry : devices_node.second.get_child(JKEY_PLANAR_INTERFACES)) {
                if (iface_count >= MAX_INTERFACES) break;

                planar_interface_t& pi = dev.planar_intfs[iface_count++];
                memset(&pi, 0, sizeof(planar_interface_t));

                strncpy(pi.id, intf_entry.second.get<std::string>(JKEY_PLANAR_INTF_ID).c_str(), MAX_STR_LEN - 1);
                strncpy(pi.name, intf_entry.second.get<std::string>(JKEY_PLANAR_INTF_NAME).c_str(), MAX_STR_LEN - 1);
                inet_pton(AF_INET, intf_entry.second.get<std::string>(JKEY_PLANAR_INTF_IPV4_ADDR).c_str(), &pi.ipv4_addr);
                inet_pton(AF_INET6, intf_entry.second.get<std::string>(JKEY_PLANAR_INTF_IPV6_ADDR).c_str(), &pi.ipv6_addr);

                //host_db.planar_to_virtual_map[pi.ipv4_addr.s_addr] = dev.virtual_ip;
                //host_db.virtual_to_planar_map[dev.virtual_ip.s_addr].push_back(pi);
            }
            dev.num_interfaces = iface_count;
        }
	host.num_devices = device_count;
    } catch (const std::exception& e) {
        std::cout << "error parsing JSON: " << e.what() << std::endl;
    }

    print_planar_config(host);

    return ANP_SUCCESS;
}

struct ncclBootstrapHandle {
  uint64_t magic;
  union anpNcclSocketAddress addr;
};
static_assert(sizeof(struct ncclBootstrapHandle) <= sizeof(ncclUniqueId), "Bootstrap handle is too large to fit inside NCCL unique ID");

ncclResult_t anp_bootstrapNetInit();
ncclResult_t anp_bootstrapCreateRoot(struct ncclBootstrapHandle* handle, bool idFromEnv);
ncclResult_t anp_bootstrapGetUniqueId(struct ncclBootstrapHandle* handle);
ncclResult_t anp_bootstrapInit(struct ncclBootstrapHandle* handle, struct ncclComm* comm);
ncclResult_t anp_bootstrapSplit(struct ncclBootstrapHandle* handle, struct ncclComm* comm, struct ncclComm* parent, int color, int key, int* parentRanks);
ncclResult_t anp_bootstrapAllGather(void* commState, void* allData, int size);
ncclResult_t anp_bootstrapSend(void* commState, int peer, int tag, void* data, int size);
ncclResult_t anp_bootstrapRecv(void* commState, int peer, int tag, void* data, int size);
ncclResult_t anp_bootstrapBarrier(void* commState, int rank, int nranks, int tag);
ncclResult_t anp_bootstrapBroadcast(void* commState, int rank, int nranks, int root, void* bcastData, int size);
ncclResult_t anp_bootstrapIntraNodeBarrier(void* commState, int *ranks, int rank, int nranks, int tag);
ncclResult_t anp_bootstrapIntraNodeAllGather(void* commState, int *ranks, int rank, int nranks, void* allData, int size);
ncclResult_t anp_bootstrapIntraNodeBroadcast(void* commState, int *ranks, int rank, int nranks, int root, void* bcastData, int size);
ncclResult_t anp_bootstrapClose(void* commState);
ncclResult_t anp_bootstrapAbort(void* commState);
#endif
