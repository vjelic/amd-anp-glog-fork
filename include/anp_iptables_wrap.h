#ifndef NCCL_ANP_IPTABLES_WRAP_H_
#define NCCL_ANP_IPTABLES_WRAP_H_

#include <iostream>
#include <cstdlib>
#include <string>
#include <sstream>

// Structure to hold iptables rule parameters
struct IptablesRule {
    std::string action;      // append, check, delete
    std::string table;       // nat, filter, etc.
    std::string chain;       // INPUT, OUTPUT, POSTROUTING, etc.
    std::string match_type;  // SIP, DIP
    std::string match_value; // Value to match on (IP address)
    std::string iface_type;  // in, out
    std::string iface_name;  // Interface name
    std::string jump_target; // SNAT, DNAT
    std::string translate_ip;// Translation IP for SNAT/DNAT
};

// Global variable to store detected iptables backend
std::string iptables_backend = "";

// Function to detect iptables backend (legacy or nftables), only detects once
std::string detect_iptables_backend() {
    if (!iptables_backend.empty()) {
        return iptables_backend;
    }

    FILE* pipe = popen("iptables --version 2>/dev/null", "r");
    if (!pipe) return "unknown";

    char buffer[128];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);

    if (result.find("nf_tables") != std::string::npos) {
        iptables_backend = "nf_tables";
    } else if (result.find("legacy") != std::string::npos) {
        iptables_backend = "legacy";
    } else {
        iptables_backend = "unknown";
    }

    return iptables_backend;
}

// Function to construct iptables command from struct
std::string construct_iptables_command(const IptablesRule& rule) {
    std::string command = "iptables -t " + rule.table + " -" + rule.action + " " + rule.chain;
    if (!rule.match_type.empty() && !rule.match_value.empty()) {
        command += (rule.match_type == "SIP" ? " -s " : " -d ") + rule.match_value;
    }
    if (!rule.iface_name.empty()) {
        command += (rule.iface_type == "in" ? " -i " : " -o ") + rule.iface_name;
    }
    if (!rule.jump_target.empty()) {
        command += " -j " + rule.jump_target;
        if (!rule.translate_ip.empty()) {
            if (rule.jump_target == "SNAT") {
                command += " --to-source " + rule.translate_ip;
            } else if (rule.jump_target == "DNAT") {
                command += " --to-destination " + rule.translate_ip;
            }
        }
    }
    return command;
}

// Function to convert an IptablesRule to an equivalent nftables command
std::string convert_to_nftables(const IptablesRule& rule) {
    std::ostringstream command;

    command << "nft add rule ip " << rule.table << " " << rule.chain;

    if (!rule.match_type.empty() && !rule.match_value.empty()) {
        command << " ip " << (rule.match_type == "SIP" ? "saddr" : "daddr") << " " << rule.match_value;
    }
    if (!rule.iface_name.empty()) {
        command << " " << (rule.iface_type == "in" ? "iif" : "oif") << " " << rule.iface_name;
    }
    if (!rule.jump_target.empty()) {
        if (rule.jump_target == "SNAT") {
            command << " snat to " << rule.translate_ip;
        } else if (rule.jump_target == "DNAT") {
            command << " dnat to " << rule.translate_ip;
        } else {
            command << " " << rule.jump_target;
        }
    }

    return command.str();
}

// Function to set up nftables nat table and chains if they do not exist (only once)
void setup_nft_nat_table() {
    static bool initialized = false;
    if (initialized) return;

    system("nft list table ip nat >/dev/null 2>&1 || nft add table ip nat");
    system("nft list chain ip nat POSTROUTING >/dev/null 2>&1 || nft add chain ip nat POSTROUTING { type nat hook postrouting priority 100 \\; }");
    system("nft list chain ip nat OUTPUT >/dev/null 2>&1 || nft add chain ip nat OUTPUT { type nat hook output priority 0 \\; }");
    system("nft list chain ip nat INPUT >/dev/null 2>&1 || nft add chain ip nat INPUT { type nat hook input priority 0 \\; }");

    initialized = true;
}

// Function to check if an iptables rule already exists
bool rule_exists(const std::string& check_command) {
    int status = system(check_command.c_str());
    return (status == 0);
}

// Wrapper function
int execute_iptables_command(const IptablesRule& rule) {
    std::string backend = detect_iptables_backend();
    std::string command;

    if (backend == "nf_tables") {
        setup_nft_nat_table();
        command = convert_to_nftables(rule);
    } else {
        command = construct_iptables_command(rule);
    }

    // If action is append (A), check if the rule exists first
    if (rule.action == "A") {
        std::string check_command = command;
        size_t pos = check_command.find(" -A ");
        if (pos != std::string::npos) {
            check_command.replace(pos + 1, 1, "C"); // Change -A to -C for checking rule existence
        }
        if (rule_exists(check_command)) {
            std::cout << "Rule already exists, skipping addition." << std::endl;
            return 0;
        }
    }
    
    std::cout << "Executing: " << command << std::endl;
    int status = system(command.c_str());
    
    return (status == 0) ? 0 : -1; // Success = 0, Failure = -1
}
#endif
