/*
 * bootstrap.cc
 *
 * Copyright(C) Advanced Micro Devices, Inc. All rights reserved.
 * You may not use this software and documentation (if any) (collectively,
 * the "Materials") except in compliance with the terms and conditions of
 * the Software License Agreement included with the Materials or otherwise as
 * set forth in writing and signed by you and an authorized signatory of AMD.
 * If you do not have a copy of the Software License Agreement, contact your
 * AMD representative for a copy.
 *
 * You agree that you will not reverse engineer or decompile the Materials,
 * in whole or in part, except as allowed by applicable law.
 *
 * THE MATERIALS ARE DISTRIBUTED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR
 * REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
 *
 * Summary:
 *   Bootstrap config logic uses the RCCL socket layer (from socket.cc) to perform a distributed
 *   configuration gathering and initialization. It reads a list of IP addresses (one per line)
 *   from a file (which includes the local host's IP). 
 *   TODO : This needs to change going forward.
 *   The host with the numerically lowest IP is elected as the Root Node (RN), and all other hosts
 *   act as Leaf Nodes (LNs).
 *
 *   Code Flow:
 *     1. Read the IP list file into an array.
 *     2. Determine the local host's IP by matching local network interface addresses
 *        with one of the IPs in the file.
 *     3. Elect the RN by comparing all IPs (converted to a numerical value) and choosing the lowest.
 *     4. Based on the role:
 *
 *        [Root Node (RN) Path]:
 *         a. Initialize a listening socket on the local IP and DEFAULT_PORT using RCCL's API.
 *         b. Wait (accept) for incoming connections from all LNs.
 *         c. For each accepted connection, record the remote IP.
 *         d. Send a PLANAR_CONFIG_REQUEST message (TLV type 1 with zero-length payload) to each LN.
 *         e. Spawn a thread per connection to receive a CONFIG_RESPONSE message (TLV type 2) from the LN.
 *         f. Each thread saves the received configuration to a file in /tmp/ (named using the LN's IP).
 *         g. Once all responses are gathered, build a composite configuration (e.g., a JSON array of all configs).
 *         h. Send a COMPOSITE_CONFIG message (TLV type 3) with the composite configuration to each LN.
 *         i. Close all connection sockets and the listening socket.
 *
 *        [Leaf Node (LN) Path]:
 *         a. Repeatedly attempt to connect to the RN (using a retry loop) via RCCL's socket connect API.
 *         b. Once connected, wait for a PLANAR_CONFIG_REQUEST message from the RN.
 *         c. On receipt, read the local file PLANAR_CONFIG_FILE and send its contents
 *            back as a CONFIG_RESPONSE message (TLV type 2) in TLV format.
 *         d. Wait for the COMPOSITE_CONFIG message (TLV type 3) from the RN.
 *         e. Save the composite configuration to /tmp/ (prefixed with the local IP).
 *         f. Close the connection.
 *
 *   Message Format (TLV):
 *     - Type: 4 bytes (network byte order)
 *     - Length: 4 bytes (network byte order)
 *     - Value: 'Length' bytes (payload)
 *
 *   Message Types:
 *     1: PLANAR_CONFIG_REQUEST (RN -> LN, no payload)
 *     2: CONFIG_RESPONSE       (LN -> RN, payload = config file content)
 *     3: COMPOSITE_CONFIG      (RN -> LN, payload = composite configuration)
 *
 *   Logging is performed with the ANP_LOG macro.
 *
 *   Communication is strictly done via the RCCL socket layer (anpNcclSocketInit, anpNcclSocketListen,
 *   anpNcclSocketAccept, anpNcclSocketConnect, anpNcclSocketSend, anpNcclSocketRecv, anpNcclSocketClose).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include "anp_param.h"
#include "bootstrap_socket.h"
#include "anp_bootstrap.h"

typedef struct {
    char ip_list_file[256];
} BootstrapArgs;

// Message type definitions for TLV messages.
#define MSG_PLANAR_CONFIG_REQUEST 1
#define MSG_CONFIG_RESPONSE       2
#define MSG_COMPOSITE_CONFIG      3

// Fixed port for bootstrap connections.
#define DEFAULT_PORT 34567
// Fixed magic number for handshake.
#define SOCKET_MAGIC 0xA1B2C3D4E5F6ABCDULL

// Maximum buffer size (8KB) for receiving TLV messages.
#define MAX_BUFFER_SIZE 8192
// Maximum number of IPs expected in the file.
#define MAX_IPS 64

// TODO : Keep this configPath as a tunable instead of hard-coding
#define PLANAR_CONFIG_FILE "/etc/ainic_planar_config.json"

// Structure to hold a socket connection (for RN connections from LNs)
struct Connection {
    anpNcclSocket sock;
    char peer_ip[INET_ADDRSTRLEN];
};

// Structure for thread arguments used by RN to receive config responses.
struct RecvThreadArg {
    struct Connection *conn;
};

// Global variables for synchronizing received responses.
pthread_mutex_t response_mutex = PTHREAD_MUTEX_INITIALIZER;
int responses_received = 0;
int total_leaves = 0;

// Host information datastore
host_db_t host_db;

/* ---------------------------------------------------------------------
 * ANP Helper function: Convert IPv4 string to uint32_t (host byte order)
 * --------------------------------------------------------------------- */
unsigned int ip_to_uint(const char *ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return 0xffffffff;
    }
    return ntohl(addr.s_addr);
}

/* ---------------------------------------------------------------------
 * ANP Helper function: Read IP list from a file.
 * Each line in the file is assumed to contain one IP address.
 * Returns the number of IPs read, or -1 on error.
 * --------------------------------------------------------------------- */
int read_ip_list(const char *filename, char ip_list[][INET_ADDRSTRLEN], int max_ips) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        ANP_LOG("ERROR: Unable to open IP list file: %s", filename);
        return -1;
    }
    int count = 0;
    while (count < max_ips && fgets(ip_list[count], INET_ADDRSTRLEN, fp)) {
        // Remove newline characters.
        ip_list[count][strcspn(ip_list[count], "\r\n")] = '\0';
        if (strlen(ip_list[count]) > 0)
            count++;
    }
    fclose(fp);
    return count;
}

/* ---------------------------------------------------------------------
 * ANP Helper function: Get local IP by matching one of the IPs in the list.
 * Returns 0 on success and fills local_ip, or -1 on failure.
 * --------------------------------------------------------------------- */
int get_local_ip(char local_ip[INET_ADDRSTRLEN], char ip_list[][INET_ADDRSTRLEN], int ip_count) {
    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) != 0) {
        ANP_LOG("ERROR: getifaddrs failed: %s", strerror(errno));
        return -1;
    }
    int found = 0;
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr, addr_str, sizeof(addr_str));
            int i;
            for (i = 0; i < ip_count; i++) {
                if (strcmp(addr_str, ip_list[i]) == 0) {
                    strncpy(local_ip, addr_str, INET_ADDRSTRLEN);
                    found = 1;
                    break;
                }
            }
            if (found)
                break;
        }
    }
    freeifaddrs(ifap);
    if (!found) {
        ANP_LOG("ERROR: Local IP not found in IP list");
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------------
 * TLV Send Helper:
 * Sends a TLV message over the given socket.
 * Header: 4-byte type + 4-byte length (both in network byte order)
 * Followed by 'length' bytes of payload.
 * Returns 0 on success, -1 on error.
 * --------------------------------------------------------------------- */
int send_tlv(anpNcclSocket *sock, unsigned int type, void *payload, unsigned int length) {
    unsigned int net_type = htonl(type);
    unsigned int net_length = htonl(length);
    if (anpNcclSocketSend(sock, &net_type, sizeof(net_type)) != ncclSuccess) {
        ANP_LOG("ERROR: anpNcclSocketSend failed (type)");
        return -1;
    }
    if (anpNcclSocketSend(sock, &net_length, sizeof(net_length)) != ncclSuccess) {
        ANP_LOG("ERROR: anpNcclSocketSend failed (length)");
        return -1;
    }
    if (length > 0 && payload != NULL) {
        if (anpNcclSocketSend(sock, payload, length) != ncclSuccess) {
            ANP_LOG("ERROR: anpNcclSocketSend failed (payload)");
            return -1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------
 * TLV Receive Helper:
 * Receives a TLV message from the given socket.
 * Reads the 8-byte header (type and length) then reads 'length' bytes.
 * Sets *msg_type and *payload_size accordingly.
 * Returns 0 on success, -1 on error.
 * --------------------------------------------------------------------- */
int recv_tlv(anpNcclSocket *sock, unsigned int *msg_type, void *payload, unsigned int *payload_size) {
    unsigned int net_type = 0, net_length = 0;
    if (anpNcclSocketRecv(sock, &net_type, sizeof(net_type)) != ncclSuccess) {
        ANP_LOG("ERROR: anpNcclSocketRecv failed (type)");
        return -1;
    }
    if (anpNcclSocketRecv(sock, &net_length, sizeof(net_length)) != ncclSuccess) {
        ANP_LOG("ERROR: anpNcclSocketRecv failed (length)");
        return -1;
    }
    *msg_type = ntohl(net_type);
    *payload_size = ntohl(net_length);
    if (*payload_size > 0 && payload != NULL) {
        if (anpNcclSocketRecv(sock, payload, *payload_size) != ncclSuccess) {
            ANP_LOG("ERROR: anpNcclSocketRecv failed (payload)");
            return -1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------
 * RN Receive Thread Function:
 * Each thread receives a CONFIG_RESPONSE (TLV type 2) message from one LN.
 * It then saves the received config file to /tmp/<peer_ip>_ainic_planar_config.json.
 * TODO : Use Logarajan's code to parse each JSON and add to the composite
 * config
 * --------------------------------------------------------------------- */
void *recv_config_thread(void *arg) {
    struct RecvThreadArg *targ = (struct RecvThreadArg*) arg;
    anpNcclSocket *sock = &targ->conn->sock;
    char peer_ip[INET_ADDRSTRLEN];
    strncpy(peer_ip, targ->conn->peer_ip, INET_ADDRSTRLEN);

    unsigned int msg_type = 0, payload_size = 0;
    if (recv_tlv(sock, &msg_type, NULL, &payload_size) != 0) {
        ANP_LOG("ERROR: Failed to receive TLV header from %s", peer_ip);
        pthread_exit(NULL);
    }
    if (msg_type != MSG_CONFIG_RESPONSE) {
        ANP_LOG("ERROR: Unexpected message type %u from %s (expected CONFIG_RESPONSE)", msg_type, peer_ip);
        pthread_exit(NULL);
    }
    std::vector<uint8_t> buffer;
    if (payload_size > 0) {
        buffer.resize(payload_size);
        if (anpNcclSocketRecv(sock, buffer.data(), payload_size) != ncclSuccess) {
            ANP_LOG("ERROR: Failed to receive payload from %s", peer_ip);
            pthread_exit(NULL);
        }
    }
    ANP_LOG("Received CONFIG_RESPONSE from %s (%u bytes)", peer_ip, payload_size);

    host_t host = deserialize_host(buffer);
    print_planar_config(host);

    // Increment global response counter
    pthread_mutex_lock(&response_mutex);
    host_db.all_hosts[host.host_ip.c_str()] = host;
    responses_received++;
    pthread_mutex_unlock(&response_mutex);
    pthread_exit(NULL);
}

void *anp_rccl_bootstrap_handler(void *arg) {
    RCCLBootstrapArgs *bootargs = (RCCLBootstrapArgs*) arg;
    if (bootargs->is_root) {
        ANP_LOG("This host (%s) is elected as Root Node (RN).", bootargs->root_ip);
    } else {
        ANP_LOG("This host is a Leaf Node (LN). Root IP: %s", bootargs->root_ip);
    }

    // Based on role, run appropriate function.
    if (bootargs->is_root) {
        // Run Root Node function
        // (see below for run_root_node implementation)
        extern int run_root_node(int ip_count);
        run_root_node(bootargs->total_hosts);
    } else {
        // Run Leaf Node function
        extern int run_leaf_node(const char *root_ip);
        run_leaf_node(bootargs->root_ip);
    }
    pthread_exit(NULL);
}

void *anp_bootstrap_handler(void *arg) {
     BootstrapArgs *bootArgs = (BootstrapArgs*) arg;
     char ip_list[MAX_IPS][INET_ADDRSTRLEN];
     int ip_count = read_ip_list(bootArgs->ip_list_file, ip_list, MAX_IPS);
     if (ip_count <= 0) {
         ANP_LOG("ERROR: No IPs found in file: %s", bootArgs->ip_list_file);
         pthread_exit(NULL);
     }

    // Determine local IP from system interfaces that match one in the list.
    char local_ip[INET_ADDRSTRLEN];
    if (get_local_ip(local_ip, ip_list, ip_count) != 0) {
        ANP_LOG("ERROR: Cannot determine local IP.");
	pthread_exit(NULL);
    }
    ANP_LOG("Local IP determined as %s", local_ip);

    // Elect the Root Node (RN): select the lowest IP (numerically)
    char root_ip[INET_ADDRSTRLEN];
    strcpy(root_ip, ip_list[0]);
    {
        unsigned int lowest = ip_to_uint(ip_list[0]);
        int i;
        for (i = 1; i < ip_count; i++) {
            unsigned int val = ip_to_uint(ip_list[i]);
            if (val < lowest) {
                lowest = val;
                strcpy(root_ip, ip_list[i]);
            }
        }
    }
    int isRoot = (strcmp(local_ip, root_ip) == 0);
    if (isRoot) {
        ANP_LOG("This host (%s) is elected as Root Node (RN).", local_ip);
    } else {
        ANP_LOG("This host (%s) is a Leaf Node (LN). Root IP: %s", local_ip, root_ip);
    }

    // Based on role, run appropriate function.
    if (isRoot) {
        // Run Root Node function
        // (see below for run_root_node implementation)
        extern int run_root_node(int ip_count);
        run_root_node(ip_count);
    } else {
        // Run Leaf Node function
        extern int run_leaf_node(const char *root_ip);
        run_leaf_node(root_ip);
    }
    pthread_exit(NULL);
}

/* ---------------------------------------------------------------------
 * TODO : Migrate this entire flow to anpNetInit and protect with a global
 * semaphore
 * Main Program Flow:
 *
 *   1. Read the IP list file (one IP per line).
 *   2. Determine the local IP by matching local interfaces to the list.
 *   3. Elect the Root Node (RN) by choosing the lowest IP (numerically).
 *   4. Depending on the role:
 *      - If RN:
 *          a. Initialize a listening socket on the local IP and DEFAULT_PORT.
 *          b. Accept connections from all other hosts (LNs).
 *          c. Send a PLANAR_CONFIG_REQUEST (TLV type 1) to each LN.
 *          d. Spawn threads to receive CONFIG_RESPONSE (TLV type 2) messages.
 *          e. Wait for all responses, then build a composite configuration.
 *          f. Send a COMPOSITE_CONFIG (TLV type 3) to each LN.
 *          g. Close all sockets.
 *      - If LN:
 *          a. Retry connecting to the RN until successful.
 *          b. Wait for PLANAR_CONFIG_REQUEST from the RN.
 *          c. Read "/etc/ainic_planar_config.json" and send it as a CONFIG_RESPONSE.
 *          d. Wait for COMPOSITE_CONFIG from the RN.
 *          e. Save the composite configuration locally.
 *          f. Close the connection.
 * --------------------------------------------------------------------- */

int main(int argc, char **argv) {
    pthread_t thread;
    BootstrapArgs args;
    if (argc < 2) {
        ANP_LOG("Usage: %s <ip_list_file>", argv[0]);
        return EXIT_FAILURE;
    }

    char ip_list[MAX_IPS][INET_ADDRSTRLEN];
    int ip_count = read_ip_list(argv[1], ip_list, MAX_IPS);
    if (ip_count <= 0) {
        ANP_LOG("ERROR: No IPs found in file.");
        return EXIT_FAILURE;
    }
     strncpy(args.ip_list_file, argv[1], sizeof(args.ip_list_file));
     int ret = pthread_create(&thread, NULL, anp_bootstrap_handler, (void *)&args);
     if (ret != 0) {
         fprintf(stderr, "Error creating thread: %s\n", strerror(ret));
         return EXIT_FAILURE;
     }
     
     // Optionally wait (join) for the thread to finish.
     pthread_join(thread, NULL);
     return EXIT_SUCCESS;
}

/* ---------------------------------------------------------------------
 * Root Node (RN) Function:
 *   1. Create a listening socket on local_ip and DEFAULT_PORT.
 *   2. Accept connections from (ip_count - 1) Leaf Nodes.
 *   3. For each connection, send a PLANAR_CONFIG_REQUEST (TLV type 1).
 *   4. Spawn a thread per connection to receive a CONFIG_RESPONSE (TLV type 2).
 *   5. Wait for all responses and build a composite configuration.
 *   6. Send COMPOSITE_CONFIG (TLV type 3) to each LN.
 *   7. Close all connections and the listening socket.
 * --------------------------------------------------------------------- */
int run_root_node(int ip_count) {
    anpNcclSocket listenSock;
    union anpNcclSocketAddress addr;
    
    // Parse the local host ainic_planar_config.json and store into datastore
    host_t host;
    parse_planar_config(PLANAR_CONFIG_FILE, host);
    host_db.local_ip = host.host_ip.c_str();
    host_db.all_hosts[host.host_ip.c_str()] = host;

    memset(&addr, 0, sizeof(addr));
    addr.sin.sin_family = AF_INET;
    inet_pton(AF_INET,  host.host_ip.c_str(), &addr.sin.sin_addr);
    addr.sin.sin_port = htons(DEFAULT_PORT);

    if (anpNcclSocketInit(&listenSock, &addr, SOCKET_MAGIC, anpNcclSocketTypePluginBootstrap, NULL, 0) != ncclSuccess) {
        ANP_LOG("RN ERROR: anpNcclSocketInit failed for listening socket.");
        return EXIT_FAILURE;
    }
    if (anpNcclSocketListen(&listenSock) != ncclSuccess) {
        ANP_LOG("RN ERROR: anpNcclSocketListen failed.");
        return EXIT_FAILURE;
    }

    int total_LNs = ip_count - 1;
    ANP_LOG("RN listening on %s:%d. waiting for %d LNs",  host.host_ip.c_str(), DEFAULT_PORT, total_LNs);
    struct Connection *connArr = (struct Connection*)malloc(total_LNs * sizeof(struct Connection));
    if (!connArr) {
        ANP_LOG("RN ERROR: malloc failed for connection array.");
        return EXIT_FAILURE;
    }
    int accepted = 0;
    while (accepted < total_LNs) {
        if (anpNcclSocketAccept(&connArr[accepted].sock, &listenSock) != ncclSuccess) {
            ANP_LOG("RN WARNING: anpNcclSocketAccept failed, retrying...");
            continue;
        }
        // Extract remote IP from the accepted connection.
        union anpNcclSocketAddress peerAddr = connArr[accepted].sock.addr;
        if (peerAddr.sa.sa_family == AF_INET) {
            inet_ntop(AF_INET, &peerAddr.sin.sin_addr, connArr[accepted].peer_ip, INET_ADDRSTRLEN);
        } else {
            strncpy(connArr[accepted].peer_ip, "unknown", INET_ADDRSTRLEN);
        }
        ANP_LOG("RN accepted connection from %s", connArr[accepted].peer_ip);
        accepted++;
    }

    // Send PLANAR_CONFIG_REQUEST (TLV type 1, length 0) to each LN.
    int i;
    for (i = 0; i < total_LNs; i++) {
        if (send_tlv(&connArr[i].sock, MSG_PLANAR_CONFIG_REQUEST, NULL, 0) != 0) {
            ANP_LOG("RN ERROR: Failed to send PLANAR_CONFIG_REQUEST to %s", connArr[i].peer_ip);
        } else {
            ANP_LOG("RN sent PLANAR_CONFIG_REQUEST to %s", connArr[i].peer_ip);
        }
    }

    // Create threads to receive CONFIG_RESPONSE messages.
    total_leaves = total_LNs;
    pthread_t *threads = (pthread_t*)malloc(total_LNs * sizeof(pthread_t));
    struct RecvThreadArg *threadArgs = (struct RecvThreadArg*)malloc(total_LNs * sizeof(struct RecvThreadArg));
    if (!threads || !threadArgs) {
        ANP_LOG("RN ERROR: malloc failed for thread structures.");
        free(connArr);
        return EXIT_FAILURE;
    }
    for (i = 0; i < total_LNs; i++) {
        threadArgs[i].conn = &connArr[i];
        if (pthread_create(&threads[i], NULL, recv_config_thread, (void*)&threadArgs[i]) != 0) {
            ANP_LOG("RN ERROR: pthread_create failed for connection %d", i);
        }
    }
    // Wait for all threads to finish.
    for (i = 0; i < total_LNs; i++) {
        pthread_join(threads[i], NULL);
    }
    ANP_LOG("RN received config responses from all LNs.");

    // Build composite configuration.
    //  a. add to the master data structure
    //  b. program routes [TODO]
    //  c. program iptables
    std::vector<uint8_t> composite = serialize_all_hosts(host_db);
    unsigned int comp_len = composite.size();
    ANP_LOG("RN constructed composite config (%u bytes)", comp_len);

    // Send COMPOSITE_CONFIG (TLV type 3) to each LN.
    for (i = 0; i < total_LNs; i++) {
        if (send_tlv(&connArr[i].sock, MSG_COMPOSITE_CONFIG, composite.data(), comp_len) != 0) {
            ANP_LOG("RN ERROR: Failed to send COMPOSITE_CONFIG to %s", connArr[i].peer_ip);
        } else {
            ANP_LOG("RN sent COMPOSITE_CONFIG to %s", connArr[i].peer_ip);
        }
    }

    ANP_LOG("RN program ip table rules");
    apply_local_vip_iptables_rule(host_db);
    apply_remote_vip_iptables_rule(host_db);

    // Close all LN connections and the listening socket.
    for (i = 0; i < total_LNs; i++) {
        anpNcclSocketClose(&connArr[i].sock);
    }
    anpNcclSocketClose(&listenSock);
    ANP_LOG("RN: All connections closed. Exiting.");

    free(connArr);
    free(threads);
    free(threadArgs);
    return EXIT_SUCCESS;
}

/* ---------------------------------------------------------------------
 * Leaf Node (LN) Function:
 *   1. Connect to the RN (retrying until successful).
 *   2. Wait for a PLANAR_CONFIG_REQUEST (TLV type 1) from the RN.
 *   3. Read local config file (/etc/ainic_planar_config.json) and send it as a
 *      CONFIG_RESPONSE (TLV type 2) message.
 *   4. Wait for the COMPOSITE_CONFIG (TLV type 3) from the RN and save it to
 *      /tmp/<local_ip>_composite_config.json.
 *   5. Close the connection.
 * --------------------------------------------------------------------- */
int run_leaf_node(const char *root_ip) {
    anpNcclSocket clientSock;
    union anpNcclSocketAddress addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin.sin_family = AF_INET;
    inet_pton(AF_INET, root_ip, &addr.sin.sin_addr);
    addr.sin.sin_port = htons(DEFAULT_PORT);


    int attempt = 0;
    while (1) {
        attempt++;
        if (anpNcclSocketInit(&clientSock, &addr, SOCKET_MAGIC, anpNcclSocketTypePluginBootstrap, NULL, 0) != ncclSuccess) {
            ANP_LOG("LN: anpNcclSocketInit failed on attempt %d", attempt);
            sleep(1);
            continue;
        }
        ANP_LOG("LN: Attempt %d: Connecting to RN %s:%d...", attempt, root_ip, DEFAULT_PORT);
        if (anpNcclSocketConnect(&clientSock) == ncclSuccess) {
            ANP_LOG("LN: Connected to RN after %d attempts", attempt);
            break;
        }
        ANP_LOG("LN: Connection attempt %d failed. Retrying...", attempt);
        anpNcclSocketClose(&clientSock);
        sleep(1);
    }

    // Wait for PLANAR_CONFIG_REQUEST (TLV type 1) from RN.
    unsigned int msg_type = 0, payload_size = 0;
    if (recv_tlv(&clientSock, &msg_type, NULL, &payload_size) != 0) {
        ANP_LOG("LN: ERROR: Failed to receive PLANAR_CONFIG_REQUEST from RN");
        anpNcclSocketClose(&clientSock);
        return EXIT_FAILURE;
    }
    if (msg_type != MSG_PLANAR_CONFIG_REQUEST) {
        ANP_LOG("LN: ERROR: Unexpected message type %u (expected PLANAR_CONFIG_REQUEST)", msg_type);
        anpNcclSocketClose(&clientSock);
        return EXIT_FAILURE;
    }
    ANP_LOG("LN: Received PLANAR_CONFIG_REQUEST from RN.");

    // Read local config file
    host_t host;
    std::vector<uint8_t> buffer;
    parse_planar_config(PLANAR_CONFIG_FILE, host);
    host_db.local_ip = host.host_ip.c_str();
    serialize_host(buffer, host);

    // Send CONFIG_RESPONSE (TLV type 2)
    if (send_tlv(&clientSock, MSG_CONFIG_RESPONSE, buffer.data(), buffer.size()) != 0) {
        ANP_LOG("LN: ERROR: Failed to send CONFIG_RESPONSE to RN.");
        anpNcclSocketClose(&clientSock);
        return EXIT_FAILURE;
    }
    ANP_LOG("LN: Sent CONFIG_RESPONSE to RN (%ld bytes)", buffer.size());

    // Wait for COMPOSITE_CONFIG (TLV type 3)
    // Block until RN eventually sends the COMPOSITE_CONFIG
    if (recv_tlv(&clientSock, &msg_type, NULL, &payload_size) != 0) {
        ANP_LOG("LN: ERROR: Failed to receive COMPOSITE_CONFIG header from RN.");
        anpNcclSocketClose(&clientSock);
        return EXIT_FAILURE;
    }
    if (msg_type != MSG_COMPOSITE_CONFIG) {
        ANP_LOG("LN: ERROR: Unexpected message type %u (expected COMPOSITE_CONFIG)", msg_type);
        anpNcclSocketClose(&clientSock);
        return EXIT_FAILURE;
    }
    if (payload_size > 0) {
	std::vector<uint8_t> compbuf(payload_size);
        if (anpNcclSocketRecv(&clientSock, compbuf.data(), payload_size) != ncclSuccess) {
            ANP_LOG("LN: ERROR: Failed to receive composite config payload");
            anpNcclSocketClose(&clientSock);
            return EXIT_FAILURE;
        }
        ANP_LOG("LN: Received COMPOSITE_CONFIG from RN (%u bytes)", payload_size);
        deserialize_all_hosts(host_db, compbuf);
    }
    for (const auto& pair : host_db.all_hosts) {
         ANP_LOG("LN: Received info for host %s", pair.first.c_str());
         print_planar_config(pair.second);
    }

    ANP_LOG("LN program ip table rules");
    apply_local_vip_iptables_rule(host_db);
    apply_remote_vip_iptables_rule(host_db);

    // TODO: parse the composite config and call helper functions to program the
    // iptables and routes. 
    anpNcclSocketClose(&clientSock);
    ANP_LOG("LN: Connection closed. Exiting.");
    return EXIT_SUCCESS;
}
