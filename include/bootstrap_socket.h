#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include "nccl.h"

union anpNcclSocketAddress {
  struct sockaddr sa;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
};

enum anpNcclSocketState {
  anpNcclSocketStateNone = 0,
  anpNcclSocketStateInitialized = 1,
  anpNcclSocketStateAccepting = 2,
  anpNcclSocketStateAccepted = 3,
  anpNcclSocketStateConnecting = 4,
  anpNcclSocketStateConnectPolling = 5,
  anpNcclSocketStateConnected = 6,
  anpNcclSocketStateReady = 7,
  anpNcclSocketStateClosed = 8,
  anpNcclSocketStateError = 9,
  anpNcclSocketStateNum = 10
};

enum anpNcclSocketType {
  anpNcclSocketTypeUnknown = 0,
  anpNcclSocketTypeBootstrap = 1,
  anpNcclSocketTypeProxy = 2,
  anpNcclSocketTypeNetSocket = 3,
  anpNcclSocketTypeNetIb = 4,
  anpNcclSocketTypePluginBootstrap = 5
};

struct anpNcclSocket {
  int fd;
  int acceptFd;
  int timedOutRetries;
  int refusedRetries;
  union anpNcclSocketAddress addr;
  volatile uint32_t* abortFlag;
  int asyncFlag;
  enum anpNcclSocketState state;
  int salen;
  uint64_t magic;
  enum anpNcclSocketType type;
};

ncclResult_t anpNcclSocketInit(anpNcclSocket* socket, anpNcclSocketAddress* address, unsigned long flags, anpNcclSocketType type, unsigned int volatile* progress, int nonBlocking);
ncclResult_t anpNcclSocketListen(anpNcclSocket* socket);
ncclResult_t anpNcclSocketAccept(anpNcclSocket* clientSocket, anpNcclSocket* listenSocket);
ncclResult_t anpNcclSocketConnect(anpNcclSocket* socket);
ncclResult_t anpNcclSocketSend(anpNcclSocket* socket, void* data, int size);
ncclResult_t anpNcclSocketRecv(anpNcclSocket* socket, void* data, int size);
ncclResult_t anpNcclSocketClose(anpNcclSocket* socket);
