#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

static volatile sig_atomic_t keep_running = 1;

static const unsigned char ASSOCIATE_AC[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00};
static const unsigned char PDATA_TF[] = {
    0x04, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00};
static const unsigned char RELEASE_RP[] = {
    0x06, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00};
static const unsigned char ABORT_PDU[] = {
    0x07, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00};

static void handle_signal(int signo) {
  (void)signo;
  keep_running = 0;
}

static int contains_crash_marker(const unsigned char *buf, size_t len) {
  static const unsigned char marker[] = {'C', 'R', 'A', 'S', 'H'};
  if (!buf || len < sizeof(marker)) return 0;
  for (size_t i = 0; i + sizeof(marker) <= len; ++i) {
    if (!memcmp(buf + i, marker, sizeof(marker))) return 1;
  }
  return 0;
}

static int send_all(int fd, const unsigned char *buf, size_t len) {
  while (len > 0) {
    ssize_t written = send(fd, buf, len, 0);
    if (written < 0) {
      if (errno == EINTR) continue;
      return 0;
    }
    buf += (size_t)written;
    len -= (size_t)written;
  }
  return 1;
}

static int recv_exact(int fd, unsigned char *buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t got = recv(fd, buf + total, len - total, 0);
    if (got == 0) return 0;
    if (got < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
      return -1;
    }
    total += (size_t)got;
  }
  return 1;
}

static int setup_listener(unsigned short port) {
  int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0) {
    perror("socket");
    return -1;
  }

  int reuse = 1;
  if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    perror("setsockopt");
    close(listen_fd);
    return -1;
  }

  struct timeval timeout;
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;
  if (setsockopt(listen_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
    perror("setsockopt");
    close(listen_fd);
    return -1;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(port);

  if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    close(listen_fd);
    return -1;
  }

  if (listen(listen_fd, 16) < 0) {
    perror("listen");
    close(listen_fd);
    return -1;
  }

  return listen_fd;
}

static void handle_client(int client_fd) {
  unsigned char header[6];
  while (keep_running) {
    int header_status = recv_exact(client_fd, header, sizeof(header));
    if (header_status <= 0) return;

    uint32_t payload_len = ((uint32_t)header[2] << 24) |
                           ((uint32_t)header[3] << 16) |
                           ((uint32_t)header[4] << 8) |
                           (uint32_t)header[5];
    if (payload_len > 1U << 20) return;

    unsigned char *payload = NULL;
    if (payload_len > 0) {
      payload = (unsigned char *)malloc(payload_len);
      if (!payload) return;
      int payload_status = recv_exact(client_fd, payload, payload_len);
      if (payload_status <= 0) {
        free(payload);
        return;
      }
      if (contains_crash_marker(payload, payload_len)) {
        free(payload);
        abort();
      }
    }

    const unsigned char *reply = PDATA_TF;
    size_t reply_len = sizeof(PDATA_TF);
    switch (header[0]) {
      case 0x01:
        reply = ASSOCIATE_AC;
        reply_len = sizeof(ASSOCIATE_AC);
        break;
      case 0x04:
        reply = PDATA_TF;
        reply_len = sizeof(PDATA_TF);
        break;
      case 0x05:
        reply = RELEASE_RP;
        reply_len = sizeof(RELEASE_RP);
        break;
      case 0x07:
        reply = ABORT_PDU;
        reply_len = sizeof(ABORT_PDU);
        break;
      default:
        reply = ABORT_PDU;
        reply_len = sizeof(ABORT_PDU);
        break;
    }

    if (!send_all(client_fd, reply, reply_len)) {
      free(payload);
      return;
    }

    free(payload);
    if (header[0] == 0x05 || header[0] == 0x07) return;
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    return 1;
  }

  char *end = NULL;
  unsigned long parsed = strtoul(argv[1], &end, 10);
  if (!end || *end != '\0' || parsed > 65535UL) {
    fprintf(stderr, "invalid port: %s\n", argv[1]);
    return 1;
  }

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  int listen_fd = setup_listener((unsigned short)parsed);
  if (listen_fd < 0) return 1;

  while (keep_running) {
    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
      perror("accept");
      break;
    }

    handle_client(client_fd);
    close(client_fd);
  }

  close(listen_fd);
  return 0;
}
