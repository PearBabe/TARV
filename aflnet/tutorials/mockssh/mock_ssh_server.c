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

static const char SSH_BANNER[] = "SSH-2.0-OpenSSH_MockSSH_1.0\r\n";

static int contains_crash_marker(const unsigned char *buf, size_t len) {
  static const unsigned char marker[] = {'C', 'R', 'A', 'S', 'H'};
  if (!buf || len < sizeof(marker)) return 0;
  for (size_t i = 0; i + sizeof(marker) <= len; ++i) {
    if (!memcmp(buf + i, marker, sizeof(marker))) return 1;
  }
  return 0;
}

static void handle_signal(int signo) {
  (void)signo;
  keep_running = 0;
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

static size_t build_ssh_packet(unsigned char message_code,
                               const unsigned char *payload,
                               size_t payload_len,
                               unsigned char *out,
                               size_t out_sz) {
  size_t payload_total = 1 + payload_len;
  size_t padding_len = 6;
  size_t packet_len = 1 + payload_total + padding_len;
  size_t extra_mac = (message_code >= 20 && message_code <= 49) ? 0 : 8;
  size_t total = 4 + packet_len + extra_mac;

  if (!out || total > out_sz) return 0;

  out[0] = (unsigned char)((packet_len >> 24) & 0xFF);
  out[1] = (unsigned char)((packet_len >> 16) & 0xFF);
  out[2] = (unsigned char)((packet_len >> 8) & 0xFF);
  out[3] = (unsigned char)(packet_len & 0xFF);
  out[4] = (unsigned char)padding_len;
  out[5] = message_code;
  if (payload_len) memcpy(out + 6, payload, payload_len);
  memset(out + 6 + payload_len, 0, padding_len + extra_mac);
  return total;
}

static int handle_message(int client_fd, const unsigned char *buf, size_t len) {
  unsigned char reply[1024];
  size_t reply_len = 0;

  if (len >= 4 && !memcmp(buf, "SSH-", 4)) {
    return send_all(client_fd, (const unsigned char *)SSH_BANNER, strlen(SSH_BANNER));
  }

  if (len < 6) {
    reply_len = build_ssh_packet(3, NULL, 0, reply, sizeof(reply));
    return reply_len ? send_all(client_fd, reply, reply_len) : 0;
  }

  switch (buf[5]) {
    case 20: {
      size_t first = build_ssh_packet(20, NULL, 0, reply, sizeof(reply));
      size_t second = build_ssh_packet(21, NULL, 0, reply + first, sizeof(reply) - first);
      if (!first || !second) return 0;
      reply_len = first + second;
      break;
    }
    case 5: {
      /* Shortcut the mock into an authenticated outcome so auth-done labels
         are observable on the stock replay seed without a full SSH stack. */
      size_t first = build_ssh_packet(6, NULL, 0, reply, sizeof(reply));
      size_t second = build_ssh_packet(52, NULL, 0, reply + first, sizeof(reply) - first);
      if (!first || !second) return 0;
      reply_len = first + second;
      break;
    }
    case 50:
      reply_len = build_ssh_packet(52, NULL, 0, reply, sizeof(reply));
      break;
    case 80:
      reply_len = build_ssh_packet(81, NULL, 0, reply, sizeof(reply));
      break;
    case 1:
    case 97:
      reply_len = build_ssh_packet(1, NULL, 0, reply, sizeof(reply));
      break;
    default:
      reply_len = build_ssh_packet(2, NULL, 0, reply, sizeof(reply));
      break;
  }

  return reply_len ? send_all(client_fd, reply, reply_len) : 0;
}

static void handle_client(int client_fd) {
  while (keep_running) {
    unsigned char buffer[8192];
    ssize_t got = recv(client_fd, buffer, sizeof(buffer), 0);
    if (got == 0) return;
    if (got < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) return;
      return;
    }

    if (contains_crash_marker(buffer, (size_t)got)) abort();
    if (!handle_message(client_fd, buffer, (size_t)got)) return;
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
