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

static const unsigned char HELLO_VERIFY_REQUEST[] = {
    0x16, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0C, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const unsigned char SERVER_HELLO_DONE[] = {
    0x16, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0C, 0x0E, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const unsigned char HEARTBEAT_RESPONSE[] = {
    0x18, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x02, 0x00, 0x00};

static void handle_signal(int signo) {
  (void)signo;
  keep_running = 0;
}

static int contains_crash_marker(const unsigned char *buf, ssize_t len) {
  static const unsigned char marker[] = {'C', 'R', 'A', 'S', 'H'};
  ssize_t marker_len = (ssize_t)sizeof(marker);
  if (!buf || len < marker_len) return 0;

  for (ssize_t i = 0; i <= len - marker_len; ++i) {
    if (!memcmp(buf + i, marker, (size_t)marker_len)) return 1;
  }
  return 0;
}

static int setup_socket(unsigned short port) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket");
    return -1;
  }

  int reuse = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    perror("setsockopt");
    close(fd);
    return -1;
  }

  struct timeval timeout;
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
    perror("setsockopt");
    close(fd);
    return -1;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(port);

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    close(fd);
    return -1;
  }

  return fd;
}

static const unsigned char *choose_reply(const unsigned char *buf, ssize_t len,
                                         size_t *reply_len) {
  if (!buf || len <= 0 || !reply_len) return NULL;

  if (len >= 14 && buf[1] == 0xFE && buf[2] == 0xFD) {
    if (buf[0] == 0x18) {
      *reply_len = sizeof(HEARTBEAT_RESPONSE);
      return HEARTBEAT_RESPONSE;
    }

    if (buf[0] == 0x16) {
      if (buf[13] == 0x01) {
        *reply_len = sizeof(HELLO_VERIFY_REQUEST);
        return HELLO_VERIFY_REQUEST;
      }
      *reply_len = sizeof(SERVER_HELLO_DONE);
      return SERVER_HELLO_DONE;
    }
  }

  *reply_len = sizeof(SERVER_HELLO_DONE);
  return SERVER_HELLO_DONE;
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

  int fd = setup_socket((unsigned short)parsed);
  if (fd < 0) return 1;

  while (keep_running) {
    unsigned char buffer[4096];
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    ssize_t got = recvfrom(fd, buffer, sizeof(buffer), 0,
                           (struct sockaddr *)&peer, &peer_len);
    if (got < 0) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
      perror("recvfrom");
      break;
    }

    if (contains_crash_marker(buffer, got)) abort();

    size_t reply_len = 0;
    const unsigned char *reply = choose_reply(buffer, got, &reply_len);
    if (!reply || !reply_len) continue;

    if (sendto(fd, reply, reply_len, 0, (struct sockaddr *)&peer, peer_len) < 0) {
      if (errno == EINTR) continue;
      perror("sendto");
      break;
    }
  }

  close(fd);
  return 0;
}
