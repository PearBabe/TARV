#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static void send_reply(int client_fd, const char *text) {
  size_t len = strlen(text);
  while (len > 0) {
    ssize_t written = send(client_fd, text, len, 0);
    if (written < 0) {
      if (errno == EINTR) continue;
      return;
    }
    text += written;
    len -= (size_t)written;
  }
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
  char buffer[4096];
  send_reply(client_fd, "220 mockftp ready\r\n");

  while (1) {
    ssize_t received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) break;

    buffer[received] = '\0';

    if (strstr(buffer, "CRASH")) abort();

    if (!strncmp(buffer, "USER", 4)) {
      send_reply(client_fd, "331 password required\r\n");
    } else if (!strncmp(buffer, "PASS", 4)) {
      send_reply(client_fd, "230 logged in\r\n");
    } else if (!strncmp(buffer, "SYST", 4)) {
      send_reply(client_fd, "215 UNIX Type: L8\r\n");
    } else if (!strncmp(buffer, "PWD", 3)) {
      send_reply(client_fd, "257 \"/\" is current directory\r\n");
    } else if (!strncmp(buffer, "PORT", 4)) {
      send_reply(client_fd, "200 PORT command successful\r\n");
    } else if (!strncmp(buffer, "LIST", 4)) {
      send_reply(client_fd, "150 opening data connection\r\n226 transfer complete\r\n");
    } else if (!strncmp(buffer, "NORESP", 6)) {
      usleep(200000);
      continue;
    } else if (!strncmp(buffer, "RST", 3)) {
      struct linger linger_opt;
      linger_opt.l_onoff = 1;
      linger_opt.l_linger = 0;
      setsockopt(client_fd, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt));
      break;
    } else if (!strncmp(buffer, "NOOP", 4)) {
      send_reply(client_fd, "200 noop ok\r\n");
    } else if (!strncmp(buffer, "QUIT", 4)) {
      send_reply(client_fd, "221 goodbye\r\n");
      break;
    } else {
      send_reply(client_fd, "200 ok\r\n");
    }
  }

  close(client_fd);
}

int main(int argc, char **argv) {
  unsigned short port = 2121;
  if (argc > 1) {
    port = (unsigned short)strtoul(argv[1], NULL, 10);
  }

  signal(SIGPIPE, SIG_IGN);

  int listen_fd = setup_listener(port);
  if (listen_fd < 0) return 1;

  while (1) {
    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
      if (errno == EINTR) continue;
      perror("accept");
      close(listen_fd);
      return 1;
    }

    handle_client(client_fd);
  }

  close(listen_fd);
  return 0;
}
