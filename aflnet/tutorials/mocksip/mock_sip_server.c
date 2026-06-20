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

static void send_all(int client_fd, const char *text) {
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

static const char *find_line_end(const char *text) {
  const char *crlf = strstr(text, "\r\n");
  if (crlf) return crlf;
  return strchr(text, '\n');
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

static int header_value(const char *request, const char *header_name, char *out, size_t out_sz) {
  size_t header_len = strlen(header_name);
  const char *cursor = find_line_end(request);
  if (!cursor) return 0;
  cursor += (cursor[0] == '\r' && cursor[1] == '\n') ? 2 : 1;

  while (*cursor) {
    const char *line_end = find_line_end(cursor);
    if (!line_end || line_end == cursor) break;
    if (!strncasecmp(cursor, header_name, header_len) && cursor[header_len] == ':') {
      const char *value = cursor + header_len + 1;
      while (*value == ' ' || *value == '\t') value++;
      size_t value_len = (size_t)(line_end - value);
      while (value_len > 0 &&
             (value[value_len - 1] == ' ' || value[value_len - 1] == '\t')) {
        value_len--;
      }
      if (!value_len) return 0;
      if (value_len >= out_sz) value_len = out_sz - 1;
      memcpy(out, value, value_len);
      out[value_len] = '\0';
      return 1;
    }
    cursor = line_end + ((line_end[0] == '\r' && line_end[1] == '\n') ? 2 : 1);
  }

  return 0;
}

static void request_line(const char *request, char *method, size_t method_sz) {
  method[0] = '\0';
  const char *line_end = find_line_end(request);
  size_t line_len = line_end ? (size_t)(line_end - request) : strlen(request);
  if (!line_len) return;

  const char *first_space = memchr(request, ' ', line_len);
  if (!first_space) return;
  size_t method_len = (size_t)(first_space - request);
  if (method_len >= method_sz) method_len = method_sz - 1;
  memcpy(method, request, method_len);
  method[method_len] = '\0';
}

static void send_sip_response(int client_fd, const char *status, const char *request) {
  char via[512] = "";
  char from[512] = "";
  char to[512] = "";
  char call_id[256] = "";
  char cseq[128] = "1 OPTIONS";
  char response[4096];

  header_value(request, "Via", via, sizeof(via));
  header_value(request, "From", from, sizeof(from));
  header_value(request, "To", to, sizeof(to));
  header_value(request, "Call-ID", call_id, sizeof(call_id));
  header_value(request, "CSeq", cseq, sizeof(cseq));

  int written = snprintf(
      response,
      sizeof(response),
      "SIP/2.0 %s\r\n"
      "%s%s%s"
      "%s%s%s"
      "%s%s%s"
      "%s%s%s"
      "CSeq: %s\r\n"
      "Content-Length: 0\r\n"
      "\r\n",
      status,
      via[0] ? "Via: " : "", via[0] ? via : "", via[0] ? "\r\n" : "",
      from[0] ? "From: " : "", from[0] ? from : "", from[0] ? "\r\n" : "",
      to[0] ? "To: " : "", to[0] ? to : "", to[0] ? "\r\n" : "",
      call_id[0] ? "Call-ID: " : "", call_id[0] ? call_id : "", call_id[0] ? "\r\n" : "",
      cseq);
  if (written > 0 && (size_t)written < sizeof(response)) send_all(client_fd, response);
}

static const char *invite_response_mode(void) {
  const char *mode = getenv("BIZONE_SIP_INVITE_RESPONSE_MODE");
  return (mode && mode[0]) ? mode : "default";
}

static void reply_request(int client_fd, const char *request) {
  char method[64];
  request_line(request, method, sizeof(method));

  if (strstr(request, "CRASH")) abort();

  if (!strcmp(method, "INVITE")) {
    const char *mode = invite_response_mode();
    if (!strcmp(mode, "drop")) {
      return;
    }
    send_sip_response(client_fd, "100 Trying", request);
    if (!strcmp(mode, "trying-only")) {
      return;
    }
    send_sip_response(client_fd, "180 Ringing", request);
    if (!strcmp(mode, "trying-ringing-only")) {
      return;
    }
    send_sip_response(client_fd, "200 OK", request);
    return;
  }

  if (!strcmp(method, "REGISTER") || !strcmp(method, "OPTIONS") ||
      !strcmp(method, "ACK") || !strcmp(method, "BYE")) {
    send_sip_response(client_fd, "200 OK", request);
    return;
  }

  send_sip_response(client_fd, "501 Not Implemented", request);
}

static void handle_client(int client_fd) {
  char buffer[16384];
  size_t used = 0;

  while (1) {
    ssize_t received = recv(client_fd, buffer + used, sizeof(buffer) - used - 1, 0);
    if (received <= 0) break;
    used += (size_t)received;
    buffer[used] = '\0';

    char *cursor = buffer;
    while (1) {
      char *boundary = strstr(cursor, "\r\n\r\n");
      size_t boundary_advance = 4;
      if (!boundary) {
        boundary = strstr(cursor, "\n\n");
        boundary_advance = 2;
      }
      if (!boundary) break;

      size_t request_len = (size_t)(boundary - cursor) + boundary_advance;
      char request[8192];
      if (request_len >= sizeof(request)) request_len = sizeof(request) - 1;
      memcpy(request, cursor, request_len);
      request[request_len] = '\0';
      reply_request(client_fd, request);
      cursor = boundary + boundary_advance;
    }

    if (cursor != buffer) {
      size_t remaining = used - (size_t)(cursor - buffer);
      memmove(buffer, cursor, remaining);
      used = remaining;
      buffer[used] = '\0';
    } else if (used == sizeof(buffer) - 1) {
      used = 0;
      buffer[0] = '\0';
    }
  }

  close(client_fd);
}

int main(int argc, char **argv) {
  unsigned short port = 5060;
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
