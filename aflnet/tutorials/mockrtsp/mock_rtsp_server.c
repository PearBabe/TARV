#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static const char *SESSION_ID = "000022B8";
static const char *SDP_BODY =
    "v=0\r\n"
    "o=- 0 0 IN IP4 127.0.0.1\r\n"
    "s=Bi-ZoneFuzz++ Mock RTSP\r\n"
    "t=0 0\r\n"
    "m=video 0 RTP/AVP 96\r\n"
    "a=control:track1\r\n";

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
  const char *cursor = strstr(request, "\r\n");
  if (!cursor) return 0;
  cursor += 2;

  while (*cursor) {
    const char *line_end = strstr(cursor, "\r\n");
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
    cursor = line_end + 2;
  }

  return 0;
}

static void request_line(const char *request, char *method, size_t method_sz,
                         char *uri, size_t uri_sz) {
  method[0] = '\0';
  uri[0] = '\0';
  const char *line_end = strstr(request, "\r\n");
  size_t line_len = line_end ? (size_t)(line_end - request) : strlen(request);
  if (!line_len) return;

  const char *first_space = memchr(request, ' ', line_len);
  const char *second_space = first_space
                                 ? memchr(first_space + 1, ' ',
                                          line_len - (size_t)(first_space - request) - 1)
                                 : NULL;
  if (!first_space || !second_space) return;

  size_t method_len = (size_t)(first_space - request);
  if (method_len >= method_sz) method_len = method_sz - 1;
  memcpy(method, request, method_len);
  method[method_len] = '\0';
  for (size_t i = 0; method[i]; ++i) method[i] = (char)toupper((unsigned char)method[i]);

  size_t uri_len = (size_t)(second_space - first_space - 1);
  if (uri_len >= uri_sz) uri_len = uri_sz - 1;
  memcpy(uri, first_space + 1, uri_len);
  uri[uri_len] = '\0';
}

static void reply_request(int client_fd, const char *request) {
  char method[64];
  char uri[512];
  char cseq[64] = "1";
  char transport[512] = "RTP/AVP/TCP;unicast;interleaved=0-1";
  char response[4096];

  if (strstr(request, "CRASH")) abort();

  request_line(request, method, sizeof(method), uri, sizeof(uri));
  header_value(request, "CSeq", cseq, sizeof(cseq));
  header_value(request, "Transport", transport, sizeof(transport));

  if (!strcmp(method, "DESCRIBE")) {
    int written = snprintf(
        response,
        sizeof(response),
        "RTSP/1.0 200 OK\r\n"
        "CSeq: %s\r\n"
        "Content-Base: %s/\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s",
        cseq,
        uri[0] ? uri : "rtsp://127.0.0.1:8554/mock",
        strlen(SDP_BODY),
        SDP_BODY);
    if (written > 0 && (size_t)written < sizeof(response)) send_all(client_fd, response);
    return;
  }

  if (!strcmp(method, "SETUP")) {
    int written = snprintf(
        response,
        sizeof(response),
        "RTSP/1.0 200 OK\r\n"
        "CSeq: %s\r\n"
        "Session: %s\r\n"
        "Transport: %s\r\n"
        "\r\n",
        cseq,
        SESSION_ID,
        transport);
    if (written > 0 && (size_t)written < sizeof(response)) send_all(client_fd, response);
    return;
  }

  if (!strcmp(method, "PLAY")) {
    int written = snprintf(
        response,
        sizeof(response),
        "RTSP/1.0 200 OK\r\n"
        "CSeq: %s\r\n"
        "Session: %s\r\n"
        "Range: npt=0.000-\r\n"
        "RTP-Info: url=%s/track1;seq=1;rtptime=0\r\n"
        "\r\n",
        cseq,
        SESSION_ID,
        uri[0] ? uri : "rtsp://127.0.0.1:8554/mock");
    if (written > 0 && (size_t)written < sizeof(response)) send_all(client_fd, response);
    return;
  }

  if (!strcmp(method, "OPTIONS") || !strcmp(method, "GET_PARAMETER") ||
      !strcmp(method, "PAUSE") || !strcmp(method, "TEARDOWN")) {
    int written = snprintf(
        response,
        sizeof(response),
        "RTSP/1.0 200 OK\r\n"
        "CSeq: %s\r\n"
        "Session: %s\r\n"
        "Public: DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, OPTIONS, GET_PARAMETER\r\n"
        "\r\n",
        cseq,
        SESSION_ID);
    if (written > 0 && (size_t)written < sizeof(response)) send_all(client_fd, response);
    return;
  }

  {
    int written = snprintf(
        response,
        sizeof(response),
        "RTSP/1.0 200 OK\r\n"
        "CSeq: %s\r\n"
        "Session: %s\r\n"
        "\r\n",
        cseq,
        SESSION_ID);
    if (written > 0 && (size_t)written < sizeof(response)) send_all(client_fd, response);
  }
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
      if (!boundary) break;

      size_t request_len = (size_t)(boundary - cursor) + 4;
      char request[8192];
      if (request_len >= sizeof(request)) request_len = sizeof(request) - 1;
      memcpy(request, cursor, request_len);
      request[request_len] = '\0';
      reply_request(client_fd, request);
      cursor = boundary + 4;
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
  unsigned short port = 8554;
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
