/* Concurrent HTTP/1.0 proxy with a bounded, shared-reader LRU cache. */
#include "csapp.h"
#include <strings.h>
#include <stdint.h>
#include <stdatomic.h>

#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400
#define MAX_REQUEST_HEADERS 65536

static const char *user_agent_hdr =
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) "
    "Gecko/20120305 Firefox/10.0.3\r\n";

typedef struct cache_block {
    char *uri;
    char *content;
    size_t size;
    atomic_ulong last_used;
    struct cache_block *next;
} cache_block;

static cache_block *cache_head;
static size_t cache_used;
static pthread_rwlock_t cache_lock = PTHREAD_RWLOCK_INITIALIZER;
static atomic_ulong cache_clock;

/* Readers copy concurrently. Atomic timestamps avoid upgrading the read lock.
 * The copy remains valid after releasing the lock, even if the entry is evicted.
 * No lock is held while writing to a potentially slow client. */
static size_t cache_lookup(const char *uri, char *out)
{
    size_t size = 0;
    pthread_rwlock_rdlock(&cache_lock);
    for (cache_block *b = cache_head; b; b = b->next) {
        if (!strcmp(b->uri, uri)) {
            memcpy(out, b->content, b->size);
            size = b->size;
            atomic_store(&b->last_used, atomic_fetch_add(&cache_clock, 1));
            break;
        }
    }
    pthread_rwlock_unlock(&cache_lock);
    return size;
}

static void cache_remove(cache_block **link)
{
    cache_block *b = *link;
    *link = b->next;
    cache_used -= b->size;
    free(b->uri);
    free(b->content);
    free(b);
}

static void cache_insert(const char *uri, const char *content, size_t size)
{
    if (!size || size > MAX_OBJECT_SIZE) return;
    cache_block *b = calloc(1, sizeof(*b));
    if (!b) return;
    b->uri = malloc(strlen(uri) + 1);
    b->content = malloc(size);
    if (!b->uri || !b->content) {
        free(b->uri);
        free(b->content);
        free(b);
        return;
    }
    strcpy(b->uri, uri);
    memcpy(b->content, content, size);
    b->size = size;
    atomic_init(&b->last_used, 0);

    pthread_rwlock_wrlock(&cache_lock);
    for (cache_block **p = &cache_head; *p; p = &(*p)->next) {
        if (!strcmp((*p)->uri, uri)) {
            cache_remove(p);
            break;
        }
    }
    while (cache_used + size > MAX_CACHE_SIZE) {
        cache_block **oldest = &cache_head;
        for (cache_block **p = &cache_head; *p; p = &(*p)->next) {
            if (atomic_load(&(*p)->last_used) <
                atomic_load(&(*oldest)->last_used)) oldest = p;
        }
        cache_remove(oldest);
    }
    atomic_store(&b->last_used, atomic_fetch_add(&cache_clock, 1));
    b->next = cache_head;
    cache_head = b;
    cache_used += size;
    pthread_rwlock_unlock(&cache_lock);
}

static int send_bytes(int fd, const void *data, size_t size)
{
    return rio_writen(fd, (void *)data, size) == (ssize_t)size;
}

static void send_error(int fd, const char *status)
{
    char response[256];
    int n = snprintf(response, sizeof(response),
                     "HTTP/1.0 %s\r\nContent-Length: 0\r\n"
                     "Connection: close\r\n\r\n", status);
    if (n > 0 && (size_t)n < sizeof(response))
        send_bytes(fd, response, (size_t)n);
}

/* Require a complete CRLF-terminated text line; reject truncation and NULs. */
static ssize_t read_line(rio_t *rio, char *line)
{
    ssize_t n = rio_readlineb(rio, line, MAXLINE);
    if (n <= 0) return n;
    if (n < 2 || line[n - 2] != '\r' || line[n - 1] != '\n' ||
        strlen(line) != (size_t)n) return -1;
    return n;
}

static int append_text(char *dst, size_t capacity, const char *src)
{
    size_t used = strlen(dst), added = strlen(src);
    if (added >= capacity - used) return 0;
    memcpy(dst + used, src, added + 1);
    return 1;
}

/* Return a validated header value, trimming outer whitespace in place. */
static char *header_value(char *line)
{
    char *colon = strchr(line, ':');
    if (!colon || colon == line) return NULL;
    for (char *p = line; p < colon; ++p)
        if (!isalnum((unsigned char)*p) && !strchr("!#$%&'*+-.^_`|~", *p))
            return NULL;
    char *value = colon + 1;
    while (*value == ' ' || *value == '\t') ++value;
    char *end = line + strlen(line);
    while (end > value && (end[-1] == '\r' || end[-1] == '\n' ||
                          end[-1] == ' ' || end[-1] == '\t')) --end;
    *end = '\0';
    for (char *p = value; *p; ++p)
        if (((unsigned char)*p < 32 && *p != '\t') || *p == 127)
            return NULL;
    return value;
}

static int parse_length(const char *value, size_t *length)
{
    size_t n = 0;
    if (!*value) return 0;
    for (const char *p = value; *p; ++p) {
        if (*p < '0' || *p > '9' || n > (SIZE_MAX - (*p - '0')) / 10)
            return 0;
        n = n * 10 + (*p - '0');
    }
    *length = n;
    return 1;
}

/* Separate the URI authority from its path/query, including bracketed IPv6. */
static int parse_uri(const char *uri, char *host, char *port,
                     char *path, char *authority)
{
    if (strncasecmp(uri, "http://", 7)) return 0;
    const char *start = uri + 7;
    size_t length = strcspn(start, "/?#");
    if (!length || length >= MAXLINE || strchr(uri, '#')) return 0;
    memcpy(authority, start, length);
    authority[length] = '\0';
    for (const char *p = authority; *p; ++p)
        if ((unsigned char)*p <= 32 || *p == 127 || *p == '@') return 0;

    strcpy(port, "80");
    const char *port_start = NULL;
    if (authority[0] == '[') {
        char *end = strchr(authority, ']');
        if (!end || end == authority + 1) return 0;
        size_t host_len = (size_t)(end - authority - 1);
        memcpy(host, authority + 1, host_len);
        host[host_len] = '\0';
        if (end[1]) {
            if (end[1] != ':') return 0;
            port_start = end + 2;
        }
    } else {
        const char *colon = strchr(authority, ':');
        size_t host_len = colon ? (size_t)(colon - authority) : length;
        if (!host_len) return 0;
        memcpy(host, authority, host_len);
        host[host_len] = '\0';
        if (colon) port_start = colon + 1;
    }
    if (port_start) {
        size_t number;
        if (!parse_length(port_start, &number) || !number || number > 65535)
            return 0;
        snprintf(port, MAXLINE, "%zu", number);
    }
    const char *suffix = start + length;
    int n = snprintf(path, MAXLINE, "%s%s", *suffix == '/' ? "" : "/", suffix);
    return n >= 0 && n < MAXLINE;
}

/* Accumulate actual bytes, discarding the candidate once it exceeds the limit. */
static int relay(int fd, const char *data, size_t size, char *object,
                 size_t *used, int *cacheable)
{
    if (!send_bytes(fd, data, size)) return 0;
    if (*cacheable) {
        if (size > MAX_OBJECT_SIZE - *used) *cacheable = 0;
        else {
            memcpy(object + *used, data, size);
            *used += size;
        }
    }
    return 1;
}

static void forward_response(int connfd, rio_t *server, const char *uri)
{
    char line[MAXLINE], parsed[MAXLINE], data[MAXLINE];
    char *object = malloc(MAX_OBJECT_SIZE);
    size_t used = 0, remaining = 0;
    int has_length = 0, transfer_encoding = 0, status = 0;
    int cacheable = object != NULL;
    ssize_t n = read_line(server, line);
    if (n <= 0 || sscanf(line, "HTTP/%*u.%*u %d", &status) != 1 ||
        status < 200 || status > 599) {
        send_error(connfd, "502 Bad Gateway");
        goto done;
    }
    if (status != 200) cacheable = 0;
    if (!relay(connfd, line, (size_t)n, object, &used, &cacheable)) goto done;
    for (;;) {
        n = read_line(server, line);
        if (n <= 0) goto done;
        if (!strcmp(line, "\r\n")) {
            if (!relay(connfd, line, (size_t)n, object, &used, &cacheable)) goto done;
            break;
        }
        strcpy(parsed, line);
        char *value = header_value(parsed);
        if (!value) goto done;
        if (!strncasecmp(line, "Content-Length:", 15)) {
            size_t length;
            if (!parse_length(value, &length) || (has_length && remaining != length))
                goto done;
            remaining = length;
            has_length = 1;
        } else if (!strncasecmp(line, "Transfer-Encoding:", 18)) {
            transfer_encoding = 1;
            cacheable = 0;
        }
        if (!relay(connfd, line, (size_t)n, object, &used, &cacheable)) goto done;
    }
    /* A 204 or 304 response has no message body. */
    if (status == 204 || status == 304) goto done;
    if (transfer_encoding) has_length = 0;
    for (;;) {
        size_t want = sizeof(data);
        if (has_length) {
            if (!remaining) break;
            if (remaining < want) want = remaining;
        }
        n = rio_readnb(server, data, want);
        if (n < 0) goto done;
        if (!n) {
            if (has_length && remaining) goto done; /* Truncated: never cache. */
            break;
        }
        if (!relay(connfd, data, (size_t)n, object, &used, &cacheable)) goto done;
        if (has_length) remaining -= (size_t)n;
    }
    if (cacheable) cache_insert(uri, object, used);
done:
    free(object);
}

static void handle_request(int connfd)
{
    rio_t client, server;
    char line[MAXLINE], parsed[MAXLINE];
    char method[MAXLINE], uri[MAXLINE], version[MAXLINE], extra;
    char host[MAXLINE], port[MAXLINE], path[MAXLINE], authority[MAXLINE];
    char host_header[MAXLINE] = "", headers[MAX_REQUEST_HEADERS] = "";
    char request_line[MAXLINE + 32];
    size_t header_bytes = 0;
    rio_readinitb(&client, connfd);
    ssize_t n = read_line(&client, line);
    if (!n) return;
    if (n < 0 || sscanf(line, "%8191s %8191s %8191s %c", method, uri,
                        version, &extra) != 3 ||
        (strcmp(version, "HTTP/1.0") && strcmp(version, "HTTP/1.1"))) {
        send_error(connfd, "400 Bad Request");
        return;
    }
    if (strcmp(method, "GET")) {
        send_error(connfd, "501 Not Implemented");
        return;
    }
    if (!parse_uri(uri, host, port, path, authority)) {
        send_error(connfd, "400 Bad Request");
        return;
    }
    for (;;) {
        n = read_line(&client, line);
        if (n <= 0) {
            send_error(connfd, "400 Bad Request");
            return;
        }
        if (!strcmp(line, "\r\n")) break;
        header_bytes += (size_t)n;
        if (header_bytes > MAX_REQUEST_HEADERS) {
            send_error(connfd, "431 Request Header Fields Too Large");
            return;
        }
        strcpy(parsed, line);
        char *value = header_value(parsed);
        if (!value) {
            send_error(connfd, "400 Bad Request");
            return;
        }
        if (!strncasecmp(line, "Host:", 5)) {
            if (!*value || *host_header) {
                send_error(connfd, "400 Bad Request");
                return;
            }
            strcpy(host_header, line);
        } else if (!strncasecmp(line, "Content-Length:", 15)) {
            size_t length;
            if (!parse_length(value, &length) || length != 0) {
                send_error(connfd, "400 Bad Request");
                return;
            }
            if (!append_text(headers, sizeof(headers), line)) goto too_large;
        } else if (!strncasecmp(line, "Transfer-Encoding:", 18)) {
            send_error(connfd, "501 Not Implemented");
            return;
        } else if (strncasecmp(line, "User-Agent:", 11) &&
                   strncasecmp(line, "Connection:", 11) &&
                   strncasecmp(line, "Proxy-Connection:", 17)) {
            if (!append_text(headers, sizeof(headers), line)) goto too_large;
        }
    }
    /* A differing virtual Host must not share another Host's cached response. */
    char cache_key[MAXLINE * 2 + 2];
    snprintf(cache_key, sizeof(cache_key), "%s\n%s", uri,
             *host_header ? host_header : authority);
    char *cached = malloc(MAX_OBJECT_SIZE);
    if (cached) {
        size_t size = cache_lookup(cache_key, cached);
        if (size) {
            send_bytes(connfd, cached, size);
            free(cached);
            return;
        }
        free(cached);
    }
    int srvfd = open_clientfd(host, port);
    if (srvfd < 0) {
        send_error(connfd, "502 Bad Gateway");
        return;
    }
    rio_readinitb(&server, srvfd);
    snprintf(request_line, sizeof(request_line), "GET %s HTTP/1.0\r\n", path);
    int ok = send_bytes(srvfd, request_line, strlen(request_line));
    if (*host_header) ok = ok && send_bytes(srvfd, host_header, strlen(host_header));
    else ok = ok && send_bytes(srvfd, "Host: ", 6) &&
                   send_bytes(srvfd, authority, strlen(authority)) &&
                   send_bytes(srvfd, "\r\n", 2);
    static const char connection_headers[] =
        "Connection: close\r\nProxy-Connection: close\r\n";
    ok = ok && send_bytes(srvfd, user_agent_hdr, strlen(user_agent_hdr)) &&
         send_bytes(srvfd, connection_headers, sizeof(connection_headers) - 1) &&
         send_bytes(srvfd, headers, strlen(headers)) && send_bytes(srvfd, "\r\n", 2);
    if (ok) forward_response(connfd, &server, cache_key);
    else send_error(connfd, "502 Bad Gateway");
    close(srvfd);
    return;
too_large:
    send_error(connfd, "431 Request Header Fields Too Large");
}

static void *worker(void *arg)
{
    int connfd = *(int *)arg;
    free(arg);
    handle_request(connfd);
    close(connfd);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return 1;
    }
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_IGN;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGPIPE, &action, NULL) < 0) return 1;
    int listenfd = open_listenfd(argv[1]);
    if (listenfd < 0) return 1;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        close(listenfd);
        return 1;
    }
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
        pthread_attr_destroy(&attr);
        close(listenfd);
        return 1;
    }
    for (;;) {
        int fd = accept(listenfd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            /* Back off on resource exhaustion without killing active clients. */
            sleep(1);
            continue;
        }
        int *arg = malloc(sizeof(*arg));
        if (!arg) { close(fd); continue; }
        *arg = fd;
        pthread_t tid;
        if (pthread_create(&tid, &attr, worker, arg) != 0) {
            free(arg);
            close(fd);
        }
    }
}
