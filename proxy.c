/* 
 * proxy.c - Concurrent caching HTTP proxy (CS:APP Proxy Lab)
 *
 * Part 1: Basic proxy  - HTTP GET forwarding (text + binary safe)
 * Part 2: Concurrency - one detached thread per connection
 * Part 3: Cache        - LRU cache, MAX_CACHE_SIZE total, MAX_OBJECT_SIZE per object
 */
#include "csapp.h"
#include <strings.h>

/* Recommended max cache and object sizes */
#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400

/* You won't lose style points for including this long line in your code */
static const char *user_agent_hdr = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) Gecko/20120305 Firefox/10.0.3\r\n";

/* ===================== LRU cache (doubly linked list + mutex) ===================== */

typedef struct cache_block {
    char uri[MAXLINE];          /* full URI as key */
    char *content;              /* complete HTTP response (status line + headers + body) */
    size_t size;
    struct cache_block *prev, *next;
} cache_block;

static cache_block *cache_head = NULL;   /* most recently used at head */
static cache_block *cache_tail = NULL;   /* least recently used at tail */
static size_t cache_used = 0;
static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;

/* list ops: caller must hold cache_lock */
static void cache_unlink(cache_block *b)
{
    if (b->prev) b->prev->next = b->next; else cache_head = b->next;
    if (b->next) b->next->prev = b->prev; else cache_tail = b->prev;
}

static void cache_push_front(cache_block *b)
{
    b->prev = NULL;
    b->next = cache_head;
    if (cache_head) cache_head->prev = b;
    else            cache_tail = b;
    cache_head = b;
}

static void cache_evict_lru(void)
{
    cache_block *victim = cache_tail;
    if (!victim) return;
    cache_unlink(victim);
    cache_used -= victim->size;
    free(victim->content);
    free(victim);
}

/* lookup: on hit copy content into out (capacity >= MAX_OBJECT_SIZE) and
 * return its size; on miss return 0 */
static size_t cache_lookup(const char *uri, char *out)
{
    size_t len = 0;
    pthread_mutex_lock(&cache_lock);
    for (cache_block *b = cache_head; b; b = b->next) {
        if (strcmp(b->uri, uri) == 0) {
            memcpy(out, b->content, b->size);
            cache_unlink(b);           /* LRU: refresh to front */
            cache_push_front(b);
            len = b->size;
            break;
        }
    }
    pthread_mutex_unlock(&cache_lock);
    return len;
}

/* insert: evict LRU objects until it fits; replace duplicate key */
static void cache_insert(const char *uri, const char *content, size_t size)
{
    if (size > MAX_OBJECT_SIZE) return;

    pthread_mutex_lock(&cache_lock);

    for (cache_block *b = cache_head; b; b = b->next) {
        if (strcmp(b->uri, uri) == 0) {
            cache_unlink(b);
            cache_used -= b->size;
            free(b->content);
            free(b);
            break;
        }
    }

    while (cache_used + size > MAX_CACHE_SIZE && cache_tail)
        cache_evict_lru();

    cache_block *nb = (cache_block *)malloc(sizeof(cache_block));
    nb->content = (char *)malloc(size);
    strcpy(nb->uri, uri);
    memcpy(nb->content, content, size);
    nb->size = size;
    cache_push_front(nb);
    cache_used += size;

    pthread_mutex_unlock(&cache_lock);
}

/* ===================== helpers ===================== */

/* parse absolute URI  http://host[:port]/path  ->  host / port (default 80) / path */
static void parse_uri(char *uri, char *host, char *port, char *path)
{
    char *p = uri;
    if (strncasecmp(p, "http://", 7) == 0)
        p += 7;

    char *slash = strchr(p, '/');
    char *colon = strchr(p, ':');

    if (colon && (!slash || colon < slash)) {           /* host:port/path */
        size_t hl = colon - p;
        strncpy(host, p, hl); host[hl] = '\0';
        size_t pl = slash ? (size_t)(slash - colon - 1) : strlen(colon + 1);
        strncpy(port, colon + 1, pl); port[pl] = '\0';
    } else {                                            /* host/path */
        size_t hl = slash ? (size_t)(slash - p) : strlen(p);
        strncpy(host, p, hl); host[hl] = '\0';
        strcpy(port, "80");
    }

    if (slash) strcpy(path, slash);
    else       strcpy(path, "/");
}

/* forward the origin response to the client; cache it when eligible */
static void forward_response(int connfd, rio_t *rio_srv, char *uri)
{
    char sbuf[MAXLINE], line[MAXLINE];
    char hbuf[MAX_OBJECT_SIZE];    /* status line + headers */
    int hlen = 0;
    int status;
    size_t cl = 0;
    int has_cl = 0;

    if (Rio_readlineb(rio_srv, sbuf, MAXLINE) <= 0)
        return;
    sscanf(sbuf, "%*s %d", &status);
    hlen += sprintf(hbuf + hlen, "%s", sbuf);

    while (Rio_readlineb(rio_srv, line, MAXLINE) > 0) {
        if (strcmp(line, "\r\n") == 0) break;
        if (hlen + (int)strlen(line) < MAX_OBJECT_SIZE)
            hlen += sprintf(hbuf + hlen, "%s", line);
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            has_cl = 1;
            cl = (size_t)atoi(line + 15);
        }
    }
    hlen += sprintf(hbuf + hlen, "\r\n");

    int cacheable = (status == 200) && has_cl && (hlen + cl <= MAX_OBJECT_SIZE);

    if (cacheable) {
        /* read the whole body, write once, then insert into cache */
        Rio_readnb(rio_srv, hbuf + hlen, cl);
        Rio_writen(connfd, hbuf, hlen + cl);
        cache_insert(uri, hbuf, hlen + cl);
    } else {
        /* stream the rest until EOF */
        Rio_writen(connfd, hbuf, hlen);
        char bbuf[MAXLINE];
        ssize_t r;
        while ((r = Rio_readnb(rio_srv, bbuf, MAXLINE)) > 0)
            Rio_writen(connfd, bbuf, r);
    }
}

/* handle one client connection: parse request, consult cache, forward */
static void handle_request(int connfd)
{
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
    char host[MAXLINE], port[MAXLINE], path[MAXLINE];
    char hdr_line[MAXLINE], req_hdrs[MAXLINE];
    static const char err501[] =
        "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rio_t rio, rio_srv;
    int srvfd;

    Rio_readinitb(&rio, connfd);

    /* 1. request line */
    if (Rio_readlineb(&rio, buf, MAXLINE) <= 0)
        return;
    sscanf(buf, "%s %s %s", method, uri, version);

    if (strcasecmp(method, "GET") != 0) {
        Rio_writen(connfd, (void *)err501, sizeof(err501) - 1);
        return;
    }

    /* 2. headers: keep everything except the four we rewrite */
    req_hdrs[0] = '\0';
    while (Rio_readlineb(&rio, hdr_line, MAXLINE) > 0) {
        if (strcmp(hdr_line, "\r\n") == 0) break;
        if (strncasecmp(hdr_line, "Host:", 5) != 0 &&
            strncasecmp(hdr_line, "User-Agent:", 11) != 0 &&
            strncasecmp(hdr_line, "Connection:", 11) != 0 &&
            strncasecmp(hdr_line, "Proxy-Connection:", 17) != 0) {
            if (strlen(req_hdrs) + strlen(hdr_line) < MAXLINE)
                strcat(req_hdrs, hdr_line);
        }
    }

    /* 3. parse URI into host / port / path */
    parse_uri(uri, host, port, path);

    /* 4. cache lookup: hit -> serve and done */
    char cached[MAX_OBJECT_SIZE];
    size_t clen = cache_lookup(uri, cached);
    if (clen > 0) {
        Rio_writen(connfd, cached, clen);
        return;
    }

    /* 5. connect to origin server */
    srvfd = Open_clientfd(host, port);
    Rio_readinitb(&rio_srv, srvfd);

    /* 6. build and send the rewritten request */
    char req[MAXLINE * 3];
    int n = 0;
    n += sprintf(req + n, "GET %s HTTP/1.1\r\n", path);
    if (strcmp(port, "80") == 0)
        n += sprintf(req + n, "Host: %s\r\n", host);
    else
        n += sprintf(req + n, "Host: %s:%s\r\n", host, port);
    n += sprintf(req + n, "%s", user_agent_hdr);
    n += sprintf(req + n, "Connection: close\r\n");
    n += sprintf(req + n, "Proxy-Connection: close\r\n");
    if (req_hdrs[0] != '\0')
        n += sprintf(req + n, "%s", req_hdrs);
    n += sprintf(req + n, "\r\n");

    Rio_writen(srvfd, req, strlen(req));

    /* 7. forward response (caching handled inside) */
    forward_response(connfd, &rio_srv, uri);

    Close(srvfd);
}

/* thread entry: one detached thread per connection */
static void *thread(void *vargp)
{
    int connfd = (int)(long)vargp;
    Pthread_detach(pthread_self());
    handle_request(connfd);
    Close(connfd);
    return NULL;
}

int main(int argc, char **argv)
{
    int listenfd, connfd;
    pthread_t tid;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        exit(0);
    }

    Signal(SIGPIPE, SIG_IGN);

    listenfd = Open_listenfd(argv[1]);
    if (listenfd < 0) {
        fprintf(stderr, "proxy: failed to listen on port %s\n", argv[1]);
        exit(1);
    }

    while (1) {
        connfd = Accept(listenfd, NULL, NULL);
        Pthread_create(&tid, NULL, thread, (void *)(long)connfd);
    }
}
