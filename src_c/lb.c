#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define MAX_UPSTREAMS 8
#define MAX_EVENTS 64
#define BACKLOG 65535
#define UNIX_PATH_MAX 108
#define DEFAULT_LB_WORKERS 2
#define MAX_LB_WORKERS 4

typedef struct {
    char path[UNIX_PATH_MAX];
    int fd;
} Upstream;

static Upstream upstreams[MAX_UPSTREAMS];
static int upstream_count;
static uint32_t rr_next;
static int efd;

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void sleep_ms(long ms) {
    struct timespec ts = {
        .tv_sec = ms / 1000,
        .tv_nsec = (ms % 1000) * 1000000L
    };

    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {}
}

static int set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD, 0);

    if (flags < 0) {
        return -1;
    }

    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

/*
 * Mantém TCP_NODELAY e deixa TCP_QUICKACK fora.
 *
 * rc3 mostrou que restaurar TCP_QUICKACK não ajudou no oficial.
 * Este rc mantém a base do rc1 e testa apenas multi-worker no accept.
 */
static void set_tcp_opts(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

static int ends_with(const char *s, const char *suffix) {
    size_t n = strlen(s);
    size_t m = strlen(suffix);

    return n >= m && memcmp(s + n - m, suffix, m) == 0;
}

static void add_upstream_path(const char *raw) {
    if (upstream_count >= MAX_UPSTREAMS) {
        return;
    }

    while (*raw == ' ' || *raw == '\t') {
        raw++;
    }

    if (!*raw) {
        return;
    }

    char *end = (char *)raw + strlen(raw);

    while (
        end > raw &&
        (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n')
    ) {
        end--;
    }

    size_t len = (size_t)(end - raw);

    if (len == 0) {
        return;
    }

    Upstream *u = &upstreams[upstream_count];
    memset(u, 0, sizeof(*u));

    if (len >= UNIX_PATH_MAX) {
        fprintf(stderr, "upstream path too long: %.*s\n", (int)len, raw);
        exit(1);
    }

    memcpy(u->path, raw, len);
    u->path[len] = '\0';

    if (!ends_with(u->path, ".ctrl")) {
        if (len + 5 >= UNIX_PATH_MAX) {
            fprintf(stderr, "control path too long: %s.ctrl\n", u->path);
            exit(1);
        }

        memcpy(u->path + len, ".ctrl", 6);
    }

    u->fd = -1;
    upstream_count++;
}

static void parse_upstreams(void) {
    const char *env = getenv("RINHA_UPSTREAMS");

    if (!env || !*env) {
        env = "/run/sock/canjica.sock,/run/sock/pamonha.sock";
    }

    char *tmp = strdup(env);

    if (!tmp) {
        exit(1);
    }

    char *save = NULL;

    for (
        char *tok = strtok_r(tmp, ",", &save);
        tok;
        tok = strtok_r(NULL, ",", &save)
    ) {
        add_upstream_path(tok);
    }

    free(tmp);

    if (upstream_count == 0) {
        fprintf(stderr, "RINHA_UPSTREAMS did not contain any usable path\n");
        exit(1);
    }
}

static int connect_ctrl_once(const char *path) {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);

    if (fd < 0) {
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    set_cloexec(fd);
    return fd;
}

static int connect_ctrl_wait(const char *path, int attempts, long delay_ms) {
    for (int i = 0; attempts <= 0 || i < attempts; i++) {
        int fd = connect_ctrl_once(path);

        if (fd >= 0) {
            return fd;
        }

        sleep_ms(delay_ms);
    }

    return -1;
}

static void connect_all_upstreams(void) {
    for (int i = 0; i < upstream_count; i++) {
        int fd = connect_ctrl_wait(upstreams[i].path, 0, 25);

        if (fd < 0) {
            die("connect control socket");
        }

        upstreams[i].fd = fd;
    }
}

static int reconnect_upstream(int idx) {
    if (upstreams[idx].fd >= 0) {
        close(upstreams[idx].fd);
        upstreams[idx].fd = -1;
    }

    int fd = connect_ctrl_wait(upstreams[idx].path, 20, 5);

    if (fd < 0) {
        return -1;
    }

    upstreams[idx].fd = fd;
    return 0;
}

static int send_fd_once(int ctrl_fd, int pass_fd) {
    char byte = 'F';

    struct iovec iov = {
        .iov_base = &byte,
        .iov_len = 1
    };

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control;

    memset(&control, 0, sizeof(control));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof(control.buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));

    memcpy(CMSG_DATA(cmsg), &pass_fd, sizeof(pass_fd));

    msg.msg_controllen = sizeof(control.buf);

    for (;;) {
        ssize_t n = sendmsg(ctrl_fd, &msg, MSG_NOSIGNAL);

        if (n == 1) {
            return 0;
        }

        if (n < 0 && errno == EINTR) {
            continue;
        }

        return -1;
    }
}

static int handoff_client_fd(int idx, int cfd) {
    if (upstreams[idx].fd < 0 && reconnect_upstream(idx) < 0) {
        return -1;
    }

    if (send_fd_once(upstreams[idx].fd, cfd) == 0) {
        return 0;
    }

    if (reconnect_upstream(idx) < 0) {
        return -1;
    }

    return send_fd_once(upstreams[idx].fd, cfd);
}

/*
 * Cada worker chama listen_tcp().
 *
 * Isso é proposital: para SO_REUSEPORT distribuir accept entre processos,
 * cada worker precisa criar/bindar/listen no próprio socket.
 * Não crie o listener antes do fork.
 */
static int listen_tcp(int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

    if (fd < 0) {
        return -1;
    }

    int one = 1;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, BACKLOG) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static inline int next_upstream_idx(void) {
    /*
     * Fast path para a submissão oficial: 2 APIs.
     * Evita divisão/modulo no hot path.
     */
    if (__builtin_expect(upstream_count == 2, 1)) {
        int idx = (int)(rr_next & 1u);
        rr_next ^= 1u;
        return idx;
    }

    int idx = (int)(rr_next % (uint32_t)upstream_count);
    rr_next++;

    return idx;
}

static void accept_loop(int sfd) {
    for (;;) {
        int cfd = accept4(sfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);

        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }

            if (errno == EINTR) {
                continue;
            }

            return;
        }

        set_tcp_opts(cfd);

        int idx = next_upstream_idx();

        if (handoff_client_fd(idx, cfd) < 0) {
            for (int j = 1; j < upstream_count; j++) {
                int alt = idx + j;

                if (alt >= upstream_count) {
                    alt -= upstream_count;
                }

                if (handoff_client_fd(alt, cfd) == 0) {
                    break;
                }
            }
        }

        close(cfd);
    }
}

static void run_worker(int worker_id, int port) {
    /*
     * Cada processo tem suas próprias conexões de controle e seu próprio rr_next.
     * O seed alternado evita que todos os workers comecem mandando para a mesma API.
     */
    rr_next = (uint32_t)worker_id;

    parse_upstreams();
    connect_all_upstreams();

    int sfd = listen_tcp(port);

    if (sfd < 0) {
        die("listen tcp");
    }

    efd = epoll_create1(EPOLL_CLOEXEC);

    if (efd < 0) {
        die("epoll_create1");
    }

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = sfd
    };

    if (epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &ev) < 0) {
        die("epoll_ctl listen");
    }

    struct epoll_event evs[MAX_EVENTS];

    for (;;) {
        int n = epoll_wait(efd, evs, MAX_EVENTS, -1);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }

            die("epoll_wait");
        }

        for (int i = 0; i < n; i++) {
            if (evs[i].data.fd == sfd) {
                accept_loop(sfd);
            }
        }
    }
}

static int read_int_env(const char *name, int fallback, int minv, int maxv) {
    const char *env = getenv(name);

    if (!env || !*env) {
        return fallback;
    }

    int v = atoi(env);

    if (v < minv) {
        v = minv;
    }

    if (v > maxv) {
        v = maxv;
    }

    return v;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    int port = read_int_env("RINHA_LB_PORT", 9999, 1, 65535);
    int workers = read_int_env("RINHA_LB_WORKERS", DEFAULT_LB_WORKERS, 1, MAX_LB_WORKERS);

    /*
     * Fork antes de criar listener/control sockets.
     * Assim cada worker cria seu próprio listener SO_REUSEPORT.
     */
    for (int i = 1; i < workers; i++) {
        pid_t pid = fork();

        if (pid < 0) {
            die("fork");
        }

        if (pid == 0) {
            run_worker(i, port);
            return 0;
        }
    }

    run_worker(0, port);
    return 0;
}
