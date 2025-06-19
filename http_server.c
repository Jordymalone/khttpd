#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>

#include "http_parser.h"
#include "http_server.h"

#define CRLF "\r\n"

#define HTTP_RESPONSE_200_DUMMY                               \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Close" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                     \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Keep-Alive" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF

#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 256

extern struct workqueue_struct *khttpd_wq;
struct httpd_service daemon_list = {.is_stopped = false, .root_path = NULL};

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    struct list_head node;           // for list management
    struct work_struct khttpd_work;  // workitem for workqueue
    struct dir_context dir_context;
};

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {
        .msg_name = 0,
        .msg_namelen = 0,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0,
    };
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0,
    };
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

// callback for 'iterate_dir', trace entry.
static bool tracedir(struct dir_context *dir_context,
                     const char *name,
                     int namelen,
                     loff_t offset,
                     u64 ino,
                     unsigned int d_type)
{
    if (strcmp(name, ".") && strcmp(name, "..")) {
        struct http_request *request =
            container_of(dir_context, struct http_request, dir_context);
        char buf[SEND_BUFFER_SIZE] = {0};

        snprintf(buf, SEND_BUFFER_SIZE,
                 "<tr><td><a href=\"%s\">%s</a></td></tr>\r\n", name, name);
        http_server_send(request->socket, buf, strlen(buf));
    }
    return true;
}

static bool handle_directory(struct http_request *request)
{
    struct file *fp;
    char buf[SEND_BUFFER_SIZE] = {0};

    request->dir_context.actor = tracedir;
    if (request->method != HTTP_GET) {
        snprintf(buf, SEND_BUFFER_SIZE,
                 "HTTP/1.1 501 Not Implemented\r\n%s%s%s%s",
                 "Content-Type: text/plain\r\n", "Content-Length: 19\r\n",
                 "Connection: Close\r\n", "501 Not Implemented\r\n");
        http_server_send(request->socket, buf, strlen(buf));
        return false;
    }
    snprintf(buf, SEND_BUFFER_SIZE, "HTTP/1.1 200 OK\r\n%s%s%s",
             "Connection: Keep-Alive\r\n", "Content-Type: text/html\r\n",
             "Keep-Alive: timeout=5, max=1000\r\n\r\n");
    http_server_send(request->socket, buf, strlen(buf));

    snprintf(buf, SEND_BUFFER_SIZE, "%s%s%s%s", "<html><head><style>\r\n",
             "body{font-family: monospace; font-size: 15px;}\r\n",
             "td {padding: 1.5px 6px;}\r\n",
             "</style></head><body><table>\r\n");
    http_server_send(request->socket, buf, strlen(buf));

    fp = filp_open(daemon_list.root_path, O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(fp)) {
        pr_info("Open directory '%s' failed", daemon_list.root_path);
        return false;
    }

    iterate_dir(fp, &request->dir_context);
    snprintf(buf, SEND_BUFFER_SIZE, "</table></body></html>\r\n");
    http_server_send(request->socket, buf, strlen(buf));
    filp_close(fp, NULL);
    return true;
}


static int http_server_response(struct http_request *request, int keep_alive)
{
    int ret = handle_directory(request);
    if (!ret) {
        pr_info("handle_directory failed\n");
        return -1;
    }
    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}

static void http_server_worker(struct work_struct *work)
{
    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete,
    };
    struct http_request *worker =
        container_of(work, struct http_request, khttpd_work);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return;
    }

    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = worker;
    while (!daemon_list.is_stopped) {
        int ret = http_server_recv(worker->socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (worker->complete && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, RECV_BUFFER_SIZE);
    }
    kernel_sock_shutdown(worker->socket, SHUT_RDWR);
    sock_release(worker->socket);
    kfree(buf);
    return;
}

static struct work_struct *create_work(struct socket *sk)
{
    struct http_request *work =
        kmalloc(sizeof(*work), GFP_KERNEL);  // GFP_KERNEL is used to allocate
                                             // memory that can be freed later
    if (!work) {
        pr_err("can't allocate memory for work!\n");
        return NULL;
    }
    work->socket = sk;
    INIT_WORK(&work->khttpd_work, http_server_worker);
    list_add(&work->node, &daemon_list.head);
    return &work->khttpd_work;
}

static void free_work(void)
{
    struct http_request *tar, *tmp;

    list_for_each_entry_safe (tar, tmp, &daemon_list.head, node) {
        kernel_sock_shutdown(tar->socket, SHUT_RDWR);
        flush_work(&tar->khttpd_work);
        sock_release(tar->socket);
        kfree(tar);
    }
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct http_server_param *param = (struct http_server_param *) arg;
    struct work_struct *work;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    INIT_LIST_HEAD(&daemon_list.head);

    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            if (signal_pending(current))
                break;
            pr_err("kernel_accept() error: %d\n", err);
            continue;
        }
        work = create_work(socket);
        if (!work) {
            pr_err("can't create work for socket\n");
            kernel_sock_shutdown(socket, SHUT_RDWR);
            sock_release(socket);
            continue;
        }
        queue_work(khttpd_wq, work);
    }
    daemon_list.is_stopped = true;
    free_work();

    return 0;
}
