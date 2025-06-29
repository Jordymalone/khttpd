#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/namei.h>  // for kern_path
#include <linux/path.h>   // for struct path
#include <linux/sched/signal.h>
#include <linux/stat.h>  // for S_ISDIR, S_ISREG
#include <linux/tcp.h>

#include "http_parser.h"
#include "http_server.h"
#include "mime_type.h"

#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 256
#define FILE_READ_BUFFER_SIZE \
    4096  // Define a buffer size for reading file chunks

/* Define fixed HTML content as constants for readability and efficiency */
static const char HTML_DOC_HEADER[] =
    "<html><head><style>\r\n"
    "body{font-family: monospace; font-size: 15px;}\r\n"
    "td {padding: 1.5px 6px;}\r\n"
    "</style></head><body><table>\r\n";

static const char HTML_DOC_FOOTER[] = "</table></body></html>\r\n";

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

/**
 * http_server_send_chunk - formats and sends a data chunk for chunked encoding.
 * @sock: The socket to send the chunk to.
 * @data: The data buffer to send. Can be NULL if len is 0.
 * @len: The size of the data buffer. If 0, sends the terminating chunk.
 *
 * This function handles the chunk formatting (size in hex, CRLFs)
 * automatically. Returns 0 on success, or a negative error code.
 */
static int http_server_send_chunk(struct socket *sock,
                                  const char *data,
                                  size_t len)
{
    if (len > 0) {
        char size_hex[16];
        int hex_len;
        // For a data chunk:
        // 1. Format the chunk size in hexadecimal, followed by \r\n.
        hex_len = snprintf(size_hex, sizeof(size_hex), "%zx\r\n", len);

        // 2. Send the hexadecimal size.
        if (http_server_send(sock, size_hex, hex_len) < 0)
            return -1;

        // 3. Send the actual data.
        if (http_server_send(sock, data, len) < 0)
            return -1;

        // 4. Send the terminating \r\n for the chunk.
        if (http_server_send(sock, "\r\n", 2) < 0)
            return -1;
    } else {
        // For the final, zero-length chunk: send "0\r\n\r\n".
        if (http_server_send(sock, "0\r\n\r\n", 5) < 0)
            return -1;
    }
    return 0;
}

static void send_http_header(struct socket *sock,
                             int status,
                             const char *status_msg,
                             const char *content_type,
                             loff_t content_len,
                             const char *conn_msg)
{
    char header[SEND_BUFFER_SIZE];
    int len;

    len = snprintf(header, sizeof(header),
                   "HTTP/1.1 %d %s\r\n"
                   "Content-Type: %s\r\n"
                   "Connection: %s\r\n",
                   status, status_msg, content_type, conn_msg);
    // If content_len is negative, use chunked encoding. Otherwise, use
    // Content-Length.
    if (content_len < 0) {
        len += snprintf(header + len, sizeof(header) - len,
                        "Transfer-Encoding: chunked\r\n");
    } else {
        len += snprintf(header + len, sizeof(header) - len,
                        "Content-Length: %lld\r\n", content_len);
    }
    snprintf(header + len, sizeof(header) - len, "\r\n");
    http_server_send(sock, header, strlen(header));
}

// callback for 'iterate_dir', trace entry.
static bool tracedir(struct dir_context *dir_context,
                     const char *name,
                     int namelen,
                     loff_t offset,
                     u64 ino,
                     unsigned int d_type)
{
    struct http_request *request =
        container_of(dir_context, struct http_request, dir_context);
    char buf[SEND_BUFFER_SIZE] = {0};

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return true;
    }
    /* * Based on the entry type, format the link appropriately.
     * The href attribute should be relative to the current directory.
     */
    if (d_type == DT_DIR) {
        snprintf(buf, SEND_BUFFER_SIZE,
                 "<tr><td><a href=\"%s/\">%s/</a></td></tr>\r\n", name, name);
    } else {
        snprintf(buf, SEND_BUFFER_SIZE,
                 "<tr><td><a href=\"%s\">%s</a></td></tr>\r\n", name, name);
    }
    // Send each directory entry as a separate chunk using the helper function.
    http_server_send_chunk(request->socket, buf, strlen(buf));

    return true;
}

static bool handle_directory(struct http_request *request, const char *path)
{
    struct file *fp;

    request->dir_context.actor = tracedir;
    if (request->method != HTTP_GET) {
        send_http_header(request->socket, 501, "Not Implemented", "text/plain",
                         (loff_t) 19, "Close");
        http_server_send(request->socket, "501 Not Implemented", 19);
        return false;
    }
    send_http_header(request->socket, 200, "OK", "text/html", -1, "Keep-Alive");
    http_server_send_chunk(request->socket, HTML_DOC_HEADER,
                           sizeof(HTML_DOC_HEADER) - 1);

    if (strcmp(request->request_url, "/") != 0) {
        char buf[SEND_BUFFER_SIZE] = {0};
        snprintf(buf, sizeof(buf),
                 "<tr><td><a href=\"..\">..</a></td></tr>\r\n");
        http_server_send_chunk(request->socket, buf, strlen(buf));
    }

    fp = filp_open(path, O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(fp)) {
        pr_info("Open directory '%s' failed", path);
        // If opening dir fails, we must still send the terminating chunk.
        http_server_send_chunk(request->socket, NULL, 0);
        return false;
    }

    iterate_dir(fp, &request->dir_context);
    filp_close(fp, NULL);
    http_server_send_chunk(request->socket, HTML_DOC_FOOTER,
                           sizeof(HTML_DOC_FOOTER) - 1);

    // Send the final, zero-length chunk.
    http_server_send_chunk(request->socket, NULL, 0);
    return true;
}

static int handle_file(struct http_request *request, const char *path)
{
    struct file *fp;
    const char *content_type;
    char *read_buf;
    int ret;

    fp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        send_http_header(request->socket, 404, "Not Found", "text/plain",
                         (loff_t) 14, "Close");
        http_server_send(request->socket, "404 Not Found.", 14);
        return -ENOENT;
    }

    content_type = get_mime_type_from_path(path);

    // 1. Send the HTTP header for chunked transfer.
    //    We pass -1 to content_len to trigger "Transfer-Encoding: chunked".
    send_http_header(request->socket, 200, "OK", content_type, -1,
                     "Keep-Alive");

    read_buf = kmalloc(FILE_READ_BUFFER_SIZE, GFP_KERNEL);
    if (!read_buf) {
        pr_err("khttpd: Failed to allocate file read buffer\n");
        // Still need to properly terminate the response before closing.
        http_server_send_chunk(request->socket, NULL, 0);
        filp_close(fp, NULL);
        return -ENOMEM;
    }

    // 2. Loop to read the file and send it chunk by chunk.
    while ((ret = kernel_read(fp, read_buf, FILE_READ_BUFFER_SIZE,
                              &fp->f_pos)) > 0) {
        if (http_server_send_chunk(request->socket, read_buf, ret) < 0) {
            pr_err("khttpd: Send file chunk failed\n");
            break;  // Stop if sending fails
        }
    }
    kfree(read_buf);
    // 3. Send the final, zero-length chunk to signify the end of the response.
    http_server_send_chunk(request->socket, NULL, 0);
    filp_close(fp, NULL);
    return 0;
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    char full_path[256];
    struct path path_info;
    struct inode *inode;
    int ret = 0;

    snprintf(full_path, sizeof(full_path), "%s%s", daemon_list.root_path,
             request->request_url);

    ret = kern_path(full_path, LOOKUP_FOLLOW, &path_info);
    if (ret < 0) {
        send_http_header(request->socket, 404, "Not Found", "text/plain",
                         (loff_t) 14, "Close");
        http_server_send(request->socket, "404 Not Found.", 14);
        return -ENOENT;
    }

    inode = path_info.dentry->d_inode;

    if (S_ISDIR(inode->i_mode)) {
        ret = handle_directory(request, full_path);
    } else if (S_ISREG(inode->i_mode)) {
        ret = handle_file(request, full_path);
    } else {
        send_http_header(request->socket, 403, "Forbidden", "text/plain",
                         (loff_t) 9, "Close");
        http_server_send(request->socket, "Forbidden", 9);
        ret = -EPERM;
    }

    path_put(&path_info);
    return ret;
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
