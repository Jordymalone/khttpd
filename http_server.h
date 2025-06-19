#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#define MODULE_NAME "khttpd"

#include <linux/list.h>
#include <linux/workqueue.h>
#include <net/sock.h>

struct http_server_param {
    struct socket *listen_socket;
};

struct httpd_service {
    bool is_stopped;
    char *root_path;  // Used to record the path passed by the user
    struct list_head head;
};

extern int http_server_daemon(void *arg);

#endif
