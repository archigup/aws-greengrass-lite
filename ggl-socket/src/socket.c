// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ggl/socket.h"
#include "pthread.h"
#include "stdlib.h"
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <ggl/buffer.h>
#include <ggl/defer.h>
#include <ggl/error.h>
#include <ggl/file.h>
#include <ggl/log.h>
#include <ggl/object.h>
#include <linux/sched.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdatomic.h>
#include <stdint.h>

__attribute__((constructor)) static void ignore_sigpipe(void) {
    // If SIGPIPE is not blocked, writing to a socket that the server has closed
    // will result in this process being killed.
    signal(SIGPIPE, SIG_IGN);
}

static pid_t sys_clone3(struct clone_args *args) {
    return (pid_t) syscall(SYS_clone3, args, sizeof(struct clone_args));
}

GglError ggl_read(int fd, GglBuffer *buf) {
    ssize_t ret = read(fd, buf->data, buf->len);
    if (ret < 0) {
        if (errno == EINTR) {
            return GGL_ERR_OK;
        }
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            GGL_LOGE("socket", "recv timed out on socket %d.", fd);
            return GGL_ERR_FAILURE;
        }
        int err = errno;
        GGL_LOGE("socket", "Failed to recv on %d: %d.", fd, err);
        return GGL_ERR_FAILURE;
    }
    if (ret == 0) {
        GGL_LOGD("socket", "Socket %d closed.", fd);
        return GGL_ERR_NOCONN;
    }

    *buf = ggl_buffer_substr(*buf, (size_t) ret, SIZE_MAX);
    return GGL_ERR_OK;
}

GglError ggl_read_exact(int fd, GglBuffer buf) {
    GglBuffer rest = buf;

    while (rest.len > 0) {
        GglError ret = ggl_read(fd, &rest);
        if (ret != GGL_ERR_OK) {
            return ret;
        }
    }

    return GGL_ERR_OK;
}

GglError ggl_write(int fd, GglBuffer *buf) {
    ssize_t ret = write(fd, buf->data, buf->len);
    if (ret < 0) {
        if (errno == EINTR) {
            return GGL_ERR_OK;
        }
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            GGL_LOGE("socket", "Write timed out on socket %d.", fd);
            return GGL_ERR_FAILURE;
        }
        if (errno == EPIPE) {
            GGL_LOGE("socket", "Write failed to %d; peer closed socket.", fd);
            return GGL_ERR_NOCONN;
        }
        int err = errno;
        GGL_LOGE("socket", "Failed to write to socket %d: %d.", fd, err);
        return GGL_ERR_FAILURE;
    }

    *buf = ggl_buffer_substr(*buf, (size_t) ret, SIZE_MAX);
    return GGL_ERR_OK;
}

GglError ggl_write_exact(int fd, GglBuffer buf) {
    GglBuffer rest = buf;

    while (rest.len > 0) {
        GglError ret = ggl_write(fd, &rest);
        if (ret != GGL_ERR_OK) {
            return ret;
        }
    }

    return GGL_ERR_OK;
}

GglError ggl_connect(GglBuffer path, int *fd) {
    if (path.len == 0) {
        return GGL_ERR_INVALID;
    }

    size_t pos = 0;
    for (size_t i = path.len; i > 0; i--) {
        if (path.data[i - 1] == '/') {
            pos = i;
            break;
        }
    }

    GglBuffer dir = ggl_buffer_substr(path, 0, pos);
    GglBuffer file = ggl_buffer_substr(path, pos, path.len);
    if (dir.len == 0) {
        dir = GGL_STR(".");
    }

    int dirfd = -1;
    GglError ret = ggl_dir_open(dir, O_PATH, &dirfd);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    return ggl_connectat(dirfd, file, fd);
}

GglError ggl_connectat(int dirfd, GglBuffer path, int *fd) {
    struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = { 0 } };

    if (path.len >= sizeof(addr.sun_path)) {
        GGL_LOGE("socket", "Connect path too long.");
        return GGL_ERR_FAILURE;
    }

    memcpy(addr.sun_path, path.data, path.len);

    int sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sockfd == -1) {
        GGL_LOGE("socket", "Failed to create socket: %d.", errno);
        return GGL_ERR_FATAL;
    }
    GGL_DEFER(close, sockfd);

    struct clone_args args = {
        // No CLONE_FS
        .flags = CLONE_VM | CLONE_VFORK | CLONE_FILES | CLONE_IO | CLONE_PTRACE
            | CLONE_SIGHAND,
        .exit_signal = SIGCHLD,
    };

    static atomic_int err;
    static pthread_mutex_t err_mtx = PTHREAD_MUTEX_INITIALIZER;

    {
        pthread_mutex_lock(&err_mtx);
        GGL_DEFER(pthread_mutex_unlock, err_mtx);
        err = -1;

        pid_t pid = sys_clone3(&args);

        if (pid == 0) {
            // async-signal-safe only
            int ret = fchdir(dirfd);
            if (ret != 0) {
                atomic_store_explicit(&err, errno, memory_order_release);
                _exit(0);
            }
            ret = connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));
            atomic_store_explicit(
                &err, (ret == 0) ? 0 : errno, memory_order_release
            );
            _exit(0);
        }

        if (pid < 0) {
            GGL_LOGE("socket", "Err %d when calling clone3.", errno);
            return GGL_ERR_FAILURE;
        }

        pid_t wait_ret;
        do {
            wait_ret = waitpid(pid, NULL, 0);
        } while ((wait_ret == -1) && (errno == EINTR));

        int conn_err = atomic_load_explicit(&err, memory_order_acquire);
        if (conn_err != 0) {
            GGL_LOGW(
                "socket",
                "Failed to connect to server (%.*s): %d.",
                (int) path.len,
                path.data,
                conn_err
            );
            return GGL_ERR_FAILURE;
        }
    }

    // To prevent deadlocking on hanged server, add a timeout
    struct timeval timeout = { .tv_sec = 5 };
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    GGL_DEFER_CANCEL(sockfd);
    *fd = sockfd;
    return GGL_ERR_OK;
}
