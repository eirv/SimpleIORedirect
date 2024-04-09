#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/version.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <syscall.h>
#include <unistd.h>

#include "linux_syscall_support.h"
#include "logging.h"

_syscall1(int, uname, struct utsname*, b)

_syscall3(int, seccomp, int, o, int, f, void*, a)

_syscall6(ssize_t,
          process_vm_readv,
          pid_t,
          pid,
          const struct kernel_iovec*,
          local_iov,
          unsigned long,
          local_iov_count,
          const struct kernel_iovec*,
          remote_iov,
          unsigned long,
          remote_iov_count,
          unsigned long,
          flags)

_syscall6(ssize_t,
          process_vm_writev,
          pid_t,
          pid,
          const struct kernel_iovec*,
          local_iov,
          unsigned long,
          local_iov_count,
          const struct kernel_iovec*,
          remote_iov,
          unsigned long,
          remote_iov_count,
          unsigned long,
          flags)

static int sendfd(int sockfd, int fd) {
    int data;
    struct iovec iov;
    struct msghdr msgh;
    struct cmsghdr *cmsgp;

    /* Allocate a char array of suitable size to hold the ancillary data.
       However, since this buffer is in reality a 'struct cmsghdr', use a
       union to ensure that it is suitably aligned. */
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        /* Space large enough to hold an 'int' */
        struct cmsghdr align;
    } controlMsg;

    /* The 'msg_name' field can be used to specify the address of the
       destination socket when sending a datagram. However, we do not
       need to use this field because 'sockfd' is a connected socket. */

    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    /* On Linux, we must transmit at least one byte of real data in
       order to send ancillary data. We transmit an arbitrary integer
       whose value is ignored by recvfd(). */

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    iov.iov_base = &data;
    iov.iov_len = sizeof(int);
    data = 12345;

    /* Set 'msghdr' fields that describe ancillary data */

    msgh.msg_control = controlMsg.buf;
    msgh.msg_controllen = sizeof(controlMsg.buf);

    /* Set up ancillary data describing file descriptor to send */

    cmsgp = reinterpret_cast<cmsghdr *>(msgh.msg_control);
    cmsgp->cmsg_level = SOL_SOCKET;
    cmsgp->cmsg_type = SCM_RIGHTS;
    cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsgp), &fd, sizeof(int));

    /* Send real plus ancillary data */

    if (sendmsg(sockfd, &msgh, 0) == -1) return -1;

    return 0;
}

static int recvfd(int sockfd) {
    int data, fd;
    ssize_t nr;
    struct iovec iov;
    struct msghdr msgh;

    /* Allocate a char buffer for the ancillary data. See the comments
       in sendfd() */
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } controlMsg;
    struct cmsghdr *cmsgp;

    /* The 'msg_name' field can be used to obtain the address of the
       sending socket. However, we do not need this information. */

    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    /* Specify buffer for receiving real data */

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    iov.iov_base = &data; /* Real data is an 'int' */
    iov.iov_len = sizeof(int);

    /* Set 'msghdr' fields that describe ancillary data */

    msgh.msg_control = controlMsg.buf;
    msgh.msg_controllen = sizeof(controlMsg.buf);

    /* Receive real plus ancillary data; real data is ignored */

    nr = recvmsg(sockfd, &msgh, 0);
    if (nr == -1) return -1;

    cmsgp = CMSG_FIRSTHDR(&msgh);

    /* Check the validity of the 'cmsghdr' */

    if (cmsgp == NULL || cmsgp->cmsg_len != CMSG_LEN(sizeof(int)) ||
        cmsgp->cmsg_level != SOL_SOCKET || cmsgp->cmsg_type != SCM_RIGHTS) {
        errno = EINVAL;
        return -1;
    }

    /* Return the received file descriptor to our caller */

    memcpy(&fd, CMSG_DATA(cmsgp), sizeof(int));
    return fd;
}

class ProcessMemory {
public:
    ProcessMemory(pid_t pid) : pid_(pid) {
    }

    int Read(uintptr_t addr, void *buf, size_t size) {
        kernel_iovec local{buf, size};
        kernel_iovec remote{reinterpret_cast<void *>(addr), size};
        return sys_process_vm_readv(pid_, &local, 1, &remote, 1, 0);
    }

    int Write(uintptr_t addr, void *buf, size_t size) {
        kernel_iovec local{buf, size};
        kernel_iovec remote{reinterpret_cast<void *>(addr), size};
        return sys_process_vm_writev(pid_, &local, 1, &remote, 1, 0);
    }

private:
    pid_t pid_;
};

void EnterSupervisor(int nfd, const char *target, const char *redirection) {
    seccomp_notif *req;
    seccomp_notif_resp *resp;
    seccomp_notif_sizes sizes;

    if (sys_seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == 0) {
        req = reinterpret_cast<decltype(req)>(malloc(sizes.seccomp_notif));
        resp = reinterpret_cast<decltype(resp)>(malloc(sizes.seccomp_notif_resp));
    } else {
        LOGE("seccomp(SECCOMP_GET_NOTIF_SIZES): %m");
        return;
    }

    char path[PATH_MAX];

    for (;;) {
        memset(req, 0, sizes.seccomp_notif);
        if (sys_ioctl(nfd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
            if (errno == EINTR) continue;
            LOGE("ioctl(SECCOMP_IOCTL_NOTIF_RECV): %m");
            goto exit;
        }

        memset(resp, 0, sizes.seccomp_notif_resp);
        resp->id = req->id;

        ProcessMemory mem(req->pid);
        int nread = mem.Read(req->data.args[1], path, sizeof(path) - 1);

        if (nread > 0) {
            path[nread] = '\0';
            LOGV("open: %s", path);

            if (strcmp(path, target) == 0) {
                int srcfd = sys_openat(AT_FDCWD, redirection, req->data.args[2],
                                       req->data.args[3]);
                if (srcfd > 0) {
                    seccomp_notif_addfd addfd = {.id = req->id,
                            .flags = SECCOMP_ADDFD_FLAG_SEND,
                            .srcfd = static_cast<uint32_t>(srcfd)};
                    resp->val = sys_ioctl(nfd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
                    sys_close(srcfd);
                } else {
                    resp->error = -errno;
                }
            } else {
                resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            }
        } else {
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        }

        if (sys_ioctl(nfd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0) {
            LOGE("ioctl(SECCOMP_IOCTL_NOTIF_SEND): %m");
        }
    }

    exit:
    free(req);
    free(resp);
    LOGD("supervisor exit");
    sys__exit(0);
}

bool InitIORedirect(const char *target, const char *redirection) {
    utsname un;
    sys_uname(&un);

    char *str;
    int kernel_major = strtol(un.release, &str, 10);
    int kernel_minor = strtol(str + 1, nullptr, 10);

    if (KERNEL_VERSION(kernel_major, kernel_minor, 0) < KERNEL_VERSION(5, 9, 0)) {
        LOGE("Kernel(%s) not supported", un.release);
        return false;
    }

    sys_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    };

    sock_fprog prog{sizeof(filter) / sizeof(sock_filter), filter};

    int socked_fds[2];
    sys_socketpair(AF_UNIX, SOCK_STREAM, 0, socked_fds);

    int supervisor_pid = sys_fork();
    if (supervisor_pid < 0) {
        LOGE("Failed to fork supervisor");
        return false;
    } else if (supervisor_pid == 0) {
        int notify_fd = recvfd(socked_fds[1]);
        sys_close(socked_fds[0]);
        sys_close(socked_fds[1]);
        EnterSupervisor(notify_fd, strdup(target), strdup(redirection));
    }

    int notify_fd = sys_seccomp(SECCOMP_SET_MODE_FILTER,
                                SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (notify_fd < 0) {
        LOGE("seccomp: %m");
        return false;
    }

    sendfd(socked_fds[0], notify_fd);
    sys_close(socked_fds[0]);
    sys_close(socked_fds[1]);
    sys_close(notify_fd);

    return true;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_io_github_eirv_simpleioredirect_MainActivity_redirect(JNIEnv *env, jclass,
                                                           jstring target, jstring redirection) {
    auto t = env->GetStringUTFChars(target, nullptr);
    auto r = env->GetStringUTFChars(redirection, nullptr);

    LOGD("Redirect %s -> %s", t, r);
    bool result = InitIORedirect(t, r);

    env->ReleaseStringUTFChars(target, t);
    env->ReleaseStringUTFChars(redirection, r);

    return result;
}