// SPDX-License-Identifier: GPL-2.0
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/highmem.h>

KPM_NAME("kx-mem-rw");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Krishu X");
KPM_DESCRIPTION("KX Memory Read/Write via access_process_vm");

// হেল্পার: হেক্স স্ট্রিং থেকে বাইট অ্যারে পার্স করা
static int parse_hex(const char *hex, unsigned char *out, int max_len) {
    int len = 0;
    while (*hex && len < max_len) {
        int hi, lo;
        char c1 = *hex++;
        if (c1 == ' ' || c1 == '\t') continue;
        if (c1 >= '0' && c1 <= '9') hi = c1 - '0';
        else if (c1 >= 'a' && c1 <= 'f') hi = c1 - 'a' + 10;
        else if (c1 >= 'A' && c1 <= 'F') hi = c1 - 'A' + 10;
        else return -1;

        char c2 = *hex++;
        if (c2 >= '0' && c2 <= '9') lo = c2 - '0';
        else if (c2 >= 'a' && c2 <= 'f') lo = c2 - 'a' + 10;
        else if (c2 >= 'A' && c2 <= 'F') lo = c2 - 'A' + 10;
        else return -1;

        out[len++] = (hi << 4) | lo;
    }
    return len;
}

static long mem_ctl0(const char *args, char *__user out_msg, int outlen) {
    char buf[256];
    char cmd[16];
    int pid, size;
    unsigned long addr;
    int ret;

    // কমান্ড ফরম্যাট: "read <pid> <hex_addr> <size>" অথবা "write <pid> <hex_addr> <hex_bytes>"
    if (sscanf(args, "%15s %d %lx %x", cmd, &pid, &addr, &size) < 4) {
        strncpy(buf, "ERR: invalid args", sizeof(buf));
        compat_copy_to_user(out_msg, buf, strlen(buf)+1);
        return -1;
    }

    // টার্গেট task_struct নিরাপদে রেফারেন্স করা
    struct task_struct *task;
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) {
        strncpy(buf, "ERR: pid not found", sizeof(buf));
        compat_copy_to_user(out_msg, buf, strlen(buf)+1);
        return -1;
    }

    if (strcmp(cmd, "read") == 0 && size > 0 && size <= 128) {
        unsigned char kbuf[128];
        ret = access_process_vm(task, addr, kbuf, size, FOLL_FORCE);
        if (ret <= 0) {
            snprintf(buf, sizeof(buf), "ERR: read failed ret=%d", ret);
        } else {
            int off = 0;
            off += snprintf(buf+off, sizeof(buf)-off, "OK READ %d bytes:", ret);
            for (int i = 0; i < ret && off < sizeof(buf)-4; i++) {
                off += snprintf(buf+off, sizeof(buf)-off, " %02X", kbuf[i]);
            }
        }
    } else if (strcmp(cmd, "write") == 0) {
        // args থেকে হেক্স স্ট্রিং বের করা (pid, addr, size এর পরে যা আছে)
        const char *hexstr = args;
        int space = 0;
        while (*hexstr && space < 3) { if (*hexstr == ' ') space++; hexstr++; }

        unsigned char wbuf[128];
        int wlen = parse_hex(hexstr, wbuf, sizeof(wbuf));
        if (wlen <= 0) {
            strncpy(buf, "ERR: bad hex", sizeof(buf));
        } else {
            ret = access_process_vm(task, addr, wbuf, wlen, FOLL_FORCE | FOLL_WRITE);
            if (ret == wlen)
                snprintf(buf, sizeof(buf), "OK WROTE %d bytes", wlen);
            else
                snprintf(buf, sizeof(buf), "ERR: write ret=%d (want %d)", ret, wlen);
        }
    } else {
        strncpy(buf, "ERR: unknown cmd", sizeof(buf));
    }

    put_task_struct(task);
    compat_copy_to_user(out_msg, buf, strlen(buf)+1);
    return 0;
}

static long mem_init(const char *args, const char *event, void *reserved) {
    pr_info("kx-mem-rw: loaded\n");
    return 0;
}

static long mem_exit(void *reserved) {
    pr_info("kx-mem-rw: unloaded\n");
    return 0;
}

KPM_INIT(mem_init);
KPM_CTL0(mem_ctl0);
KPM_EXIT(mem_exit);
