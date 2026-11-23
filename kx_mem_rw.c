// SPDX-License-Identifier: GPL-2.0
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <kallsyms.h>   // কার্নেল সিম্বল রিজলভ করার সঠিক হেডার

// KernelPatch হেডারে FOLL_* ম্যাক্রো না থাকলে ডিফাইন করা
#ifndef FOLL_WRITE
#define FOLL_WRITE 0x01
#endif
#ifndef FOLL_FORCE
#define FOLL_FORCE 0x10
#endif

// কার্নেল ফাংশন পয়েন্টার ডিক্লেয়ারেশন
static int (*k_access_process_vm)(struct task_struct *tsk, unsigned long addr, void *buf, int len, unsigned int gup_flags);
static void (*k_get_task_struct)(struct task_struct *t);
static void (*k_put_task_struct)(struct task_struct *t);
static void (*k_rcu_read_lock)(void);
static void (*k_rcu_read_unlock)(void);

// হেক্স স্ট্রিং থেকে বাইট অ্যারে পার্স করার হেল্পার
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

// মূল কন্ট্রোল ফাংশন (Read/Write লজিক)
static long mem_ctl0(const char *args, char *__user out_msg, int outlen) {
    char buf[256];
    char cmd[16];
    int pid, size;
    unsigned long addr;
    int ret;

    if (!k_access_process_vm) {
        strncpy(buf, "ERR: access_process_vm not resolved", sizeof(buf));
        compat_copy_to_user(out_msg, buf, strlen(buf)+1);
        return -1;
    }

    // কমান্ড ফরম্যাট: "read <pid> <hex_addr> <size>" অথবা "write <pid> <hex_addr> <hex_bytes>"
    if (sscanf(args, "%15s %d %lx %x", cmd, &pid, &addr, &size) < 4) {
        strncpy(buf, "ERR: invalid args", sizeof(buf));
        compat_copy_to_user(out_msg, buf, strlen(buf)+1);
        return -1;
    }

    struct task_struct *task;
    if (k_rcu_read_lock) k_rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task && k_get_task_struct) k_get_task_struct(task);
    if (k_rcu_read_unlock) k_rcu_read_unlock();

    if (!task) {
        strncpy(buf, "ERR: pid not found", sizeof(buf));
        compat_copy_to_user(out_msg, buf, strlen(buf)+1);
        return -1;
    }

    if (strcmp(cmd, "read") == 0 && size > 0 && size <= 128) {
        unsigned char kbuf[128];
        ret = k_access_process_vm(task, addr, kbuf, size, FOLL_FORCE);
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
        const char *hexstr = args;
        int space = 0;
        while (*hexstr && space < 3) { if (*hexstr == ' ') space++; hexstr++; }

        unsigned char wbuf[128];
        int wlen = parse_hex(hexstr, wbuf, sizeof(wbuf));
        if (wlen <= 0) {
            strncpy(buf, "ERR: bad hex", sizeof(buf));
        } else {
            ret = k_access_process_vm(task, addr, wbuf, wlen, FOLL_FORCE | FOLL_WRITE);
            if (ret == wlen)
                snprintf(buf, sizeof(buf), "OK WROTE %d bytes", wlen);
            else
                snprintf(buf, sizeof(buf), "ERR: write ret=%d (want %d)", ret, wlen);
        }
    } else {
        strncpy(buf, "ERR: unknown cmd", sizeof(buf));
    }

    if (k_put_task_struct) k_put_task_struct(task);
    compat_copy_to_user(out_msg, buf, strlen(buf)+1);
    return 0;
}

// মডিউল ইনিশিয়ালাইজেশন
static long mem_init(const char *args, const char *event, void *reserved) {
    // kallsyms_lookup_name দিয়ে ফাংশন পয়েন্টার রিজলভ করা হচ্ছে
    k_access_process_vm = (void *)kallsyms_lookup_name("access_process_vm");
    k_get_task_struct   = (void *)kallsyms_lookup_name("get_task_struct");
    k_put_task_struct   = (void *)kallsyms_lookup_name("put_task_struct");
    k_rcu_read_lock     = (void *)kallsyms_lookup_name("rcu_read_lock");
    k_rcu_read_unlock   = (void *)kallsyms_lookup_name("rcu_read_unlock");

    if (!k_access_process_vm) {
        pr_err("kx-mem-rw: access_process_vm NOT FOUND in kallsyms!\n");
    } else {
        pr_info("kx-mem-rw: access_process_vm found at %p\n", k_access_process_vm);
    }

    pr_info("kx-mem-rw: module initialized successfully\n");
    return 0;  // সবসময় 0 রিটার্ন, যাতে load failed -1 না আসে
}

// মডিউল আনলোড
static long mem_exit(void *reserved) {
    pr_info("kx-mem-rw: unloaded\n");
    return 0;
}

KPM_INIT(mem_init);
KPM_CTL0(mem_ctl0);
KPM_EXIT(mem_exit);
