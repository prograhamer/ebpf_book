#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("kprobe/kill_pid_info")
int BPF_KPROBE(kprobe_kill_pid_info, int sig, struct kernel_siginfo *info, struct pid *pid) {
	long err;
	struct kernel_siginfo si;
	struct pid p;

	// Seems like this is a special value indicating the signal originates in the kernel.
	// This appears to be true for any time this kprobe is triggered on my VM.
	//
	// These special values are documented here, which seems appropriate to this case, maybe:
	// https://www.kernel.org/doc/html/v6.7/core-api/tracepoint.html#c.trace_signal_generate
	//
	// Stealing these definitions from here:
	// https://github.com/torvalds/linux/blob/master/include/linux/sched/signal.h#L567-L569
	if ((struct kernel_siginfo *)0 == info) {
		// SEND_SIG_NOINFO
		bpf_printk("[KPROBE] info = SEND_SIG_NOINFO");
	} else if ((struct kernel_siginfo *)1 == info) {
		// SEND_SIG_PRIV
		bpf_printk("[KPROBE] info = SEND_SIG_PRIV");
	} else {
		// This fails for some reason. Errno 14 = EFAULT (bad address).
		// Seems like the value for `info` is sometimes not actually a valid pointer, so we can't
		// rely on getting information from there.
		err = bpf_probe_read_kernel(&si, sizeof(struct kernel_siginfo), info);
		if (err < 0) {
			bpf_printk("[KPROBE] failed to read kernel memory: struct kernel_siginfo: errno=%d", -err);
		}
	}

	err = bpf_probe_read_kernel(&p, sizeof(struct pid), pid);
	if (err < 0) {
		bpf_printk("[KPROBE] failed to read kernel memory: struct pid: errno=%d", -err);
	}

	bpf_printk("[KPROBE] pid %d received signal %d", p.numbers[0].nr, sig);
	return 0;
}

/*
From /sys/kernel/debug/tracing/events/syscalls/sys_enter_kill/format
name: sys_enter_kill
ID: 123
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:pid_t pid;	offset:16;	size:8;	signed:0;
	field:int sig;	offset:24;	size:8;	signed:0;

print fmt: "pid: 0x%08lx, sig: 0x%08lx", ((unsigned long)(REC->pid)), ((unsigned long)(REC->sig))
*/

struct my_kill_stuff {
	struct trace_entry ent; // matches the first four fields, size 8 bytes

	int syscall_nr;    // int, size 4 bytes
	int padding;       // 4 byte padding so pid is at offset 16
	unsigned long pid; // pid has size 8, despite the definition of pid_t in vmlinux.h
	unsigned long sig; // sig also has size 8
};

SEC("tp/syscalls/sys_enter_kill")
int tp_btf_signal_deliver(struct my_kill_stuff *ctx) {
	bpf_printk("[TP] pid %ld received signal %ld", ctx->pid, ctx->sig);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
