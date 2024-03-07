#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("uprobe//home/debian/Code/ebpf/uprobe/looper:uprobe_test_func")
int BPF_KPROBE(uprobe_test1, char *message) {
	char msg[128];
	long res;

	res =  bpf_probe_read_user_str(msg, 128, message);

	if (res < 0) {
		bpf_printk("failed to read user memory");
		return 0;
	}

	bpf_printk("looper called with: %s", msg);

	return 0;
}

struct go_string {
	void *data;
	u64 length;
};

SEC("uprobe//home/debian/Code/ebpf/uprobe/glooper:testfunc")
int uprobe_test2(struct pt_regs *ctx) {
	struct go_string receiver;
	long res;
	// need to initialize 
	char message[128] = {0};

	bpf_printk("uprobe_test2");

#if defined __TARGET_ARCH_arm64
	res = bpf_probe_read_user(&receiver, sizeof(receiver), (void *)(ctx->regs[0]));
#elif defined __TARGET_ARCH_x86
	res = bpf_probe_read_user(&receiver, sizeof(receiver), (void *)(ctx->regs.ax));
#endif
	if (res < 0) {
		bpf_printk("failed to read user memory 1: %d", -res);
		return 0;
	}

	if (NULL == receiver.data) {
		bpf_printk("receiver.data is null");
		return 0;
	}

	if (receiver.length > sizeof(message)) {
		bpf_printk("message too long");
		return 0;
	}

	res = bpf_probe_read_user(message, receiver.length, receiver.data);
	if (res < 0) {
		bpf_printk("failed to read user memory 2: %d", -res);
		return 0;
	}

	bpf_printk("uprobe_test2: %s, %d", message, receiver.length);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
