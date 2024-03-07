#include <unistd.h>

#include "uprobe.skel.h"

int main(int argc, char *argv[]) {
	struct uprobe_bpf *skel;
	int err;

	skel = uprobe_bpf__open();
	if (NULL == skel) {
		perror("uprobe_bpf__open");
		return 1;
	}

	err = uprobe_bpf__load(skel);
	if (0 != err) {
		perror("uprobe_bpf__load");
		uprobe_bpf__destroy(skel);
		return 1;
	}

	// Looks like luck that memory offset and file offset are the same for the toy
	// C program:
	//
	// ❯ objdump -F --disassemble=uprobe_test_func looper
	// ...
	// 00000000000007d4 <uprobe_test_func> (File Offset: 0x7d4):
	// ...
	if (NULL == bpf_program__attach_uprobe(skel->progs.uprobe_test1, false, -1, "/home/debian/Code/ebpf/uprobe/looper", 0x7d4)) {
		perror("bpf_program__attach_uprobe");
		uprobe_bpf__destroy(skel);
		return 1;
	}

	// objdump -F --disassemble='main.(*Message).Print' glooper | head
	// ...
	// 000000000008f740 <main.(*Message).Print> (File Offset: 0x7f740):
	// ...
	//
	// Looks like the `.text` section is offset by 0x10000 in memory vs the file.
	// Maybe related to segment offset in the ELF program headers.
	if (NULL == bpf_program__attach_uprobe(skel->progs.uprobe_test2, false, -1, "/home/debian/Code/ebpf/uprobe/glooper", 0x7f740)) {
		perror("bpf_program__attach_uprobe");
		uprobe_bpf__destroy(skel);
		return 1;
	}

	sleep(30);

	uprobe_bpf__destroy(skel);

	return 0;
}
