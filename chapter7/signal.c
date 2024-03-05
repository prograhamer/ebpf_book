#include <unistd.h>

#include "signal.skel.h"

int main(int argc, char *argv[]) {
	struct signal_bpf *skel;
	int err;

	skel = signal_bpf__open();
	if (NULL == skel) {
		perror("signal_bpf__open");
		return 1;
	}

	err = signal_bpf__load(skel);
	if (0 != err) {
		perror("signal_bpf__load");
		signal_bpf__destroy(skel);
		return 1;
	}

	err = signal_bpf__attach(skel);
	if (0 != err) {
		perror("signal_bpf__attach");
		signal_bpf__destroy(skel);
		return 1;
	}

	sleep(30);

	signal_bpf__destroy(skel);

	return 0;
}
