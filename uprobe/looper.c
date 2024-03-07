#include <stdio.h>
#include <unistd.h>

void uprobe_test_func(const char *message) {
	puts(message);
}

int main(int argc, char *argv[]) {
	for (;;) {
		uprobe_test_func("test message");
		sleep(1);
	}
}
