/**
 * @mebeim - 2024-09-13
 */

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void bdecode_integer(void);
static void bdecode_list(void);
static void bdecode_dictionary(void);
static void bdecode_key_value(void);
static void bdecode_string(void);
static void bdecode(void);

static void die(const char *msg) {
	fprintf(stderr, "\n%s\n", msg);
	_exit(1);
}

static void bdecode_integer(void) {
	struct {
		int c;
		unsigned len;
		long value;
		char *endptr;
		char buf[32];
	} stack;

	memset(&stack, 0, sizeof(stack));

	while (1) {
		if ((stack.c = getchar()) == EOF)
			die("I/O error");

		if (stack.c == 'e')
			break;

		/* BUG #1: bad bound check stack.buf[] leading to limited linear stack
		 * buffer overflow.
		 *
		 * The saved PAC-signed return address is before (lower address) the
		 * buffer and therefore cannot be overwritten. The caller function is
		 * PAC-protected, so this bug alone is not enough to break things.
		 *
		 * However, having leaked a PAC-signed return address of another target
		 * function (BUG #2), one can replace the return address of the caller
		 * with the leaked value IFF the caller has the same stack depth as the
		 * target function, thus making it return where the target function
		 * would have returned, but with a corrupted stack frame.
		 */
		stack.buf[stack.len++] = stack.c;
		if (stack.len > sizeof(stack.buf) + 0x10)
			break;
	}

	errno = 0;

	/* This check is easily bypassed with a NUL byte (that getchar() accepts) */
	stack.value = strtol(stack.buf, &stack.endptr, 10);
	if (stack.endptr == stack.buf || *stack.endptr || errno == ERANGE)
		die("Invalid encoding");

	fprintf(stdout, "%ld", stack.value);
}

static void bdecode_list(void) {
	bool first = true;
	int c;

	putchar('[');

	while (1) {
		if ((c = getchar()) == EOF)
			die("I/O error");

		if (c == 'e')
			break;

		if (first)
			first = false;
		else
			putchar(',');

		if (ungetc(c, stdin) == EOF)
			die("I/O error");

		bdecode();
	}

	putchar(']');
}

static void bdecode_key_value(void) {
	bdecode_string();
	putchar(':');
	bdecode();
}

static void bdecode_dictionary(void) {
	bool first = true;
	int c;

	putchar('{');

	while (1) {
		if ((c = getchar()) == EOF)
			die("I/O error");

		if (c == 'e')
			break;

		if (first)
			first = false;
		else
			putchar(',');

		if (ungetc(c, stdin) == EOF)
			die("I/O error");

		bdecode_key_value();
	}

	putchar('}');
}

static void bdecode_string(void) {
	struct {
		bool alloc;
		int c;
		unsigned i;
		unsigned len;
		char buf[127];
		char *dst;
	} __attribute__((packed)) stack;

	stack.alloc = false;

	if (scanf("%u", &stack.len) != 1)
		die("Invalid encoding");

	stack.c = getchar();
	if (stack.c == EOF)
		die("I/O error");

	if (stack.c != ':')
		die("Invalid encoding");

	/* BUG #2: off-by-one in length check: stack.buf[] is only 127 bytes. If
	 * stack.len is exactly 128, the last input byte will overwrite the LSB of
	 * stack.dst. Doing this, the final fwrite() can be abused to leak data from
	 * the stack.
	 *
	 * Calling this function at the right stack depth and overwriting the LSB
	 * with the right value, it is possible to leak the PAC-signed return
	 * address of this function or one of the callers.
	 */
	if (stack.len > sizeof(stack.buf) + 1) {
		stack.dst = calloc(stack.len + 1, 1);
		stack.alloc = true;
	} else {
		stack.dst = stack.buf;
	}

	for (stack.i = 0; stack.i < stack.len; stack.i++) {
		if ((stack.c = getchar()) == EOF)
			die("I/O error");

		if (stack.c < ' ' || stack.c > '~')
			die("Unsupported encoding, only printable ASCII accepted");

		stack.dst[stack.i] = stack.c;
	}

	putchar('"');

	if (fwrite(stack.dst, 1, stack.len, stdout) != stack.len)
		die("I/O error");

	putchar('"');

	if (stack.alloc)
		free(stack.dst);
}

static void bdecode(void) {
	bool debug = false;
	int c;

	if (getenv("DEBUG") && !strcmp(getenv("DEBUG"), "1")) {
		/* This will never happen */
		debug = true;
	}

	if ((c = getchar()) == EOF)
		_exit(0);

	switch (c) {
		case 'i':
			bdecode_integer();
			break;

		case 'l':
			bdecode_list();
			break;

		case 'd':
			bdecode_dictionary();
			break;

		default:
			if (ungetc(c, stdin) == EOF)
				die("I/O error");

			bdecode_string();
			break;
	}

	/* GOAL: get here with broken stack frame where debug & 0x01 != 0 (yes, that
	 * is how the truth check against a `bool` gets compiled, at least with my
	 * aarch64-linux-gnu-gcc 13.2.0 on Ubuntu 24.04).
	 *
	 * When corrupting the return address in the right way we make `debug`
	 * collide with the MSB of a PAC-signed return address (which is random),
	 * therefore we have a 50% chance to pass the check anyway.
	 */
	if (debug)
		system("gdb-multiarch --pid $PPID");
}

static void bdecode_line(void) {
	bdecode();
	putchar('\n');

	int c = getchar();
	if (c == '\n')
		return;

	if (c != EOF)
		die("Invalid encoding");

	_exit(0);
}

int main(void) {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	bdecode_line();
}
