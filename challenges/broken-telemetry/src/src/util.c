#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "util.h"

// Like perror() but prints to stdout
void perror_stdout(const char *msg) {
	if (!msg)
		printf("%m\n");
	else
		printf("%s: %m\n", msg);
}

void timestamp_to_iso_str(double ts, char *out, size_t out_size) {
	const time_t seconds = (time_t)ts;
	struct tm *tm = gmtime(&seconds);

	// YYYY-mm-dd HH:MM:SS
	strftime(out, out_size, "%Y-%m-%dT%H:%M:%S", tm);

	if (out_size > 19 + 1) {
		// .xxx
		const unsigned millis = (ts - seconds) * 1000U;
		snprintf(out + 19, out_size - 19, ".%03uZ", millis);
	}
}

void *map_file(const char *path, size_t len, size_t offset) {
	const int fd = open(path, O_RDONLY);
	if (fd == -1) {
		perror_stdout("open failed");
		return NULL;
	}

	void *data = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, offset);
	close(fd);

	if (data == MAP_FAILED) {
		perror_stdout("mmap failed");
		return NULL;
	}

	return data;
}
