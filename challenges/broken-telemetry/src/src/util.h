#ifndef UTIL_H
#define UTIL_H

#ifndef PAGE_SIZE
// x86-64, hardcoded just for ease of use
#define PAGE_SIZE 0x1000
#endif

void perror_stdout(const char *msg);

void timestamp_to_iso_str(double ts, char *out, size_t out_size);

void *map_file(const char *path, size_t len, size_t offset);

#endif // UTIL_H
