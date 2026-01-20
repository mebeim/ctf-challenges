#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/mman.h>

#include "patch.h"
#include "util.h"
#include "worker.h"

// Apparently musl does not define this??
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 16384
#endif

#define THREAD_STACK_N_PAGES 4
#define THREAD_STACK_SIZE    (PAGE_SIZE * THREAD_STACK_N_PAGES)

static_assert(THREAD_STACK_SIZE >= PTHREAD_STACK_MIN, "thread stack size too small");

int main(void) {
    pthread_attr_t attr;
    pthread_t th;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* Setup a custom stack via a worker POSIX thread, then delegate all the
     * work to it. This thread will also have no stack guard page.
     */
    void *const stack = mmap(NULL, THREAD_STACK_SIZE, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED)
        perror_stdout("mmap failed");

    if (pthread_attr_init(&attr) != 0)
        goto err;

    if (pthread_attr_setstack(&attr, stack, THREAD_STACK_SIZE) != 0)
        goto err;

    if (pthread_create(&th, &attr, worker, NULL) != 0)
        goto err;

    pthread_attr_destroy(&attr);
    pthread_join(th, NULL);
    return 0;

err:
    puts("system failure");
    return 1;
}
