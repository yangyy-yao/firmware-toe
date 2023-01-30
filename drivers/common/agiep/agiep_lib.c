#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "agiep_lib.h"

#define PAGE_SIZE   (sysconf(_SC_PAGESIZE))
#define PAGE_MASK   (~(PAGE_SIZE - 1))

void* agiep_mmap(void* start, size_t length, int prot, int flags,
        off_t offset, void **map_addr, int *retfd)
{
        off_t newoff = 0;
        off_t diff = 0;
        off_t mask = PAGE_MASK;
        void *p = NULL;
        int fd = 0;

        fd = open("/dev/mem", O_RDWR|O_SYNC);
        if (fd == -1) {
                printf("open \"/dev/mem\" ERROR \n");
                return NULL;
        }

        newoff = offset & mask;
        if (newoff != offset)
                diff = offset - newoff;

        p = mmap(start, length, prot, flags, fd, newoff);
        if (p == NULL) {
                printf("agiep_mmap %lX-%lX ERROR \n", newoff, offset);
                return NULL;
        }

        if (map_addr)
                *map_addr = (void *)((uint64_t)p + diff);

        if (retfd)
                *retfd = fd;

        return p;
}
int agiep_ummap(void *p, size_t length, int retfd)
{
	munmap(p, length);
	return close(retfd);
}