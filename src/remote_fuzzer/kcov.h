#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>


#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)
#define COVER_SIZE (64 << 10)

#define KCOV_TRACE_PC 0
#define KCOV_TRACE_CMP 1

struct kcov {
	int fd;
	uint64_t *cover;
};



struct kcov *kcov_new(void);
void kcov_enable(struct kcov *kcov);
void kcov_enable(struct kcov *kcov);
int kcov_disable(struct kcov *kcov);
void kcov_free(struct kcov *kcov);
uint64_t *kcov_cover(struct kcov *kcov);
int kcov_collect(struct kcov *kcov);
