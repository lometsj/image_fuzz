#include "kcov.h"



struct kcov *kcov_new(void)
{
	int fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (fd == -1) {
		printf("open(/sys/kernel/debug/kcov)");
	}

	/* Setup trace mode and trace size. */
	int r = ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE);
	if (r != 0) {
		printf("ioctl(KCOV_INIT_TRACE)");
	}

	/* Mmap buffer shared between kernel- and user-space. */
	unsigned long *cover = (unsigned long *)mmap(
		NULL, COVER_SIZE * sizeof(unsigned long),
		PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	if ((void *)cover == MAP_FAILED) {
		printf("mmap(/sys/kernel/debug/kcov)");
	}
	struct kcov *kcov = calloc(1, sizeof(struct kcov));
	kcov->fd = fd;
	kcov->cover = cover;
	return kcov;
}

void kcov_enable(struct kcov *kcov)
{
	/* reset counter */
	__atomic_store_n(&kcov->cover[0], 0, __ATOMIC_RELAXED);

	int r = ioctl(kcov->fd, KCOV_ENABLE, KCOV_TRACE_PC);
	if (r != 0) {
		printf("ioctl(KCOV_ENABLE)");
	}

	/* Reset coverage. */
	__atomic_store_n(&kcov->cover[0], 0, __ATOMIC_RELAXED);
	__sync_synchronize();
}

void kcov_reset(struct kcov *kcov){
	__atomic_store_n(&kcov->cover[0], 0, __ATOMIC_RELAXED);
	__sync_synchronize();
}


int kcov_collect(struct kcov *kcov){
	/* Stop counter */
	__sync_synchronize();

	return __atomic_load_n(&kcov->cover[0], __ATOMIC_RELAXED);
}

int kcov_disable(struct kcov *kcov)
{
	/* Stop actual couting. */
	int r = ioctl(kcov->fd, KCOV_DISABLE, 0);
	if (r != 0) {
		printf("ioctl(KCOV_DISABLE)");
	}
	return r;
}

void kcov_free(struct kcov *kcov)
{
	close(kcov->fd);
	kcov->fd = -1;
	munmap(kcov->cover, COVER_SIZE * sizeof(unsigned long));
	kcov->cover = MAP_FAILED;
}

uint64_t *kcov_cover(struct kcov *kcov) { return kcov->cover; }