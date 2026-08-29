#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

struct attempt {
	int epfd;
	pthread_barrier_t barrier;
};

static void pin_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set)) {
		perror("sched_setaffinity");
		exit(EXIT_FAILURE);
	}
}

static void print_credentials(void)
{
	FILE *fp;
	char line[256];

	printf("initial uid=%ld euid=%ld gid=%ld egid=%ld\n",
	       (long)getuid(), (long)geteuid(), (long)getgid(), (long)getegid());
	fp = fopen("/proc/self/status", "re");
	if (!fp)
		return;
	while (fgets(line, sizeof(line), fp)) {
		if (!strncmp(line, "CapInh:", 7) ||
		    !strncmp(line, "CapPrm:", 7) ||
		    !strncmp(line, "CapEff:", 7) ||
		    !strncmp(line, "CapAmb:", 7))
			fputs(line, stdout);
	}
	fclose(fp);
}

static void *poller(void *opaque)
{
	struct attempt *a = opaque;
	struct epoll_event event;

	pin_cpu(1);
	pthread_barrier_wait(&a->barrier);
	(void)epoll_wait(a->epfd, &event, 1, 10);
	return NULL;
}

int main(void)
{
	const uint64_t one = 1;
	uint64_t attempts = 0;
	struct timespec start, now;

	setbuf(stdout, NULL);
	if (getuid() == 0) {
		fprintf(stderr, "run as an ordinary non-root user\n");
		return EXIT_FAILURE;
	}
	print_credentials();
	pin_cpu(0);
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (;;) {
		struct epoll_event event = {
			.events = EPOLLIN,
			.data.u64 = 0x5d4cb6b4409edfd1ULL,
		};
		struct attempt a;
		pthread_t thread;
		int target;

		a.epfd = epoll_create1(EPOLL_CLOEXEC);
		target = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		if (a.epfd < 0 || target < 0) {
			perror("epoll_create1/eventfd");
			return EXIT_FAILURE;
		}
		if (epoll_ctl(a.epfd, EPOLL_CTL_ADD, target, &event)) {
			perror("epoll_ctl");
			return EXIT_FAILURE;
		}
		if (write(target, &one, sizeof(one)) != sizeof(one)) {
			perror("eventfd write");
			return EXIT_FAILURE;
		}

		pthread_barrier_init(&a.barrier, NULL, 2);
		if (pthread_create(&thread, NULL, poller, &a)) {
			perror("pthread_create");
			return EXIT_FAILURE;
		}
		pthread_barrier_wait(&a.barrier);

		/* Sweep the close relative to the ready-list scan. */
		if ((attempts & 0x3f) != 0) {
			struct timespec delay = {
				.tv_nsec = (long)(attempts & 0x3f) * 50,
			};
			nanosleep(&delay, NULL);
		}
		close(target);
		pthread_join(thread, NULL);
		pthread_barrier_destroy(&a.barrier);
		close(a.epfd);

		attempts++;
		if (!(attempts % 10000))
			printf("attempts=%lu\n", (unsigned long)attempts);
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec >= 120)
			break;
	}

	printf("completed %lu attempts; inspect serial/GDB output\n",
	       (unsigned long)attempts);
	return 0;
}
