#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int sv[2];

static void pin_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set)) {
		perror("sched_setaffinity");
		exit(1);
	}
}

static void *drain_queue_ref(void *unused)
{
	char byte;
	ssize_t ret;

	(void)unused;
	pin_cpu(2);
	ret = recv(sv[1], &byte, 1, 0);
	fprintf(stderr, "normal recv unexpectedly returned %zd errno=%d\n", ret,
		errno);
	return NULL;
}

static void *replace_oob(void *unused)
{
	char byte = 'B';
	ssize_t ret;

	(void)unused;
	pin_cpu(1);
	usleep(1000000);
	ret = send(sv[0], &byte, 1, MSG_OOB);
	fprintf(stderr, "replacement OOB send returned %zd errno=%d\n", ret,
		errno);
	return NULL;
}

static void *peek_oob(void *unused)
{
	char byte = 0;
	ssize_t ret;

	(void)unused;
	pin_cpu(0);
	ret = recv(sv[1], &byte, 1, MSG_OOB | MSG_PEEK);
	fprintf(stderr, "OOB peek returned %zd byte=%02x errno=%d\n", ret,
		(unsigned char)byte, errno);
	return NULL;
}

int main(void)
{
	pthread_t drain, replacer, peeker;
	char byte = 'A';
	ssize_t ret;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
		perror("socketpair");
		return 1;
	}
	if (pthread_create(&drain, NULL, drain_queue_ref, NULL))
		return 1;
	usleep(100000);
	ret = send(sv[0], &byte, 1, MSG_OOB);
	fprintf(stderr, "initial OOB send returned %zd errno=%d\n", ret, errno);
	if (ret != 1)
		return 1;
	/* Let the normal reader unlink the skb from sk_receive_queue. */
	usleep(300000);
	if (pthread_create(&replacer, NULL, replace_oob, NULL))
		return 1;
	if (pthread_create(&peeker, NULL, peek_oob, NULL))
		return 1;
	pthread_join(peeker, NULL);
	pthread_join(replacer, NULL);
	return 0;
}
