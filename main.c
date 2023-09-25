#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <stdint.h>
#include <locale.h>
#include <time.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

#ifdef TNT_1_5
/*
 * CMakeLists.txt:
 *
```
project(bench)

enable_tnt_compile_flags()

include_directories("${PROJECT_SOURCE_DIR}/../connector/c/include")

add_executable(bench main.c)
set_source_files_compile_flags("TARANTOOL" main.c)
target_link_libraries(bench tntrpl tntnet tntsql tnt)

install (TARGETS bench DESTINATION bin)
```
 */

#include <connector/c/include/tarantool/tnt.h>
#include <connector/c/include/tarantool/tnt_net.h>
#include <connector/c/include/tarantool/tnt_sql.h>
#include <connector/c/include/tarantool/tnt_iter.h>
#include <connector/c/include/tarantool/tnt_xlog.h>
#endif /* TNT_1_5 */

#define lengthof(array) (sizeof(array) / sizeof(array[0]))

#define ERROR_SYS(msg) do { perror(msg); exit(1); } while (0)
#define ERROR_FATAL(fmt, ...) do { printf(fmt "\n", ## __VA_ARGS__); exit(1); } while (0)

uint64_t
nsecs(struct timespec t0, struct timespec t1)
{
	return (t1.tv_sec * 1000000000llu + t1.tv_nsec) -
		(t0.tv_sec * 1000000000llu + t0.tv_nsec);
}

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

void tnt_io_nonblock(int fd, int set) {
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		ERROR_SYS("Couldn't get the socket flags");
	if (set)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1)
		ERROR_SYS("Couldn't set the socket flags");
}

int
bench_connect(const char *hostname, uint16_t port)
{
	/* Create the connection socket. */
	int fd = -1;
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		ERROR_SYS("Couldn't create a socket");
	/* Set socket options. */
	{
		struct timeval tmout_send = {};
		struct timeval tmout_recv = {};
		if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tmout_send, sizeof(tmout_send)) == -1)
			ERROR_SYS("Couldn't set socket send timeout");
		if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmout_recv, sizeof(tmout_recv)) == -1)
			ERROR_SYS("Couldn't set socket recv timeout");
	}
	/* Get Tarantool address. */
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};
	{
		struct addrinfo *addr_info = NULL;
		if (getaddrinfo(hostname, NULL, NULL, &addr_info) != 0)
			ERROR_SYS("Couldn't resolve the Tarantool address");
		memcpy(&addr.sin_addr,
		       (void*)&((struct sockaddr_in *)addr_info->ai_addr)->sin_addr,
		       sizeof(addr.sin_addr));
		freeaddrinfo(addr_info);
	}
	/* Connect to the Tarantool. */
	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
		ERROR_SYS("Couldn't connect to Tarantool.");
#if 0
	struct timeval tmout_connect = {
		.tv_sec = 16,
	};
	tnt_io_nonblock(fd, 1);
	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		if (errno == EINPROGRESS) {
			/** waiting for connection while handling signal events */
			const int64_t micro = 1000000;
			int64_t tmout_usec = tmout_connect.tv_sec * micro;
			/* get start connect time */
			struct timeval start_connect;
			if (gettimeofday(&start_connect, NULL) == -1)
				ERROR_SYS("Couldn't get the connection start time");
			/* set initial timer */
			struct timeval tmout;
			memcpy(&tmout, &tmout_connect, sizeof(tmout));
			while (1) {
				fd_set fds;
				FD_ZERO(&fds);
				FD_SET(fd, &fds);
				int ret = select(fd + 1, NULL, &fds, NULL, &tmout);
				if (ret == -1) {
					if (errno == EINTR || errno == EAGAIN) {
						/* get current time */
						struct timeval curr;
						if (gettimeofday(&curr, NULL) == -1)
							ERROR_SYS("Coudn't get the current time");
						/* calculate timeout last time */
						int64_t passd_usec = (curr.tv_sec - start_connect.tv_sec) * micro +
							(curr.tv_usec - start_connect.tv_usec);
						int64_t curr_tmeout = passd_usec - tmout_usec;
						if (curr_tmeout <= 0)
							ERROR_FATAL("Connection timeout.");
						tmout.tv_sec = curr_tmeout / micro;
						tmout.tv_usec = curr_tmeout % micro;
					} else {
						ERROR_SYS("Unexpected error in fselect");
					}
				} else if (ret == 0) {
					ERROR_FATAL("Connection timeout.");
				} else {
					/* we have a event on socket */
					break;
				}
			}
			/* checking error status */
			int opt = 0;
			socklen_t len = sizeof(opt);
			if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &opt, &len) == -1)
				ERROR_SYS("Couldn't get the socket error status");
			if (opt)
				ERROR_FATAL("Socket error: %s.", strerror(opt));
		} else {
			ERROR_SYS("Unexpected error in connect");
		}
	}
	/* setting block */
	tnt_io_nonblock(fd, 0);
#endif
	return fd;
}

#define WRITE_IOVEC(fd, v, v_len) do {			   \
	char buf[1024];					  \
	size_t size = 0;					 \
	for (int i = 0; i < v_len; i++) {			\
		memcpy(buf + size, v[i].iov_base, v[i].iov_len); \
		size += v[i].iov_len;			    \
	}							\
	DumpHex(buf, size);				      \
	write(fd, buf, size);				    \
} while (0)

#define READ(fd) do {			    \
	struct tnt_header reply_hdr;	     \
	read(fd, &reply_hdr, sizeof(reply_hdr)); \
	DumpHex(&reply_hdr, sizeof(reply_hdr));  \
	char *buf = calloc(1, reply_hdr.len);    \
	read(fd, buf, reply_hdr.len);	    \
	DumpHex(buf, reply_hdr.len);	     \
} while (0)

#ifdef TNT_1_5
void
bench_call_proc(int fd, const char *proc, struct tnt_tuple *args)
{
	/* encoding procedure name */
	int proc_len = strlen(proc);
	int proc_enc_size = tnt_enc_size(proc_len);
	char proc_enc[5];
	tnt_enc_write(proc_enc, proc_len);
	/* filling major header */
	struct tnt_header hdr;
	hdr.type = TNT_OP_CALL;
	hdr.len = sizeof(struct tnt_header_call) +
		  proc_enc_size + proc_len + args->size;
	if (args->size == 0)
		hdr.len += 4;
	hdr.reqid = 0;
	/* filling call header */
	struct tnt_header_call hdr_call;
	hdr_call.flags = 0;
	/* writing data to stream */
	struct iovec v[5];
	v[0].iov_base = (void *)&hdr;
	v[0].iov_len  = sizeof(struct tnt_header);
	v[1].iov_base = (void *)&hdr_call;
	v[1].iov_len  = sizeof(struct tnt_header_call);
	v[2].iov_base = proc_enc;
	v[2].iov_len  = proc_enc_size;
	v[3].iov_base = (void *)proc;
	v[3].iov_len  = proc_len;
	uint32_t argc = 0;
	if (args->size == 0) {
		v[4].iov_base = (void *)&argc;
		v[4].iov_len  = 4;
	} else {
		v[4].iov_base = args->data;
		v[4].iov_len  = args->size;
	}
	WRITE_IOVEC(fd, v, lengthof(v));
	READ(fd);
}

void
bench_iproto_insert(int fd, struct tnt_tuple *kv)
{
	/* filling major header */
	struct tnt_header hdr;
	hdr.type  = TNT_OP_INSERT;
	hdr.len = sizeof(struct tnt_header_insert) + kv->size;
	hdr.reqid = 0;
	/* filling insert header */
	struct tnt_header_insert hdr_insert;
	hdr_insert.ns = 0;
	hdr_insert.flags = 0;
	/* writing data to stream */
	struct iovec v[3];
	v[0].iov_base = (void *)&hdr;
	v[0].iov_len  = sizeof(struct tnt_header);
	v[1].iov_base = (void *)&hdr_insert;
	v[1].iov_len  = sizeof(struct tnt_header_insert);
	v[2].iov_base = kv->data;
	v[2].iov_len  = kv->size;
	WRITE_IOVEC(fd, v, lengthof(v));
	READ(fd);
}

void
bench_iptoto_select(int fd, struct tnt_tuple *kv)
{
	/* filling major header */
	struct tnt_header hdr;
	hdr.type = TNT_OP_SELECT;
	hdr.len = sizeof(struct tnt_header_select) + 4 + kv->size;
	hdr.reqid = 0;
	/* filling select header */
	struct tnt_header_select hdr_sel;
	hdr_sel.ns = 0;
	hdr_sel.index = 0;
	hdr_sel.offset = 0;
	hdr_sel.limit = 0xffffffff;
	/* key count */
	uint32_t key_count = 1;
	/* write vector */
	struct iovec v[4];
	v[0].iov_base = (void *)&hdr;
	v[0].iov_len  = sizeof(struct tnt_header);
	v[1].iov_base = (void *)&hdr_sel;
	v[1].iov_len  = sizeof(struct tnt_header_select);
	v[2].iov_base = (void *)&key_count;
	v[2].iov_len  = sizeof(key_count);
	v[3].iov_base = kv->data;
	v[3].iov_len  = kv->size;
	/* writing data to stream */
	WRITE_IOVEC(fd, v, lengthof(v));
	READ(fd);
}

void
bench_iptoto_delete(int fd, struct tnt_tuple *k)
{
	/* filling major header */
	struct tnt_header hdr;
	hdr.type  = TNT_OP_DELETE;
	hdr.len = sizeof(struct tnt_header_delete) + k->size;
	hdr.reqid = 0;
	/* filling delete header */
	struct tnt_header_delete hdr_del;
	hdr_del.ns = 0;
	hdr_del.flags = TNT_FLAG_RETURN;
	/* writing data to stream */
	struct iovec v[3];
	v[0].iov_base = (void *)&hdr;
	v[0].iov_len  = sizeof(struct tnt_header);
	v[1].iov_base = (void *)&hdr_del;
	v[1].iov_len  = sizeof(struct tnt_header_delete);
	v[2].iov_base = k->data;
	v[2].iov_len  = k->size;
	WRITE_IOVEC(fd, v, lengthof(v));
	READ(fd);
}

void
bench_iproto_ping(int fd)
{
	/* filling major header */
	struct tnt_header hdr;
	hdr.type = TNT_OP_PING;
	hdr.len = 0;
	hdr.reqid = 0;
	/* writing data to stream */
	struct iovec v[1];
	v[0].iov_base = (void*)&hdr;
	v[0].iov_len = sizeof(struct tnt_header);
	WRITE_IOVEC(fd, v, lengthof(v));
	READ(fd);
}
#endif /* TNT_1_5 */

struct timespec
bench_start()
{
	struct timespec t0;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	return t0;
}

uint64_t
bench_finish(struct timespec t0)
{
	struct timespec t1;
	clock_gettime(CLOCK_MONOTONIC, &t1);
	return nsecs(t0, t1);
}

uint64_t
bench_raw_request(int fd, size_t req_size, const char *req, size_t res_size, const char *res)
{
	char buf[res_size];
	struct timespec t0 = bench_start();
	write(fd, req, req_size);
	read(fd, buf, res_size);
	uint64_t result = bench_finish(t0);
	if (memcmp(buf, res, res_size)) {
		printf("Got:\n");
		DumpHex(buf, res_size);
		printf("Expected:\n");
		DumpHex(res, res_size);
		ERROR_FATAL("Unexpected response.");
	}
	return result;
}

char raw_req_call_bench_call[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x13, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x0A, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x63, 0x61, 0x6C, 0x6C, /* "bench_call" */
	0x00, 0x00, 0x00, 0x00, /* No tuples. */
};

char raw_res_call_bench_call[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x08, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No error. */
	0x00, 0x00, 0x00, 0x00, /* No tuples. */
};

char raw_req_call_bench_insert[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x1A, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x0C, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x69, 0x6E, 0x73, 0x65, 0x72, 0x74, /* "bench_insert" */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

char raw_res_call_bench_insert[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

char raw_req_call_bench_delete[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x1A, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x0C, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x64, 0x65, 0x6C, 0x65, 0x74, 0x65, /* "bench_delete" */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

char raw_res_call_bench_delete[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

char raw_req_call_bench_select[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x1A, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x0C, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x73, 0x65, 0x6C, 0x65, 0x63, 0x74, /* "bench_select" */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

char raw_res_call_bench_select[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

char raw_req_insert[] = {
	0x0D, 0x00, 0x00, 0x00, /* INSERT */
	0x11, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Space. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

char raw_res_insert[] = {
	0x0D, 0x00, 0x00, 0x00, /* INSERT */
	0x08, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, /* What? */
};

char raw_req_select[] = {
	0x11, 0x00, 0x00, 0x00, /* SELECT */
	0x1D, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Space. */
	0x00, 0x00, 0x00, 0x00, /* Index. */
	0x00, 0x00, 0x00, 0x00, /* Offset. */
	0xFF, 0xFF, 0xFF, 0xFF, /* Limit. */
	0x01, 0x00, 0x00, 0x00, /* Key count. */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The key. */
};

char raw_res_select[] = {
	0x11, 0x00, 0x00, 0x00, /* SELECT */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The selected tuple. */
};

char raw_req_delete[] = {
	0x15, 0x00, 0x00, 0x00, /* DELETE */
	0x11, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Space. */
	0x01, 0x00, 0x00, 0x00, /* Flags: RETURN. */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The key. */
};

char raw_res_delete[] = {
	0x15, 0x00, 0x00, 0x00, /* DELETE */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The deleted tuple. */
};

char raw_req_ping[] = {
	0x00, 0xFF, 0x00, 0x00, /* PING */
	0x00, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
};

char raw_res_ping[] = {
        0x00, 0xFF, 0x00, 0x00, /* PING */
        0x00, 0x00, 0x00, 0x00, /* Body length. */
        0x00, 0x00, 0x00, 0x00, /* Request ID. */
};

void *
raw_id_find(size_t raw_size, const char *raw)
{
	const char needle[] = {0x42, 0x42, 0x42, 0x42};
	return memmem(raw, raw_size, needle, sizeof(needle));
}

void
raw_id_update(void *id_ptr, uint32_t new_id)
{
	if (id_ptr == NULL)
		return;
	char *id_bytes = id_ptr;
	id_bytes[0] = (new_id >> 0) & 0xff;
	id_bytes[1] = (new_id >> 8) & 0xff;
	id_bytes[2] = (new_id >> 16) & 0xff;
	id_bytes[3] = (new_id >> 24) & 0xff;
}

void
raw_id_reset(void *id_ptr)
{
	raw_id_update(id_ptr, 0x42424242);
}

uint32_t
rand_id()
{
	static uint32_t state = 1;
	return state = (uint64_t)state * 48271 % 0x7fffffff;
}

int
comp_u64(const void *a, const void *b)
{
	return *(uint64_t *)a - *(uint64_t *)b;
}

double
average(size_t size, const uint64_t *data)
{
	double sum = 0.0;
	for (size_t i = 0; i < size; i++)
		sum += data[i];
	return sum / size;
}

double
median(size_t size, const uint64_t *data)
{
	if (size == 0)
		return 0;
	if (size % 2 == 1)
		return data[size / 2];
	size_t i_right = size / 2;
	size_t i_left = i_right - 1;
	return ((double)data[i_left] + (double)data[i_right]) / 2.0;
}

int
main(int argc, char **argv)
{
	int fd = bench_connect("localhost", 33013);
#if TNT_1_5
	(void)argc;
	(void)argv;
	struct tnt_tuple args;
	tnt_tuple_init(&args);
	tnt_tuple(&args, "%d", 0x42424242);
	//bench_call_proc(fd, "bench_select", &args);
	//bench_iproto_insert(fd, &args);
	//bench_iptoto_select(fd, &args);
	//bench_iptoto_delete(fd, &args);
	bench_iproto_ping(fd);
#else
	struct {
		const char *name;
		char *raw_req;
		size_t raw_req_size;
		char *raw_res;
		size_t raw_res_size;
	} whatever[] = {
#define ENTRY(name) { #name, raw_req_ ## name, sizeof(raw_req_ ## name), raw_res_ ## name, sizeof(raw_res_ ## name) }
		ENTRY(call_bench_call),
		ENTRY(call_bench_insert),
		ENTRY(call_bench_delete),
		ENTRY(call_bench_select),
		ENTRY(insert),
		ENTRY(select),
		ENTRY(delete),
		ENTRY(ping),
#undef ENTRY
	};

	const char *bench_func = argc >= 2 ? argv[1] : "call_bench_call";
	size_t bench_i = -1;

	for (size_t i = 0; i < lengthof(whatever); i++) {
		if (!strcmp(whatever[i].name, bench_func)) {
			bench_i = i;
			break;
		}
	}

	if (bench_i == -1)
		ERROR_FATAL("Couldn't find function: %s.\n", bench_func);

	uint64_t reqs = 10000;
	uint64_t *latencies_ns = calloc(1, reqs * sizeof(*latencies_ns));
	char *raw_req = whatever[bench_i].raw_req;
	char *raw_res = whatever[bench_i].raw_res;
	size_t raw_req_size = whatever[bench_i].raw_req_size;
	size_t raw_res_size = whatever[bench_i].raw_res_size;
	void *raw_req_id_ptr = raw_id_find(raw_req_size, raw_req);
	void *raw_res_id_ptr = raw_id_find(raw_res_size, raw_res);

	struct timespec t0 = bench_start();
	for (size_t i = 0; i < reqs; i++) {
		size_t id = rand_id();
		raw_id_update(raw_req_id_ptr, id);
		raw_id_update(raw_res_id_ptr, id);
		uint64_t latency_ns = bench_raw_request(fd, raw_req_size, raw_req, raw_res_size, raw_res);
		latencies_ns[i] = latency_ns;
	}
	uint64_t overall_ns = bench_finish(t0);
	double rps = (double)reqs / ((double)(overall_ns) / 1000000000.0);

	raw_id_reset(raw_req_id_ptr);
	raw_id_reset(raw_res_id_ptr);

	qsort(latencies_ns, reqs, sizeof(*latencies_ns), comp_u64);

	double avg_us = average(reqs, latencies_ns) / 1000.0;
	double med_us = median(reqs, latencies_ns) / 1000.0;
	double min_us = (double)latencies_ns[0] / 1000.0;
	double max_us = (double)latencies_ns[reqs - 1] / 1000.0;
	double p90_us = (double)latencies_ns[(size_t)((reqs - 1) * 0.9)] / 1000.0;
	double p99_us = (double)latencies_ns[(size_t)((reqs - 1) * 0.99)] / 1000.0;
	double p999_us = (double)latencies_ns[(size_t)((reqs - 1) * 0.999)] / 1000.0;

	printf("90%%: %.2f\n", p90_us);
	printf("99%%: %.2f\n", p99_us);
	printf("99.9%%: %.2f\n", p999_us);
	printf("MED: %.2f\n", med_us);
	printf("AVG: %.2f\n", avg_us);
	printf("MIN: %.2f\n", min_us);
	printf("MAX: %.2f\n", max_us);
	printf("COUNT: %lu\n", reqs);
	printf("TIME: %.2f\n", (double)overall_ns / 1000000000.0);
	printf("RPS: %.0f\n", rps);
#endif
	return 0;
}
