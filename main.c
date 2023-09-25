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

#define WRITE_IOVEC(fd, v, v_len) do {                           \
	char buf[1024];                                          \
	size_t size = 0;\
	for (int i = 0; i < v_len; i++) {\
		memcpy(buf + size, v[i].iov_base, v[i].iov_len);\
		size += v[i].iov_len;\
	}\
	DumpHex(buf, size);\
	write(fd, buf, size);\
} while (0)

#define READ(fd) do { \
	char mp_uint32[9]; \
	read(fd, &mp_uint32, sizeof(mp_uint32)); \
	DumpHex(&mp_uint32, sizeof(mp_uint32)); \
	const char *mp_uint32_end = mp_uint32; \
	uint32_t bufsize = mp_decode_uint(&mp_uint32_end); \
	int bufsize_size = mp_uint32_end - mp_uint32; \
	bufsize -= sizeof(mp_uint32) - bufsize_size; \
	char *buf = calloc(1, bufsize); \
	read(fd, buf, bufsize); \
	DumpHex(buf, bufsize); \
} while (0)

enum tnt_header_key_t {
        TNT_CODE      = 0x00,
        TNT_SYNC      = 0x01,
        TNT_SERVER_ID = 0x02,
        TNT_LSN       = 0x03,
        TNT_TIMESTAMP = 0x04,
        TNT_SCHEMA_ID = 0x05
};

enum tnt_body_key_t {
        TNT_SPACE = 0x10,
        TNT_INDEX = 0x11,
        TNT_LIMIT = 0x12,
        TNT_OFFSET = 0x13,
        TNT_ITERATOR = 0x14,
        TNT_INDEX_BASE = 0x15,
        TNT_KEY = 0x20,
        TNT_TUPLE = 0x21,
        TNT_FUNCTION = 0x22,
        TNT_USERNAME = 0x23,
        TNT_SERVER_UUID = 0x24,
        TNT_CLUSTER_UUID = 0x25,
        TNT_VCLOCK = 0x26,
        TNT_EXPRESSION = 0x27,
        TNT_OPS = 0x28,
        TNT_SQL_TEXT = 0x40,
        TNT_SQL_BIND = 0x41,
};

enum tnt_response_type_t {
        TNT_OK    = 0x00,
        TNT_CHUNK = 0x80,
};

enum tnt_response_key_t {
        TNT_DATA = 0x30,
        TNT_ERROR = 0x31,
        TNT_METADATA = 0x32,
        TNT_SQL_INFO = 0x42,
};

enum tnt_request_t {
        TNT_OP_SELECT    = 1,
        TNT_OP_INSERT    = 2,
        TNT_OP_REPLACE   = 3,
        TNT_OP_UPDATE    = 4,
        TNT_OP_DELETE    = 5,
        TNT_OP_CALL_16   = 6,
        TNT_OP_AUTH      = 7,
        TNT_OP_EVAL      = 8,
        TNT_OP_UPSERT    = 9,
        TNT_OP_CALL      = 10,
        TNT_OP_EXECUTE   = 11,
        TNT_OP_PING      = 64,
        TNT_OP_JOIN      = 65,
        TNT_OP_SUBSCRIBE = 66
};

#include "msgpuck/msgpuck.h"

struct tnt_iheader {
        char header[25];
        char *end;
};

static inline int
encode_header(struct tnt_iheader *hdr, uint32_t code, uint64_t sync)
{
        memset(hdr, 0, sizeof(struct tnt_iheader));
        char *h = mp_encode_map(hdr->header, 2);
        h = mp_encode_uint(h, TNT_CODE);
        h = mp_encode_uint(h, code);
        h = mp_encode_uint(h, TNT_SYNC);
        h = mp_encode_uint(h, sync);
        hdr->end = h;
        return 0;
}

static inline size_t
mp_sizeof_luint32(uint64_t num) {
        if (num <= UINT32_MAX)
                return 1 + sizeof(uint32_t);
        return 1 + sizeof(uint64_t);
}

static inline char *
mp_encode_luint32(char *data, uint64_t num) {
        if (num <= UINT32_MAX) {
                data = mp_store_u8(data, 0xce);
                return mp_store_u32(data, num);
        }
        data = mp_store_u8(data, 0xcf);
        return mp_store_u64(data, num);
}

void
bench_iproto_call(int fd, const char *proc, uint32_t key)
{
	size_t proc_len = strlen(proc);
      	char args_data[6];
	size_t args_size = sizeof(args_data);
	{
		char *data = args_data;
		data = mp_encode_array(data, 1);
		data = mp_encode_uint(data, key);
		assert(data - args_data == sizeof(args_data));
	}

	struct tnt_iheader hdr;
        struct iovec v[6]; int v_sz = 6;
        char *data = NULL, *body_start = NULL;
        encode_header(&hdr, TNT_OP_CALL_16, 0);
        v[1].iov_base = (void *)hdr.header;
        v[1].iov_len  = hdr.end - hdr.header;
        char body[64]; body_start = body; data = body;

        data = mp_encode_map(data, 2);
        data = mp_encode_uint(data, TNT_FUNCTION);
        data = mp_encode_strl(data, proc_len);
        v[2].iov_base = body_start;
        v[2].iov_len  = data - body_start;
        v[3].iov_base = (void *)proc;
        v[3].iov_len  = proc_len;
        body_start = data;
        data = mp_encode_uint(data, TNT_TUPLE);
        v[4].iov_base = body_start;
        v[4].iov_len  = data - body_start;
        v[5].iov_base = args_data;
        v[5].iov_len  = args_size;

        size_t package_len = 0;
        for (int i = 1; i < v_sz; ++i)
                package_len += v[i].iov_len;
        char len_prefix[9];
        char *len_end = mp_encode_luint32(len_prefix, package_len);
        v[0].iov_base = len_prefix;
        v[0].iov_len = len_end - len_prefix;
	WRITE_IOVEC(fd, v, v_sz);
	READ(fd);
}

void
bench_iproto_store(int fd, uint32_t key, int op)
{
	char tuple_data[6];
	size_t tuple_size = sizeof(tuple_data);
	{
		char *data = tuple_data;
		data = mp_encode_array(data, 1);
		data = mp_encode_uint(data, key);
		assert(data - tuple_data == sizeof(tuple_data));
	}

	struct tnt_iheader hdr;
        struct iovec v[4]; int v_sz = 4;
        char *data = NULL;
        encode_header(&hdr, op, 0);
        v[1].iov_base = (void *)hdr.header;
        v[1].iov_len  = hdr.end - hdr.header;
        char body[64]; data = body;

        data = mp_encode_map(data, 2);
        data = mp_encode_uint(data, TNT_SPACE);
        data = mp_encode_uint(data, 512);
        data = mp_encode_uint(data, TNT_TUPLE);
        v[2].iov_base = body;
        v[2].iov_len  = data - body;
        v[3].iov_base = tuple_data;
        v[3].iov_len  = tuple_size;

        size_t package_len = 0;
        for (int i = 1; i < v_sz; ++i)
                package_len += v[i].iov_len;
        char len_prefix[9];
        char *len_end = mp_encode_luint32(len_prefix, package_len);
        v[0].iov_base = len_prefix;
        v[0].iov_len = len_end - len_prefix;
	WRITE_IOVEC(fd, v, v_sz);
	READ(fd);
}

void
bench_iproto_insert(int fd, uint32_t key)
{
	return bench_iproto_store(fd, key, TNT_OP_INSERT);
}

void
bench_iproto_replace(int fd, uint32_t key)
{
	return bench_iproto_store(fd, key, TNT_OP_REPLACE);
}

void
bench_iproto_select(int fd, uint32_t key)
{
	char key_data[6];
	size_t key_size = sizeof(key_data);
	{
		char *data = key_data;
		data = mp_encode_array(data, 1);
		data = mp_encode_uint(data, key);
		assert(data - key_data == sizeof(key_data));
	}
	struct tnt_iheader hdr;
        struct iovec v[4]; int v_sz = 4;
        char *data = NULL;
        encode_header(&hdr, TNT_OP_SELECT, 0);
        v[1].iov_base = (void *)hdr.header;
        v[1].iov_len  = hdr.end - hdr.header;
        char body[64]; data = body;

        data = mp_encode_map(data, 6);
        data = mp_encode_uint(data, TNT_SPACE);
        data = mp_encode_uint(data, 512);
        data = mp_encode_uint(data, TNT_INDEX);
        data = mp_encode_uint(data, 0);
        data = mp_encode_uint(data, TNT_LIMIT);
        data = mp_encode_uint(data, 0xffffffff);
        data = mp_encode_uint(data, TNT_OFFSET);
        data = mp_encode_uint(data, 0);
        data = mp_encode_uint(data, TNT_ITERATOR);
        data = mp_encode_uint(data, 0);
        data = mp_encode_uint(data, TNT_KEY);
        v[2].iov_base = body;
        v[2].iov_len  = data - body;
        v[3].iov_base = key_data;
        v[3].iov_len  = key_size;

        size_t package_len = 0;
        for (int i = 1; i < v_sz; ++i)
                package_len += v[i].iov_len;
        char len_prefix[9];
        char *len_end = mp_encode_luint32(len_prefix, package_len);
        v[0].iov_base = len_prefix;
        v[0].iov_len = len_end - len_prefix;
	WRITE_IOVEC(fd, v, v_sz);
	READ(fd);
}

void
bench_iproto_delete(int fd, uint32_t key)
{
	char key_data[6];
	size_t key_size = sizeof(key_data);
	{
		char *data = key_data;
		data = mp_encode_array(data, 1);
		data = mp_encode_uint(data, key);
		assert(data - key_data == sizeof(key_data));
	}
	struct tnt_iheader hdr;
        struct iovec v[4]; int v_sz = 4;
        char *data = NULL;
        encode_header(&hdr, TNT_OP_DELETE, 0);
        v[1].iov_base = (void *)hdr.header;
        v[1].iov_len  = hdr.end - hdr.header;
        char body[64]; data = body;

        data = mp_encode_map(data, 3);
        data = mp_encode_uint(data, TNT_SPACE);
        data = mp_encode_uint(data, 512);
        data = mp_encode_uint(data, TNT_INDEX);
        data = mp_encode_uint(data, 0);
        data = mp_encode_uint(data, TNT_KEY);
        v[2].iov_base = body;
        v[2].iov_len  = data - body;
        v[3].iov_base = key_data;
        v[3].iov_len  = key_size;

        size_t package_len = 0;
        for (int i = 1; i < v_sz; ++i)
                package_len += v[i].iov_len;
        char len_prefix[9];
        char *len_end = mp_encode_luint32(len_prefix, package_len);
        v[0].iov_base = len_prefix;
        v[0].iov_len = len_end - len_prefix;
	WRITE_IOVEC(fd, v, v_sz);
        READ(fd);
}

void
bench_iproto_ping(int fd)
{
	struct tnt_iheader hdr;
        struct iovec v[3]; int v_sz = 3;
        char *data = NULL;
        encode_header(&hdr, TNT_OP_PING, 0);
        v[1].iov_base = (void *)hdr.header;
        v[1].iov_len  = hdr.end - hdr.header;
        char body[2]; data = body;

        data = mp_encode_map(data, 0);
        v[2].iov_base = body;
        v[2].iov_len  = data - body;

        size_t package_len = 0;
        for (int i = 1; i < v_sz; ++i)
                package_len += v[i].iov_len;
        char len_prefix[9];
        char *len_end = mp_encode_luint32(len_prefix, package_len);
        v[0].iov_base = len_prefix;
        v[0].iov_len = len_end - len_prefix;
        WRITE_IOVEC(fd, v, v_sz);
	READ(fd);
}

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

char tt_1_5_raw_req_call_bench_call[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x13, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x0A, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x63, 0x61, 0x6C, 0x6C, /* "bench_call" */
	0x00, 0x00, 0x00, 0x00, /* No tuples. */
};

char tt_1_5_raw_res_call_bench_call[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x08, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No error. */
	0x00, 0x00, 0x00, 0x00, /* No tuples. */
};

char tt_1_5_raw_req_call_bench_insert[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x1A, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x0C, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x69, 0x6E, 0x73, 0x65, 0x72, 0x74, /* "bench_insert" */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

char tt_1_5_raw_res_call_bench_insert[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

char tt_1_5_raw_req_call_bench_delete[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x1A, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x0C, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x64, 0x65, 0x6C, 0x65, 0x74, 0x65, /* "bench_delete" */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

char tt_1_5_raw_res_call_bench_delete[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

char tt_1_5_raw_req_call_bench_select[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x1A, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x0C, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x73, 0x65, 0x6C, 0x65, 0x63, 0x74, /* "bench_select" */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

char tt_1_5_raw_res_call_bench_select[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

char tt_1_5_raw_req_insert[] = {
	0x0D, 0x00, 0x00, 0x00, /* INSERT */
	0x11, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Space. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

char tt_1_5_raw_res_insert[] = {
	0x0D, 0x00, 0x00, 0x00, /* INSERT */
	0x08, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, /* What? */
};

char tt_1_5_raw_req_select[] = {
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

char tt_1_5_raw_res_select[] = {
	0x11, 0x00, 0x00, 0x00, /* SELECT */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The selected tuple. */
};

char tt_1_5_raw_req_delete[] = {
	0x15, 0x00, 0x00, 0x00, /* DELETE */
	0x11, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Space. */
	0x01, 0x00, 0x00, 0x00, /* Flags: RETURN. */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The key. */
};

char tt_1_5_raw_res_delete[] = {
	0x15, 0x00, 0x00, 0x00, /* DELETE */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The deleted tuple. */
};

char tt_1_5_raw_req_ping[] = {
	0x00, 0xFF, 0x00, 0x00, /* PING */
	0x00, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
};

char tt_1_5_raw_res_ping[] = {
        0x00, 0xFF, 0x00, 0x00, /* PING */
        0x00, 0x00, 0x00, 0x00, /* Body length. */
        0x00, 0x00, 0x00, 0x00, /* Request ID. */
};

char tt_last_raw_req_ping[] = {
	0xCE, 0x00, 0x00, 0x00, 0x06, /* Size. */
	0x82,                         /* Header. */
	0x00, 0x40,                   /* IPROTO_REQUEST_TYPE: IPROTO_PING */
	0x01, 0x00,                   /* IPROTO_SYNC: 0 */
	0x80,                         /* Body. */
};

char tt_last_raw_res_ping[] = {
	0xCE, 0x00, 0x00, 0x00, 0x18,                               /* Size. */
	0x83,                                                       /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,                         /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,                         /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x80,                                                       /* Body. */
};

char tt_last_raw_req_insert[] = {
	0xCE, 0x00, 0x00, 0x00, 0x11,             /* Size. */
	0x82,                                     /* Header. */
	0x00, 0x02,                               /* IPROTO_REQUEST_TYPE: IPROTO_INSERT */
	0x01, 0x00,                               /* IPROTO_SYNC: 0 */
	0x82,                                     /* Body. */
	0x10, 0xCD, 0x02, 0x00,                   /* IPROTO_SPACE_ID: 512 */
	0x21, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42, /* IPROTO_TUPLE: [0x42424242] */
};

char tt_last_raw_res_insert[] = {
	0xCE, 0x00, 0x00, 0x00, 0x24,                               /* Size. */
	0x83,                                                       /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,                         /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,                         /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,                                                       /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x01,                         /* IPROTO_DATA: Array(1), */
	0x91, 0xCE, 0x42, 0x42, 0x42, 0x42,                         /* the inserted tuple. */
};

char tt_last_raw_req_replace[] = {
	0xCE, 0x00, 0x00, 0x00, 0x11,             /* Size. */
	0x82,                                     /* Header. */
	0x00, 0x03,                               /* IPROTO_REQUEST_TYPE: IPROTO_REPLACE */
	0x01, 0x00,                               /* IPROTO_SYNC: 0 */
	0x82,                                     /* Body. */
	0x10, 0xCD, 0x02, 0x00,                   /* IPROTO_SPACE_ID: 512 */
	0x21, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42, /* IPROTO_TUPLE: [0x42424242] */
};

char tt_last_raw_res_replace[] = {
	0xCE, 0x00, 0x00, 0x00, 0x24,                               /* Size. */
	0x83,                                                       /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,                         /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,                         /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,                                                       /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x01,                         /* IPROTO_DATA: Array(1), */
	0x91, 0xCE, 0x42, 0x42, 0x42, 0x42,                         /* [0x42424242]. */
};

char tt_last_raw_req_select[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1D,		  /* Size. */
	0x82,					  /* Header. */
	0x00, 0x01,				  /* IPROTO_REQUEST_TYPE: IPROTO_SELECT */
	0x01, 0x00,				  /* IPROTO_SYNC: 0 */
	0x86,					  /* Body. */
	0x10, 0xCD, 0x02, 0x00,			  /* IPROTO_SPACE_ID: 512 */
	0x11, 0x00,				  /* IPROTO_INDEX_ID: 0 */
	0x12, 0xCE, 0xFF, 0xFF, 0xFF, 0xFF,	  /* IPROTO_LIMIT: 0xffffffff */
	0x13, 0x00,				  /* IPROTO_OFFSET: 0 */
	0x14, 0x00,				  /* IPROTO_ITERATOR: EQ */
	0x20, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42, /* IPROTO_KEY: [0x42424242]. */
};

char tt_last_raw_res_select[] = {
	0xCE, 0x00, 0x00, 0x00, 0x24,   			    /* Size. */
	0x83,							    /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,			    /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,							    /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x01,			    /* IPROTO_DATA: Array(1), */
	0x91, 0xCE, 0x42, 0x42, 0x42, 0x42,			    /* [0x42424242]. */
};

char tt_last_raw_req_delete[] = {
	0xCE, 0x00, 0x00, 0x00, 0x13,		  /* Size. */
	0x82,					  /* Header. */
	0x00, 0x05,				  /* IPROTO_REQUEST_TYPE: IPROTO_DELETE */
	0x01, 0x00,				  /* IPROTO_SYNC: 0 */
	0x83,					  /* Body. */
	0x10, 0xCD, 0x02, 0x00,			  /* IPROTO_SPACE_ID: 512 */
	0x11, 0x00,				  /* IPROTO_INDEX_ID: 0 */
	0x20, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42, /* IPROTO_KEY: [0x42424242]. */
};

char tt_last_raw_res_delete[] = {
	0xCE, 0x00, 0x00, 0x00, 0x24,				    /* Size. */
	0x83,							    /* Header.*/
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,			    /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,							    /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x01,			    /* IPROTO_DATA: Array(1), */
	0x91, 0xCE, 0x42, 0x42, 0x42, 0x42,			    /* [0x42424242]. */
};

char tt_last_raw_req_call_bench_call[] = {
	0xCE, 0x00, 0x00, 0x00, 0x14,						/* Size. */
	0x82,									/* Header. */
	0x00, 0x06,								/* IPROTO_REQUEST_TYPE: IPROTO_CALL_16*/
	0x01, 0x00,								/* IPROTO_SYNC: 0 */
	0x82,									/* Body. */
	0x22, 0xAA, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x63, 0x61, 0x6C, 0x6C, /* IPROTO_FUNCTION_NAME: "bench_call" */
	0x21, 0x90,								/* IPROTO_TUPLE: [] */
};

char tt_last_raw_res_call_bench_call[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1E,				    /* Size. */
	0x83,							    /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,			    /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,							    /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_DATA: Array(0).*/
};

char tt_last_raw_req_call_bench_insert[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1B,							    /* Size. */
	0x82,										    /* Header. */
	0x00, 0x06,									    /* IPROTO_REQUEST_TYPE: IPROTO_CALL_16*/
	0x01, 0x00,									    /* IPROTO_SYNC: 0 */
	0x82,										    /* Body. */
	0x22, 0xAC, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x69, 0x6E, 0x73, 0x65, 0x72, 0x74, /* IPROTO_FUNCTION_NAME: "bench_insert" */
	0x21, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42					    /* IPROTO_TUPLE: [0x42424242] */
};

char tt_last_raw_res_call_bench_insert[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1E,				    /* Size. */
	0x83,							    /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,			    /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,							    /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_DATA: Array(0), */
};

char tt_last_raw_req_call_bench_delete[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1B,							    /* Size. */
	0x82,										    /* Header. */
	0x00, 0x06,									    /* IPROTO_REQUEST_TYPE: IPROTO_CALL_16*/
	0x01, 0x00,									    /* IPROTO_SYNC: 0 */
	0x82,										    /* Body. */
	0x22, 0xAC, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x64, 0x65, 0x6C, 0x65, 0x74, 0x65, /* IPROTO_FUNCTION_NAME: "bench_delete" */
	0x21, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42					    /* IPROTO_TUPLE: [0x42424242] */
};

char tt_last_raw_res_call_bench_delete[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1E,				    /* Size. */
	0x83,							    /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,			    /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,							    /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_DATA: Array(0), */
};

char tt_last_raw_req_call_bench_select[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1B,							    /* Size. */
	0x82,										    /* Header. */
	0x00, 0x06,									    /* IPROTO_REQUEST_TYPE: IPROTO_CALL_16*/
	0x01, 0x00,									    /* IPROTO_SYNC: 0 */
	0x82,										    /* Body. */
	0x22, 0xAC, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x64, 0x65, 0x6C, 0x65, 0x74, 0x65, /* IPROTO_FUNCTION_NAME: "bench_select" */
	0x21, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42					    /* IPROTO_TUPLE: [0x42424242] */
};

char tt_last_raw_res_call_bench_select[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1E,				    /* Size. */
	0x83,							    /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,			    /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,							    /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_DATA: Array(0), */
};

char tt_last_raw_req_call_bench_replace[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1C,							          /* Size. */
	0x82,										          /* Header. */
	0x00, 0x06,									          /* IPROTO_REQUEST_TYPE: IPROTO_CALL_16*/
	0x01, 0x00,									          /* IPROTO_SYNC: 0 */
	0x82,											  /* Body. */
	0x22, 0xAD, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x72, 0x65, 0x70, 0x6C, 0x61, 0x63, 0x65, /* IPROTO_FUNCTION_NAME: "bench_replace" */
	0x21, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42					          /* IPROTO_TUPLE: [0x42424242] */
};

char tt_last_raw_res_call_bench_replace[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1E,				    /* Size. */
	0x83,							    /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,			    /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,							    /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_DATA: Array(0), */
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
	const char *host = "localhost";
	uint16_t port = 3301;
	int fd = bench_connect(host, port);
	if (port == 3301) {
		/* Tarantool 1.6+. */
		char greeting[128];
		read(fd, greeting, sizeof(greeting));
		printf("%.*s\n", sizeof(greeting), greeting);
		bench_iproto_call(fd, "bench_replace", 0x42424242);
		printf("\n");
		bench_iproto_call(fd, "bench_delete", 0x42424242);
		printf("\n");
		bench_iproto_call(fd, "bench_insert", 0x42424242);
		printf("\n");
		bench_iproto_call(fd, "bench_select", 0x42424242);
	}
	struct Data {
		const char *name;
		char *raw_req;
		size_t raw_req_size;
		char *raw_res;
		size_t raw_res_size;
	};
	
	struct Data data_tt_1_5[] = {
#define ENTRY(name) { #name, tt_1_5_raw_req_ ## name, sizeof(tt_1_5_raw_req_ ## name), tt_1_5_raw_res_ ## name, sizeof(tt_1_5_raw_res_ ## name) }
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

	struct Data data_tt_last[] = {
#define ENTRY(name) { #name, tt_last_raw_req_ ## name, sizeof(tt_last_raw_req_ ## name), tt_last_raw_res_ ## name, sizeof(tt_last_raw_res_ ## name) }
		ENTRY(call_bench_call),
		ENTRY(call_bench_insert),
		ENTRY(call_bench_delete),
		ENTRY(call_bench_select),
		ENTRY(call_bench_replace),
		ENTRY(ping),
		ENTRY(insert),
		ENTRY(replace),
		ENTRY(select),
		ENTRY(delete),
#undef ENTRY
	};

	const char *bench_func = argc >= 2 ? argv[1] : "call_bench_call";
	struct Data *datas = port == 3301 ? data_tt_last : data_tt_1_5;
	size_t data_count = port == 3301 ? lengthof(data_tt_last) : lengthof(data_tt_1_5);
	size_t data_i = -1;

	for (size_t i = 0; i < data_count; i++) {
		if (!strcmp(datas[i].name, bench_func)) {
			data_i = i;
			break;
		}
	}

	if (data_i == -1)
		ERROR_FATAL("Couldn't find function: %s.\n", bench_func);

	struct Data data = datas[data_i];

	uint64_t reqs = 10000;
	uint64_t *latencies_ns = calloc(1, reqs * sizeof(*latencies_ns));
	char *raw_req = data.raw_req;
	char *raw_res = data.raw_res;
	size_t raw_req_size = data.raw_req_size;
	size_t raw_res_size = data.raw_res_size;
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
	return 0;
}
