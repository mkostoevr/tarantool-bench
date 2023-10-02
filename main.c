#define _GNU_SOURCE

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <netdb.h>
#include <unistd.h>

#define lengthof(array) (sizeof(array) / sizeof(array[0]))

#define ERROR_SYS(msg) do { perror(msg); exit(1); } while (0)
#define ERROR_FATAL(fmt, ...) do { printf(fmt "\n", ## __VA_ARGS__); exit(1); } while (0)
#define BUG_ON(x) do { if (x) ERROR_FATAL("Bug at %s:%d: %s\n", __FILE__, __LINE__, #x); } while (0)

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
	return fd;
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
get_unsigned(char *buf, int bytes)
{
	uint64_t result = 0;
	for (int i = 0; i < bytes; i++)
		result |= buf[i] >> (((bytes - 1) - i) * 8);
	return result;
}

uint64_t
get_uint64(char *buf)
{
	return get_unsigned(buf, 8);
}

uint32_t
get_uint32(char *buf)
{
	return get_unsigned(buf, 4);
}

void
bench_raw_request_expect(int fd, size_t req_size, const unsigned char *req, size_t *res_size, unsigned char **res)
{
	unsigned char data_size_and_possibly_data[9]; /* Size of uint64 encoded in msgpack. */
	size_t data_size = 0; /* Size of packet data excluding the first msgpack field, which encodes the size. */
	size_t data_size_size = 0; /* Size of msgpack containing data size. */
	write(fd, req, req_size);
	read(fd, data_size_and_possibly_data, sizeof(data_size_and_possibly_data));
	if (data_size_and_possibly_data[0] == 0xce) {
		data_size = get_uint32(&data_size_and_possibly_data[1]);
		data_size_size = 5;
	} else if (data_size_and_possibly_data[0] == 0xcf) {
		data_size = get_uint64(&data_size_and_possibly_data[1]);
		data_size_size = 9;
	} else {
		ERROR_FATAL("Unexpected packet data_size encoding: %02x\n", data_size_and_possibly_data[0]);
	}
	size_t data_bytes_read = sizeof(data_size_and_possibly_data) - data_size_size;
	size_t data_bytes_remained = data_size - (sizeof(data_size_and_possibly_data) - data_size_size);
	unsigned char *result = calloc(1, data_size + data_size_size);
	memcpy(result, data_size_and_possibly_data, sizeof(data_size_and_possibly_data));
	read(fd, result + sizeof(data_size_and_possibly_data), data_bytes_remained);
	*res_size = data_size + data_size_size;
	*res = result;
}

uint64_t
bench_raw_request(int fd, size_t req_size, const unsigned char *req, size_t res_size, const unsigned char *res)
{
	char buf[res_size];
	struct timespec t0 = bench_start();
	write(fd, req, req_size);
	read(fd, buf, res_size);
	uint64_t result = bench_finish(t0);
	if (res_size > 27 && res[27] == 0x34)
		buf[27] = 0x34;
	if (memcmp(buf, res, res_size)) {
		printf("Got:\n");
		DumpHex(buf, res_size);
		printf("Expected:\n");
		DumpHex(res, res_size);
		ERROR_FATAL("Unexpected response.");
	}
	return result;
}

unsigned char tt_1_5_raw_req_call_bench_call[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x13, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x0A, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x63, 0x61, 0x6C, 0x6C, /* "bench_call" */
	0x00, 0x00, 0x00, 0x00, /* No tuples. */
};

unsigned char tt_1_5_raw_res_call_bench_call[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x08, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No error. */
	0x00, 0x00, 0x00, 0x00, /* No tuples. */
};

unsigned char tt_1_5_raw_req_call_bench_insert[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x1A, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x0C, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x69, 0x6E, 0x73, 0x65, 0x72, 0x74, /* "bench_insert" */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

unsigned char tt_1_5_raw_res_call_bench_insert[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

unsigned char tt_1_5_raw_req_call_bench_delete[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x1A, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x0C, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x64, 0x65, 0x6C, 0x65, 0x74, 0x65, /* "bench_delete" */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

unsigned char tt_1_5_raw_res_call_bench_delete[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

unsigned char tt_1_5_raw_req_call_bench_select[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x1A, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x0C, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x73, 0x65, 0x6C, 0x65, 0x63, 0x74, /* "bench_select" */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

unsigned char tt_1_5_raw_res_call_bench_select[] = {
	0x16, 0x00, 0x00, 0x00, /* CALL */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

unsigned char tt_1_5_raw_req_insert[] = {
	0x0D, 0x00, 0x00, 0x00, /* INSERT */
	0x11, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Space. */
	0x00, 0x00, 0x00, 0x00, /* Flags. */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The tuple. */
};

unsigned char tt_1_5_raw_res_insert[] = {
	0x0D, 0x00, 0x00, 0x00, /* INSERT */
	0x08, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, /* What? */
};

unsigned char tt_1_5_raw_req_select[] = {
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

unsigned char tt_1_5_raw_res_select[] = {
	0x11, 0x00, 0x00, 0x00, /* SELECT */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The selected tuple. */
};

unsigned char tt_1_5_raw_req_delete[] = {
	0x15, 0x00, 0x00, 0x00, /* DELETE */
	0x11, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* Space. */
	0x01, 0x00, 0x00, 0x00, /* Flags: RETURN. */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The key. */
};

unsigned char tt_1_5_raw_res_delete[] = {
	0x15, 0x00, 0x00, 0x00, /* DELETE */
	0x15, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
	0x00, 0x00, 0x00, 0x00, /* No errors. */
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, /* What? */
	0x01, 0x00, 0x00, 0x00, 0x04, 0x42, 0x42, 0x42, 0x42, /* The deleted tuple. */
};

unsigned char tt_1_5_raw_req_ping[] = {
	0x00, 0xFF, 0x00, 0x00, /* PING */
	0x00, 0x00, 0x00, 0x00, /* Body length. */
	0x00, 0x00, 0x00, 0x00, /* Request ID. */
};

unsigned char tt_1_5_raw_res_ping[] = {
        0x00, 0xFF, 0x00, 0x00, /* PING */
        0x00, 0x00, 0x00, 0x00, /* Body length. */
        0x00, 0x00, 0x00, 0x00, /* Request ID. */
};

unsigned char tt_last_raw_req_ping[] = {
	0xCE, 0x00, 0x00, 0x00, 0x06, /* Size. */
	0x82,                         /* Header. */
	0x00, 0x40,                   /* IPROTO_REQUEST_TYPE: IPROTO_PING */
	0x01, 0x00,                   /* IPROTO_SYNC: 0 */
	0x80,                         /* Body. */
};

unsigned char tt_last_raw_res_ping[] = {
	0xCE, 0x00, 0x00, 0x00, 0x18,                               /* Size. */
	0x83,                                                       /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,                         /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,                         /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x80,                                                       /* Body. */
};

unsigned char tt_last_raw_req_insert[] = {
	0xCE, 0x00, 0x00, 0x00, 0x11,             /* Size. */
	0x82,                                     /* Header. */
	0x00, 0x02,                               /* IPROTO_REQUEST_TYPE: IPROTO_INSERT */
	0x01, 0x00,                               /* IPROTO_SYNC: 0 */
	0x82,                                     /* Body. */
	0x10, 0xCD, 0x02, 0x00,                   /* IPROTO_SPACE_ID: 512 */
	0x21, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42, /* IPROTO_TUPLE: [0x42424242] */
};

unsigned char tt_last_raw_res_insert[] = {
	0xCE, 0x00, 0x00, 0x00, 0x24,                               /* Size. */
	0x83,                                                       /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,                         /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,                         /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,                                                       /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x01,                         /* IPROTO_DATA: Array(1), */
	0x91, 0xCE, 0x42, 0x42, 0x42, 0x42,                         /* the inserted tuple. */
};

unsigned char tt_last_raw_req_replace[] = {
	0xCE, 0x00, 0x00, 0x00, 0x11,             /* Size. */
	0x82,                                     /* Header. */
	0x00, 0x03,                               /* IPROTO_REQUEST_TYPE: IPROTO_REPLACE */
	0x01, 0x00,                               /* IPROTO_SYNC: 0 */
	0x82,                                     /* Body. */
	0x10, 0xCD, 0x02, 0x00,                   /* IPROTO_SPACE_ID: 512 */
	0x21, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42, /* IPROTO_TUPLE: [0x42424242] */
};

unsigned char tt_last_raw_res_replace[] = {
	0xCE, 0x00, 0x00, 0x00, 0x24,                               /* Size. */
	0x83,                                                       /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,                         /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,                         /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,                                                       /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x01,                         /* IPROTO_DATA: Array(1), */
	0x91, 0xCE, 0x42, 0x42, 0x42, 0x42,                         /* [0x42424242]. */
};

unsigned char tt_last_raw_req_select[] = {
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

unsigned char tt_last_raw_res_select[] = {
	0xCE, 0x00, 0x00, 0x00, 0x24,   			    /* Size. */
	0x83,							    /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,			    /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,							    /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x01,			    /* IPROTO_DATA: Array(1), */
	0x91, 0xCE, 0x42, 0x42, 0x42, 0x42,			    /* [0x42424242]. */
};

unsigned char tt_last_raw_req_delete[] = {
	0xCE, 0x00, 0x00, 0x00, 0x13,		  /* Size. */
	0x82,					  /* Header. */
	0x00, 0x05,				  /* IPROTO_REQUEST_TYPE: IPROTO_DELETE */
	0x01, 0x00,				  /* IPROTO_SYNC: 0 */
	0x83,					  /* Body. */
	0x10, 0xCD, 0x02, 0x00,			  /* IPROTO_SPACE_ID: 512 */
	0x11, 0x00,				  /* IPROTO_INDEX_ID: 0 */
	0x20, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42, /* IPROTO_KEY: [0x42424242]. */
};

unsigned char tt_last_raw_res_delete[] = {
	0xCE, 0x00, 0x00, 0x00, 0x24,				    /* Size. */
	0x83,							    /* Header.*/
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,			    /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,							    /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x01,			    /* IPROTO_DATA: Array(1), */
	0x91, 0xCE, 0x42, 0x42, 0x42, 0x42,			    /* [0x42424242]. */
};

unsigned char tt_last_raw_req_call_bench_call[] = {
	0xCE, 0x00, 0x00, 0x00, 0x14,						/* Size. */
	0x82,									/* Header. */
	0x00, 0x06,								/* IPROTO_REQUEST_TYPE: IPROTO_CALL_16*/
	0x01, 0x00,								/* IPROTO_SYNC: 0 */
	0x82,									/* Body. */
	0x22, 0xAA, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x63, 0x61, 0x6C, 0x6C, /* IPROTO_FUNCTION_NAME: "bench_call" */
	0x21, 0x90,								/* IPROTO_TUPLE: [] */
};

unsigned char tt_last_raw_res_call_bench_call[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1E,				    /* Size. */
	0x83,							    /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,			    /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,							    /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_DATA: Array(0).*/
};

unsigned char tt_last_raw_req_call_bench_insert[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1B,							    /* Size. */
	0x82,										    /* Header. */
	0x00, 0x06,									    /* IPROTO_REQUEST_TYPE: IPROTO_CALL_16*/
	0x01, 0x00,									    /* IPROTO_SYNC: 0 */
	0x82,										    /* Body. */
	0x22, 0xAC, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x69, 0x6E, 0x73, 0x65, 0x72, 0x74, /* IPROTO_FUNCTION_NAME: "bench_insert" */
	0x21, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42					    /* IPROTO_TUPLE: [0x42424242] */
};

unsigned char tt_last_raw_res_call_bench_insert[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1E,				    /* Size. */
	0x83,							    /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,			    /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,							    /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_DATA: Array(0), */
};

unsigned char tt_last_raw_req_call_bench_delete[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1B,							    /* Size. */
	0x82,										    /* Header. */
	0x00, 0x06,									    /* IPROTO_REQUEST_TYPE: IPROTO_CALL_16*/
	0x01, 0x00,									    /* IPROTO_SYNC: 0 */
	0x82,										    /* Body. */
	0x22, 0xAC, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x64, 0x65, 0x6C, 0x65, 0x74, 0x65, /* IPROTO_FUNCTION_NAME: "bench_delete" */
	0x21, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42					    /* IPROTO_TUPLE: [0x42424242] */
};

unsigned char tt_last_raw_res_call_bench_delete[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1E,				    /* Size. */
	0x83,							    /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,			    /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,							    /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_DATA: Array(0), */
};

unsigned char tt_last_raw_req_call_bench_select[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1B,							    /* Size. */
	0x82,										    /* Header. */
	0x00, 0x06,									    /* IPROTO_REQUEST_TYPE: IPROTO_CALL_16*/
	0x01, 0x00,									    /* IPROTO_SYNC: 0 */
	0x82,										    /* Body. */
	0x22, 0xAC, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x64, 0x65, 0x6C, 0x65, 0x74, 0x65, /* IPROTO_FUNCTION_NAME: "bench_select" */
	0x21, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42					    /* IPROTO_TUPLE: [0x42424242] */
};

unsigned char tt_last_raw_res_call_bench_select[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1E,				    /* Size. */
	0x83,							    /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,			    /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,							    /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_DATA: Array(0), */
};

unsigned char tt_last_raw_req_call_bench_replace[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1C,							          /* Size. */
	0x82,										          /* Header. */
	0x00, 0x06,									          /* IPROTO_REQUEST_TYPE: IPROTO_CALL_16*/
	0x01, 0x00,									          /* IPROTO_SYNC: 0 */
	0x82,											  /* Body. */
	0x22, 0xAD, 0x62, 0x65, 0x6E, 0x63, 0x68, 0x5F, 0x72, 0x65, 0x70, 0x6C, 0x61, 0x63, 0x65, /* IPROTO_FUNCTION_NAME: "bench_replace" */
	0x21, 0x91, 0xCE, 0x42, 0x42, 0x42, 0x42					          /* IPROTO_TUPLE: [0x42424242] */
};

unsigned char tt_last_raw_res_call_bench_replace[] = {
	0xCE, 0x00, 0x00, 0x00, 0x1E,				    /* Size. */
	0x83,							    /* Header. */
	0x00, 0xCE, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_REQUEST_TYPE: IPROTO_OK */
	0x01, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* IPROTO_SYNC: 0 */
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x34,			    /* IPROTO_SCHEMA_VERSION: 0x34 */
	0x81,							    /* Body. */
	0x30, 0xDD, 0x00, 0x00, 0x00, 0x00,			    /* IPROTO_DATA: Array(0), */
};

void *
raw_id_find(size_t raw_size, const unsigned char *raw)
{
	const char needle[] = {0x42, 0x42, 0x42, 0x42};
	return memmem(raw, raw_size, needle, sizeof(needle));
}

void
raw_id_update(void *id_ptr, uint32_t new_id)
{
	if (id_ptr == NULL)
		return;
	unsigned char *id_bytes = (unsigned char *)id_ptr;
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
	int port = 3301;
	uint64_t reqs = 1000000;
	const char *bench_func = NULL;

	while (bench_func == NULL) {
		switch (getopt(argc, argv, "bp:c:")) {
		case 'p':
			port = atoi(optarg);
			continue;
		case 'c':
			reqs = atol(optarg);
			continue;
		case '?':
			return -1;
		case -1:
			if (optind == argc)
				ERROR_FATAL("Usage: %s <bench_func> [-b][-p <port>][-c <request_count>]", argv[0]);
			bench_func = argv[optind];
			break;
		};
	}

	const char *host = "localhost";
	int fd = bench_connect(host, port);

	if (port == 3301) {
		/* Tarantool 1.6+. */
		char greeting[128];
		read(fd, greeting, sizeof(greeting));
	}

	struct Data {
		const char *name;
		unsigned char *raw_req;
		size_t raw_req_size;
		unsigned char *raw_res;
		size_t raw_res_size;
	};
	
	struct Data data_tt_1_5[] = {
#define ENTRY(name) { #name, tt_1_5_raw_req_ ## name, sizeof(tt_1_5_raw_req_ ## name), tt_1_5_raw_res_ ## name, sizeof(tt_1_5_raw_res_ ## name) }
		ENTRY(call_bench_call),
		ENTRY(call_bench_insert),
		ENTRY(call_bench_select),
		ENTRY(call_bench_delete),
		ENTRY(ping),
		ENTRY(insert),
		ENTRY(select),
		ENTRY(delete),
#undef ENTRY
	};

	struct Data data_tt_last[] = {
#define ENTRY(name) { #name, tt_last_raw_req_ ## name, sizeof(tt_last_raw_req_ ## name), NULL, SIZE_MAX }
		ENTRY(call_bench_call),
		ENTRY(call_bench_insert),
		ENTRY(call_bench_replace),
		ENTRY(call_bench_select),
		ENTRY(call_bench_delete),
		ENTRY(ping),
		ENTRY(insert),
		ENTRY(replace),
		ENTRY(select),
		ENTRY(delete),
#undef ENTRY
	};

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

	uint64_t *latencies_ns = (uint64_t *)calloc(1, reqs * sizeof(*latencies_ns));
	unsigned char *raw_req = data.raw_req;
	unsigned char *raw_res = data.raw_res;
	size_t raw_req_size = data.raw_req_size;
	size_t raw_res_size = data.raw_res_size;

	BUG_ON(raw_req_size == SIZE_MAX || raw_req == NULL);
	/* If size is invalid, pointer should be invalid too. */
	BUG_ON((raw_res_size == SIZE_MAX) != (raw_res == NULL));

	if (raw_res_size == SIZE_MAX)
		bench_raw_request_expect(fd, raw_req_size, raw_req, &raw_res_size, &raw_res);

	BUG_ON(raw_res_size == SIZE_MAX || raw_res == NULL);

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

	printf("%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%.2f\t%lu\t%.2f\t%.0f\n", p90_us, p99_us, p999_us, med_us, avg_us, min_us, max_us, reqs, (double)overall_ns / 1000000000.0, rps);
	return 0;
}
