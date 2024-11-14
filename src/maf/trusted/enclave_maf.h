#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <assert.h>  ///home/mahdi/Desktop/mysgx/sgxsdk/include/tlibc/assert.h
// #include "../../../../sgxsdk/include/tlibc/assert.h"

#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif



// void add_client_ssl_mapping(int client_fd, SSL *ssl);
// SSL *get_ssl_by_client_fd(int client_fd);

// #ifndef OGS_CORE_H
// #define OGS_CORE_H

// #endif

// #define _GNU_SOURCE
// #include "asn_internal.h"
// #include "constr_TYPE.h"
// #if defined __USE_MISC && !defined __ASSEMBLER__
// be32toh a;
// #endif
#define _DEFAULT_SOURCE 1
#define __USE_MISC     1
// #if defined __USE_MISC && !defined __ASSEMBLER__

// #define _ENDIAN_H
// #endif


// # if __BYTE_ORDER == __LITTLE_ENDIAN
// #  define be32toh(x) __bswap_32 (x)

// # endif
// int a = be32toh(2);
#include <stdbool.h>
#include <stdint.h>
// uint32_t a =0;

#include <sys/types.h>	/* For size_t */


typedef __ssize_t ssize_t;
typedef __time_t time_t;
// #include "../lib/sgx/include/tlibc/stdlib.h"



// #include "../../../../sgxsdk/include/tlibc/string.h"
// #include <string.h>




// #include "ogs-nas-5gs.h"
#undef FILE
#undef printf


#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
