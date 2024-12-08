#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

// #include <assert.h>  ///home/mahdi/Desktop/mysgx/sgxsdk/include/tlibc/assert.h
// #include "../../../../sgxsdk/include/tlibc/assert.h"


#if defined(__cplusplus)
extern "C" {
#endif

#include <sgx_trts.h>
#include "enclave_amf_t.h" /* print_string */

#include "ogs-core.h"
#include "ogs-ngap.h"
#include "anonymizer.h"


#define ogs_warn ocall_print_string
#define ogs_error ocall_print_string


// #define ogs_log_printf(...) ((void)(0))

ogs_ngap_message_t trusted_ogs_ngap_decode(uint8_t* data, size_t len);

int mask_ngap_message(ogs_ngap_message_t *message);



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
// #if defined __USE_MISC && !defined __ASSEMBLER__

// #define _ENDIAN_H
// #endif


// # if __BYTE_ORDER == __LITTLE_ENDIAN
// #  define be32toh(x) __bswap_32 (x)

// # endif
// int a = be32toh(2);

// uint32_t a =0;



// #include "../lib/sgx/include/tlibc/stdlib.h"



// #include "../../../../sgxsdk/include/tlibc/string.h"
// #include <string.h>




#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
