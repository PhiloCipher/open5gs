/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <assert.h>  ///home/mahdi/Desktop/mysgx/sgxsdk/include/tlibc/assert.h
// #include "../../../../sgxsdk/include/tlibc/assert.h"

#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef SGX
#define SGX
#endif

#include "ogs-ngap.h"

int printf(const char* fmt, ...);
int ogs_ngap_decode_sgx(NGAP_NGAP_PDU_t *message, const void *buffer,size_t size);
int ogs_asn_decode_sgx(const asn_TYPE_descriptor_t *td,
        void *struct_ptr, size_t struct_size, const void *buffer,size_t size);
int ocall_print_errors(const char *str, size_t len, void *u);


int delete_ssl_by_client_fd(int client_fd);
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

#include "ogs-ngap.h"

// #include "../../../../sgxsdk/include/tlibc/string.h"
// #include <string.h>




// #include "ogs-nas-5gs.h"
#undef FILE
#undef printf
#include "Ocall_wrappers.h"
#include "ssl.h"
#include "openssl/err.h"

#include "sgx_trts.h" //sgx_is_within_enclave

SSL *get_ssl_by_client_fd(int client_fd);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
