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


#ifndef SGX
#define SGX
#endif
#include "../tlibc/stdlib.h"


// #ifndef OGS_CORE_H
// #define OGS_CORE_H
// #endif /* OGS_CORE_H */


// #include <stdio.h>
// #ifndef __FILE_defined
// #define __FILE_defined 1

// struct _IO_FILE;

// /* The opaque type of streams.  This is the definition used elsewhere.  */
// typedef struct _IO_FILE FILE;

// #endif


// #ifndef	ASN_INTERNAL_H
// #define	ASN_INTERNAL_H

// #endif /* ASN_INTERNAL_H */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
// #include <stdarg.h>
// #include <stdio.h> /* vsnprintf */

// #include <string.h>
// #include <arpa/inet.h>


// #include <assert.h>
// # include <unistd.h>
// # include <pwd.h>
// # define MAX_PATH FILENAME_MAX
// #include <sys/types.h> 
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <stdlib.h>


// #include "ogs-ngap.h"
// int __ogs_ngap_domain;
/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */

#ifndef FILE
#define FILE void  // Define FILE as an opaque type

#endif




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
uint32_t a =0;

#include <sys/types.h>	/* For size_t */

// #include <sys/socket.h>
// #define __U32_TYPE		unsigned int
// #define __U32_TYPE __socklen_t;
// typedef __socklen_t socklen_t;


// struct sockaddr_in6{};
// struct sockaddr_in{};
// struct sockaddr{};
// struct sockaddr_storage{};
// #define socklen_t   unsigned int


// #include <sgx_tstdc.h>
// #include <sgx_trts.h>
// #include <sgx_tcrypto.h>
// #include <sgx_tseal.h>

typedef __ssize_t ssize_t;
typedef __time_t time_t;
// #include "../lib/sgx/include/tlibc/stdlib.h"

#include "ogs-ngap.h"

#include "../../../../sgxsdk/include/tlibc/string.h"
// #include <string.h>

// #include "ogs-nas-5gs.h"


int printf(const char* fmt, ...)
{
    // char buf[BUFSIZ] = { '\0' };
    // va_list ap;
    // va_start(ap, fmt);
    // vsnprintf(buf, BUFSIZ, fmt, ap);
    // va_end(ap);
    // ocall_print_string(buf);
    // return (int)strnlen(buf, BUFSIZ - 1) + 1;
    return 0;
}

int ogs_asn_decode_sgx(const asn_TYPE_descriptor_t *td,
        void *struct_ptr, size_t struct_size, const void *buffer,size_t size)
{
    asn_dec_rval_t dec_ret = {0};

    // ogs_assert(td);
    // ogs_assert(struct_ptr);
    // ogs_assert(struct_size);
    // ogs_assert(buffer);
    // ogs_assert(size);
    //int *a = malloc(10);
    //memset(a, 0, 10);
    // assert(0);
    memset(struct_ptr, 0, struct_size);
    dec_ret = aper_decode(NULL, td, (void **)&struct_ptr,
           buffer, size, 0, 0);

    if (dec_ret.code != RC_OK) {
        // ogs_warn("Failed to decode ASN-PDU [code:%d,consumed:%d]",
        //         dec_ret.code, (int)dec_ret.consumed);
        // return OGS_ERROR;
        return -1;
    }

    return 0;
}



int ogs_ngap_decode_sgx(NGAP_NGAP_PDU_t *message, const void *buffer,size_t size)
{
    int rv;
    // ogs_assert(message);
    // ogs_assert(buffer);
    // ogs_assert(size);
    // const asn_TYPE_descriptor_t a = asn_DEF_NGAP_NGAP_PDU;
    rv = ogs_asn_decode_sgx(&asn_DEF_NGAP_NGAP_PDU,
            message, sizeof(NGAP_NGAP_PDU_t), buffer, size);
    // if (rv != OGS_OK) {
    if (rv != 0) {
        // ogs_warn("Failed to decode NGAP-PDU");
        return rv;
    }

    // if (ogs_log_get_domain_level(OGS_LOG_DOMAIN) >= OGS_LOG_TRACE)
    //     asn_fprint(stdout, &asn_DEF_NGAP_NGAP_PDU, message);

    // return OGS_OK;
    return 0;
}


// int sgx_ngap_decode(char* str, size_t len)
// {
//     const void *pkbuf_data;
//     size_t pkbuf_size;
//     NGAP_NGAP_PDU_t *message;
//     int a = ogs_ngap_decode_sgx(message, pkbuf_data, pkbuf_size);
//     return a;

// }


void *sgx_ngap_decode_ecall(const void *pkbuf_data, size_t pkbuf_size) 
{
    NGAP_NGAP_PDU_t *message = malloc(sizeof(NGAP_NGAP_PDU_t));
    int a = ogs_ngap_decode_sgx(message, pkbuf_data, pkbuf_size);
    void *b = message;
    // ogs_ngap_free(message);
    return b;

}


int sgx_test_array(char* str, size_t len)
{
    str[1]= 'p';
    return 5;
}

