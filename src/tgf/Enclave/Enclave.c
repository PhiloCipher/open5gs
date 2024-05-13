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
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */

#include <string.h>
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
// #include <sys/socket.h>
// #define __U32_TYPE		unsigned int
// #define __U32_TYPE __socklen_t;
// typedef __socklen_t socklen_t;


struct sockaddr_in6{};
struct sockaddr_in{};
struct sockaddr{};
struct sockaddr_storage{};
#define socklen_t   unsigned int


// #include <sgx_tstdc.h>
// #include <sgx_trts.h>
// #include <sgx_tcrypto.h>
// #include <sgx_tseal.h>

typedef __ssize_t ssize_t;
typedef __time_t time_t;
// #include "../lib/sgx/include/tlibc/stdlib.h"
// #include "ogs-ngap.h"



int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}


int mymytest(char* str, size_t len)
{
    // ogs_asn_decode(&asn_DEF_NGAP_NGAP_PDU,
    //         NULL, sizeof(ogs_ngap_message_t), NULL);
    // ogs_ngap_decode(NULL,NULL);
    malloc(5);
    printf("AAA");
    str[1]= 'p';
    return 5;

}
