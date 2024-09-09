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

// #ifndef FILE
// #define FILE void  // Define FILE as an opaque type

// #endif




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
#undef FILE
#undef printf
#include "Ocall_wrappers.h"
#include "ssl.h"
#include "openssl/err.h"
#include "Enclave_t.h" /* print_string */



#include "sgx_trts.h" //sgx_is_within_enclave


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
    int c = sgx_is_within_enclave(message,1);
    int a = ogs_ngap_decode_sgx(message, pkbuf_data, pkbuf_size);
    // printf("ogs_ngap_decode_sgx");
    void *b = message;
    int d = sgx_is_within_enclave(message->choice.initiatingMessage,1);
    // ogs_ngap_free(message);
    return b;

}


int sgx_test_array(char* str, size_t len)
{
    str[1]= 'p';
    return 5;
}

// int printf(const char *fmt, ...)
// {
//     char buf[BUFSIZ] = {'\0'};
//     va_list ap;
//     va_start(ap, fmt);
//     vsnprintf(buf, BUFSIZ, fmt, ap);
//     va_end(ap);
//     ocall_print_string(buf);
//     return 0;
// }



// static void init_openssl()
// {
// 	OpenSSL_add_ssl_algorithms();
// 	OpenSSL_add_all_ciphers();
// 	SSL_load_error_strings();
// }

// static void cleanup_openssl()
// {
//     EVP_cleanup();
// }

// static SSL_CTX *create_context()
// {
//     const SSL_METHOD *method;
//     SSL_CTX *ctx;

//     method = DTLS_server_method();

//     ctx = SSL_CTX_new(method);
//     if (!ctx) {
//         printe("Unable to create SSL context");
//         exit(EXIT_FAILURE);
//     }
//     return ctx;
// }

// static int password_cb(char *buf, int size, int rwflag, void *password)
// {
//     strncpy(buf, (char *)(password), size);
//     buf[size - 1] = '\0';
//     return strlen(buf);
// }

static EVP_PKEY *generatePrivateKey()
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
    EVP_PKEY_keygen(pctx, &pkey);
    return pkey;
}

static X509 *generateCertificate(EVP_PKEY *pkey)
{
    X509 *x509 = X509_new();
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), (long)60*60*24*365);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"YourCN", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_md5());
    return x509;
}

static int password_cb(char *buf, int size, int rwflag, void *password)
{
    strncpy(buf, (char *)(password), size);
    buf[size - 1] = '\0';
    return strlen(buf);
}

static void configure_context(SSL_CTX *ctx)
{
	EVP_PKEY *pkey = generatePrivateKey();
	X509 *x509 = generateCertificate(pkey);

	SSL_CTX_use_certificate(ctx, x509);
	SSL_CTX_set_default_passwd_cb(ctx, password_cb);
	SSL_CTX_use_PrivateKey(ctx, pkey);

	RSA *rsa=RSA_generate_key(512, RSA_F4, NULL, NULL);
	SSL_CTX_set_tmp_rsa(ctx, rsa);
	RSA_free(rsa);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
}

// static int create_socket_server(int port)
// {
//     int s, optval = 1;
//     struct sockaddr_in addr;

//     addr.sin_family = AF_INET;
//     addr.sin_port = htons(port);
//     addr.sin_addr.s_addr = htonl(INADDR_ANY);

//     s = socket(AF_INET, SOCK_STREAM, 132); // IPPROTO_SCTP = 132, Stream Control Transmission Protocol.  
//     if (s < 0) {
//         printe("sgx_socket");
//         exit(EXIT_FAILURE);
//     }
//     if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int)) < 0) {
//         printe("sgx_setsockopt");
//         exit(EXIT_FAILURE);
//     }
//     if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
//         printe("sgx_bind");
//         exit(EXIT_FAILURE);
//     }
//     if (listen(s, 128) < 0) {
//         printe("sgx_listen");
//         exit(EXIT_FAILURE);
//     }
//     return s;
// }

// int ecall_start_dtls_server(int client)
// {
//     int sock;
//     SSL_CTX *ctx;

//     printl("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
//     init_openssl();
//     ctx = create_context();
//     configure_context(ctx);

//     SSL *cli;
//     unsigned char read_buf[1024];
//     int r = 0;


//     cli = SSL_new(ctx);
//     SSL_set_fd(cli, client);
//     if (SSL_accept(cli) <= 0) {
//         printe("SSL_accept");
//         exit(EXIT_FAILURE);
//     }
    
//     printl("ciphersuit: %s", SSL_get_current_cipher(cli)->name);
//     /* Receive buffer from TLS server */
//     r = SSL_read(cli, read_buf, sizeof(read_buf));
//     printl("read_buf: length = %d : %s", r, read_buf);
//     memset(read_buf, 0, sizeof(read_buf));        
    
//     printl("Close DTLS client");
//     SSL_free(cli);
//     sgx_close(client);
//     // }

//     sgx_close(sock);
//     SSL_CTX_free(ctx);
//     cleanup_openssl();

//     return 0;
// }





#define MAX_CLIENTS 1024

typedef struct {
    int client_fd;
    SSL *ssl;
} client_ssl_map_t;

client_ssl_map_t client_ssl_map[MAX_CLIENTS];

void add_client_ssl_mapping(int client_fd, SSL *ssl);
// Function to add a mapping
void add_client_ssl_mapping(int client_fd, SSL *ssl) {
    int i;
    for (i = 0; i < MAX_CLIENTS; ++i) {
        if (client_ssl_map[i].client_fd == 0) {
            client_ssl_map[i].client_fd = client_fd;
            client_ssl_map[i].ssl = ssl;
            return;
        }
    }
    printe("Mapping array is full, unable to add more clients");
}

SSL *get_ssl_by_client_fd(int client_fd);

// Function to retrieve SSL* by client_fd
SSL *get_ssl_by_client_fd(int client_fd) {
    int i;
    for (i = 0; i < MAX_CLIENTS; ++i) {
        if (client_ssl_map[i].client_fd == client_fd) {
            return client_ssl_map[i].ssl;
        }
    }
    return NULL;
}

int ocall_print_errors(const char *str, size_t len, void *u) {
    char *buffer = (char *)u;
    strncat(buffer, str, len);
    return 1;
}

#include "ssl_locl.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/md5.h>
#include <openssl/bn.h>
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif


int ecall_dtls_server_initialization(int client)
{
    ocall_print_string("Hi from enclave");
    printl("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
    
    OpenSSL_add_ssl_algorithms();
    OpenSSL_add_all_ciphers();
    SSL_load_error_strings();
    

    SSL_CTX *ctx = SSL_CTX_new(DTLSv1_2_method());
    if (!ctx) {
        printe("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }
    
	EVP_PKEY *pkey = generatePrivateKey();
	X509 *x509 = generateCertificate(pkey);
    configure_context(ctx);

	SSL *cli = SSL_new(ctx);
    SSL_set_fd(cli, client);
    // volatile long long int i;
    //for (i = 0; i < 15000000000; i++) {};
    
    int ssl_accept_ret = SSL_accept(cli);
    ocall_print_string("SSL_accept called");
    
    
	if (ssl_accept_ret <= 0) {
        printe("SSL_accept failed");
        char err_buffer[1024] = {0};
        ERR_print_errors_cb(ocall_print_errors, err_buffer);
        error(err_buffer);
        exit(EXIT_FAILURE);
    }
		
    printl("ciphersuit: %s", SSL_get_current_cipher(cli)->name);

    add_client_ssl_mapping(client, cli);

    return 0;
    
    /* Receive buffer from TLS server */
    unsigned char read_buf[1024];
    int r = SSL_read(cli, read_buf, sizeof(read_buf));
    ocall_print_string(read_buf);
    return r;

    memset(read_buf, 0, sizeof(read_buf));        
    
    printl("Close SSL/TLS client");
    SSL_free(cli);


    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}


int ecall_dtls_recv_handler(int client_fd, char *output_buf, size_t buf_size) {

    SSL *cli = get_ssl_by_client_fd(client_fd);

    const char read_buf[8192];
    int r = 0;
        ocall_print_string("SSL_read starting...!");
    r = SSL_read(cli, read_buf, sizeof(read_buf));
    if (r > 0) {
        size_t copy_size = (r < buf_size) ? r : buf_size - 1;
        memcpy(output_buf, read_buf, copy_size);
        output_buf[copy_size] = '\0'; // Ensure null termination
    } else {
        output_buf[0] = '\0'; // Set output to empty string if SSL_read fails
    }
    return r;

}

int ecall_dtls_recv_handler_test(int client_fd){

    SSL *cli = get_ssl_by_client_fd(client_fd);

    const char read_buf[1024];
    int r = 0;
    r = SSL_read(cli, read_buf, sizeof(read_buf));
    ocall_print_string(read_buf);
    return r;

}


void *ecall_dtls_recv_and_ngap_decode(int client_fd){

    SSL *cli = get_ssl_by_client_fd(client_fd);

    const char read_buf[1024];
    int r = 0;
    r = SSL_read(cli, read_buf, sizeof(read_buf));
    ocall_print_string(read_buf);
    
    return sgx_ngap_decode_ecall(read_buf, r);

}