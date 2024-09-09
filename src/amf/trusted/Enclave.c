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

// static EVP_PKEY *generatePrivateKey()
// {
//     EVP_PKEY *pkey = NULL;
//     EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
//     EVP_PKEY_keygen_init(pctx);
//     EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
//     EVP_PKEY_keygen(pctx, &pkey);
//     return pkey;
// }

// static X509 *generateCertificate(EVP_PKEY *pkey)
// {
//     X509 *x509 = X509_new();
//     X509_set_version(x509, 2);
//     ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
//     X509_gmtime_adj(X509_get_notBefore(x509), 0);
//     X509_gmtime_adj(X509_get_notAfter(x509), (long)60*60*24*365);
//     X509_set_pubkey(x509, pkey);

//     X509_NAME *name = X509_get_subject_name(x509);
//     X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
//     X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"YourCN", -1, -1, 0);
//     X509_set_issuer_name(x509, name);
//     X509_sign(x509, pkey, EVP_md5());
//     return x509;
// }

// static void configure_context(SSL_CTX *ctx)
// {
// 	EVP_PKEY *pkey = generatePrivateKey();
// 	X509 *x509 = generateCertificate(pkey);

// 	SSL_CTX_use_certificate(ctx, x509);
// 	SSL_CTX_set_default_passwd_cb(ctx, password_cb);
// 	SSL_CTX_use_PrivateKey(ctx, pkey);

// 	RSA *rsa=RSA_generate_key(512, RSA_F4, NULL, NULL);
// 	SSL_CTX_set_tmp_rsa(ctx, rsa);
// 	RSA_free(rsa);

// 	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
// }

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


static int password_cb(char *buf, int size, int rwflag, void *password)
{
    strncpy(buf, (char *)(password), size);
    buf[size - 1] = '\0';
    return strlen(buf);
}


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

static int dtls1_send_hello_verify_request(SSL *s);

int dtls1_send_hello_verify_request(SSL *s)
{
    unsigned int msg_len;
    unsigned char *msg, *buf, *p;

    if (s->state == DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A) {
        buf = (unsigned char *)s->init_buf->data;

        msg = p = &(buf[DTLS1_HM_HEADER_LENGTH]);
        /* Always use DTLS 1.0 version: see RFC 6347 */
        *(p++) = DTLS1_VERSION >> 8;
        *(p++) = DTLS1_VERSION & 0xFF;

        if (s->ctx->app_gen_cookie_cb == NULL ||
            s->ctx->app_gen_cookie_cb(s, s->d1->cookie,
                                      &(s->d1->cookie_len)) == 0) {
            SSLerr(SSL_F_DTLS1_SEND_HELLO_VERIFY_REQUEST,
                   ERR_R_INTERNAL_ERROR);
            s->state = SSL_ST_ERR;
            return 0;
        }

        *(p++) = (unsigned char)s->d1->cookie_len;
        memcpy(p, s->d1->cookie, s->d1->cookie_len);
        p += s->d1->cookie_len;
        msg_len = p - msg;

        dtls1_set_message_header(s, buf,
                                 DTLS1_MT_HELLO_VERIFY_REQUEST, msg_len, 0,
                                 msg_len);

        s->state = DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B;
        /* number of bytes to write */
        s->init_num = p - buf;
        s->init_off = 0;
    }

    /* s->state = DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B */
    return (dtls1_do_write(s, SSL3_RT_HANDSHAKE));
}


int dtls1_accept2(SSL *s);
int dtls1_accept2(SSL *s)
{
    BUF_MEM *buf;
    unsigned long Time = (unsigned long)time(NULL);
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
    unsigned long alg_k;
    int ret = -1;
    int new_state, state, skip = 0;
    int listen;
#ifndef OPENSSL_NO_SCTP
    unsigned char sctpauthkey[64];
    char labelbuffer[sizeof(DTLS1_SCTP_AUTH_LABEL)];
#endif

    RAND_add(&Time, sizeof(Time), 0);
    ERR_clear_error();
    clear_sys_error();

    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ctx->info_callback != NULL)
        cb = s->ctx->info_callback;

    listen = s->d1->listen;

    /* init things to blank */
    s->in_handshake++;
    if (!SSL_in_init(s) || SSL_in_before(s))
        SSL_clear(s);

    s->d1->listen = listen;
#ifndef OPENSSL_NO_SCTP
    /*
     * Notify SCTP BIO socket to enter handshake mode and prevent stream
     * identifier other than 0. Will be ignored if no SCTP is used.
     */
    BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE,
             s->in_handshake, NULL);
#endif

    if (s->cert == NULL) {
        SSLerr(SSL_F_DTLS1_ACCEPT, SSL_R_NO_CERTIFICATE_SET);
        return (-1);
    }
#ifndef OPENSSL_NO_HEARTBEATS
    /*
     * If we're awaiting a HeartbeatResponse, pretend we already got and
     * don't await it anymore, because Heartbeats don't make sense during
     * handshakes anyway.
     */
    if (s->tlsext_hb_pending) {
        dtls1_stop_timer(s);
        s->tlsext_hb_pending = 0;
        s->tlsext_hb_seq++;
    }
#endif

    for (;;) {
        state = s->state;

        switch (s->state) {
        case SSL_ST_RENEGOTIATE:
            s->renegotiate = 1;
            /* s->state=SSL_ST_ACCEPT; */

        case SSL_ST_BEFORE:
        case SSL_ST_ACCEPT:
        case SSL_ST_BEFORE | SSL_ST_ACCEPT:
        case SSL_ST_OK | SSL_ST_ACCEPT:


            s->server = 1;
            if (cb != NULL)
                cb(s, SSL_CB_HANDSHAKE_START, 1);

            if ((s->version & 0xff00) != (DTLS1_VERSION & 0xff00)) {
                SSLerr(SSL_F_DTLS1_ACCEPT, ERR_R_INTERNAL_ERROR);
                return -1;
            }
            s->type = SSL_ST_ACCEPT;

            if (s->init_buf == NULL) {
                if ((buf = BUF_MEM_new()) == NULL) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }
                if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
                    BUF_MEM_free(buf);
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }
                s->init_buf = buf;
            }

            if (!ssl3_setup_buffers(s)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            s->init_num = 0;
            s->d1->change_cipher_spec_ok = 0;
            /*
             * Should have been reset by ssl3_get_finished, too.
             */
            s->s3->change_cipher_spec = 0;

            if (s->state != SSL_ST_RENEGOTIATE) {
                /*
                 * Ok, we now need to push on a buffering BIO so that the
                 * output is sent in a way that TCP likes :-) ...but not with
                 * SCTP :-)
                 */
#ifndef OPENSSL_NO_SCTP
                if (!BIO_dgram_is_sctp(SSL_get_wbio(s)))
#endif
                    if (!ssl_init_wbio_buffer(s, 1)) {
                        ret = -1;
                        s->state = SSL_ST_ERR;
                        goto end;
                    }

                if (!ssl3_init_finished_mac(s)) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }

                s->state = SSL3_ST_SR_CLNT_HELLO_A;
                s->ctx->stats.sess_accept++;
            } else if (!s->s3->send_connection_binding &&
                       !(s->options &
                         SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)) {
                /*
                 * Server attempting to renegotiate with client that doesn't
                 * support secure renegotiation.
                 */
                SSLerr(SSL_F_DTLS1_ACCEPT,
                       SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
                ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            } else {
                /*
                 * s->state == SSL_ST_RENEGOTIATE, we will just send a
                 * HelloRequest
                 */
                s->ctx->stats.sess_accept_renegotiate++;
                s->state = SSL3_ST_SW_HELLO_REQ_A;
            }

            break;

        case SSL3_ST_SW_HELLO_REQ_A:
        case SSL3_ST_SW_HELLO_REQ_B:

            s->shutdown = 0;
            dtls1_clear_sent_buffer(s);
            dtls1_start_timer(s);
            ret = ssl3_send_hello_request(s);
            if (ret <= 0)
                goto end;
            s->s3->tmp.next_state = SSL3_ST_SR_CLNT_HELLO_A;
            s->state = SSL3_ST_SW_FLUSH;
            s->init_num = 0;

            if (!ssl3_init_finished_mac(s)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }
            break;

        case SSL3_ST_SW_HELLO_REQ_C:
            s->state = SSL_ST_OK;
            break;

        case SSL3_ST_SR_CLNT_HELLO_A:
        case SSL3_ST_SR_CLNT_HELLO_B:
        case SSL3_ST_SR_CLNT_HELLO_C:

            s->shutdown = 0;
            ret = ssl3_get_client_hello(s);
            if (ret <= 0)
                goto end;
            dtls1_stop_timer(s);

            if (ret == 1 && (SSL_get_options(s) & SSL_OP_COOKIE_EXCHANGE))
                s->state = DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A;
            else
                s->state = SSL3_ST_SW_SRVR_HELLO_A;

            s->init_num = 0;

            /* If we're just listening, stop here */
            if (listen && s->state == SSL3_ST_SW_SRVR_HELLO_A) {
                ret = 2;
                s->d1->listen = 0;
                /*
                 * Set expected sequence numbers to continue the handshake.
                 */
                s->d1->handshake_read_seq = 2;
                s->d1->handshake_write_seq = 1;
                s->d1->next_handshake_write_seq = 1;
                goto end;
            }

            break;

        case DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A:
        case DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B:

            ret = dtls1_send_hello_verify_request(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_SW_FLUSH;
            s->s3->tmp.next_state = SSL3_ST_SR_CLNT_HELLO_A;

            /* HelloVerifyRequest resets Finished MAC */
            if (s->version != DTLS1_BAD_VER)
                if (!ssl3_init_finished_mac(s)) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }
            break;

#ifndef OPENSSL_NO_SCTP
        case DTLS1_SCTP_ST_SR_READ_SOCK:

            if (BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s))) {
                s->s3->in_read_app_data = 2;
                s->rwstate = SSL_READING;
                BIO_clear_retry_flags(SSL_get_rbio(s));
                BIO_set_retry_read(SSL_get_rbio(s));
                ret = -1;
                goto end;
            }

            s->state = SSL3_ST_SR_FINISHED_A;
            break;

        case DTLS1_SCTP_ST_SW_WRITE_SOCK:
            ret = BIO_dgram_sctp_wait_for_dry(SSL_get_wbio(s));
            if (ret < 0)
                goto end;

            if (ret == 0) {
                if (s->d1->next_state != SSL_ST_OK) {
                    s->s3->in_read_app_data = 2;
                    s->rwstate = SSL_READING;
                    BIO_clear_retry_flags(SSL_get_rbio(s));
                    BIO_set_retry_read(SSL_get_rbio(s));
                    ret = -1;
                    goto end;
                }
            }

            s->state = s->d1->next_state;
            break;
#endif

        case SSL3_ST_SW_SRVR_HELLO_A:
        case SSL3_ST_SW_SRVR_HELLO_B:
            s->renegotiate = 2;
            dtls1_start_timer(s);
            ret = ssl3_send_server_hello(s);
            if (ret <= 0)
                goto end;

            if (s->hit) {
#ifndef OPENSSL_NO_SCTP
                /*
                 * Add new shared key for SCTP-Auth, will be ignored if no
                 * SCTP used.
                 */
                snprintf((char *)labelbuffer, sizeof(DTLS1_SCTP_AUTH_LABEL),
                         DTLS1_SCTP_AUTH_LABEL);

                if (SSL_export_keying_material(s, sctpauthkey,
                        sizeof(sctpauthkey), labelbuffer,
                        sizeof(labelbuffer), NULL, 0, 0) <= 0) {
                    ret = -1;
                    s->state = SSL_ST_ERR;
                    goto end;
                }

                BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY,
                         sizeof(sctpauthkey), sctpauthkey);
#endif
#ifndef OPENSSL_NO_TLSEXT
                if (s->tlsext_ticket_expected)
                    s->state = SSL3_ST_SW_SESSION_TICKET_A;
                else
                    s->state = SSL3_ST_SW_CHANGE_A;
#else
                s->state = SSL3_ST_SW_CHANGE_A;
#endif
            } else
                s->state = SSL3_ST_SW_CERT_A;
            s->init_num = 0;
            break;

        case SSL3_ST_SW_CERT_A:
        case SSL3_ST_SW_CERT_B:
            /* Check if it is anon DH or normal PSK */
            if (!(s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL)
                && !(s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)) {
                dtls1_start_timer(s);
                ret = ssl3_send_server_certificate(s);
                if (ret <= 0)
                    goto end;
#ifndef OPENSSL_NO_TLSEXT
                if (s->tlsext_status_expected)
                    s->state = SSL3_ST_SW_CERT_STATUS_A;
                else
                    s->state = SSL3_ST_SW_KEY_EXCH_A;
            } else {
                skip = 1;
                s->state = SSL3_ST_SW_KEY_EXCH_A;
            }
#else
            } else
                skip = 1;

            s->state = SSL3_ST_SW_KEY_EXCH_A;
#endif
            s->init_num = 0;
            break;

        case SSL3_ST_SW_KEY_EXCH_A:
        case SSL3_ST_SW_KEY_EXCH_B:
        
            alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

            /*
             * clear this, it may get reset by
             * send_server_key_exchange
             */
            s->s3->tmp.use_rsa_tmp = 0;

            /*
             * only send if a DH key exchange or RSA but we have a sign only
             * certificate
             */
            if (0
                /*
                 * PSK: send ServerKeyExchange if PSK identity hint if
                 * provided
                 */
#ifndef OPENSSL_NO_PSK
                || ((alg_k & SSL_kPSK) && s->ctx->psk_identity_hint)
#endif
                || (alg_k & SSL_kDHE)
                || (alg_k & SSL_kEECDH)
                || ((alg_k & SSL_kRSA)
                    && (s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL
                        || (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher)
                            && EVP_PKEY_size(s->cert->pkeys
                                             [SSL_PKEY_RSA_ENC].privatekey) *
                            8 > SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)
                        )
                    )
                )
                ) {
                dtls1_start_timer(s);
                ret = ssl3_send_server_key_exchange(s);
                if (ret <= 0)
                    goto end;
            } else
                skip = 1;

            s->state = SSL3_ST_SW_CERT_REQ_A;
            s->init_num = 0;
            break;

        case SSL3_ST_SW_CERT_REQ_A:
        case SSL3_ST_SW_CERT_REQ_B:
            if (                /* don't request cert unless asked for it: */
                   !(s->verify_mode & SSL_VERIFY_PEER) ||
                   /*
                    * if SSL_VERIFY_CLIENT_ONCE is set, don't request cert
                    * during re-negotiation:
                    */
                   ((s->session->peer != NULL) &&
                    (s->verify_mode & SSL_VERIFY_CLIENT_ONCE)) ||
                   /*
                    * never request cert in anonymous ciphersuites (see
                    * section "Certificate request" in SSL 3 drafts and in
                    * RFC 2246):
                    */
                   ((s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL) &&
                    /*
                     * ... except when the application insists on
                     * verification (against the specs, but s3_clnt.c accepts
                     * this for SSL 3)
                     */
                    !(s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) ||
                   /*
                    * never request cert in Kerberos ciphersuites
                    */
                   (s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5)
                   /*
                    * With normal PSK Certificates and Certificate Requests
                    * are omitted
                    */
                   || (s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK)) {
                /* no cert request */
                skip = 1;
                s->s3->tmp.cert_request = 0;
                s->state = SSL3_ST_SW_SRVR_DONE_A;
#ifndef OPENSSL_NO_SCTP
                if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
                    s->d1->next_state = SSL3_ST_SW_SRVR_DONE_A;
                    s->state = DTLS1_SCTP_ST_SW_WRITE_SOCK;
                }
#endif
            } else {
                s->s3->tmp.cert_request = 1;
                dtls1_start_timer(s);
                ret = ssl3_send_certificate_request(s);
                if (ret <= 0)
                    goto end;
#ifndef NETSCAPE_HANG_BUG
                s->state = SSL3_ST_SW_SRVR_DONE_A;
# ifndef OPENSSL_NO_SCTP
                if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
                    s->d1->next_state = SSL3_ST_SW_SRVR_DONE_A;
                    s->state = DTLS1_SCTP_ST_SW_WRITE_SOCK;
                }
# endif
#else
                s->state = SSL3_ST_SW_FLUSH;
                s->s3->tmp.next_state = SSL3_ST_SR_CERT_A;
# ifndef OPENSSL_NO_SCTP
                if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
                    s->d1->next_state = s->s3->tmp.next_state;
                    s->s3->tmp.next_state = DTLS1_SCTP_ST_SW_WRITE_SOCK;
                }
# endif
#endif
                s->init_num = 0;
            }
            break;

        case SSL3_ST_SW_SRVR_DONE_A:
        case SSL3_ST_SW_SRVR_DONE_B:
            dtls1_start_timer(s);
            ret = ssl3_send_server_done(s);
            if (ret <= 0)
                goto end;
            s->s3->tmp.next_state = SSL3_ST_SR_CERT_A;
            s->state = SSL3_ST_SW_FLUSH;
            s->init_num = 0;
            break;

        case SSL3_ST_SW_FLUSH:
            s->rwstate = SSL_WRITING;
            if (BIO_flush(s->wbio) <= 0) {
                /*
                 * If the write error was fatal, stop trying
                 */
                if (!BIO_should_retry(s->wbio)) {
                    s->rwstate = SSL_NOTHING;
                    s->state = s->s3->tmp.next_state;
                }

                ret = -1;
                goto end;
            }
            s->rwstate = SSL_NOTHING;
            s->state = s->s3->tmp.next_state;
            break;

        case SSL3_ST_SR_CERT_A:
        case SSL3_ST_SR_CERT_B:
            if (s->s3->tmp.cert_request) {
                ret = ssl3_get_client_certificate(s);
                if (ret <= 0)
                    goto end;
            }
            s->init_num = 0;
            s->state = SSL3_ST_SR_KEY_EXCH_A;
            break;

        case SSL3_ST_SR_KEY_EXCH_A:
        case SSL3_ST_SR_KEY_EXCH_B:
            ret = ssl3_get_client_key_exchange(s);
            if (ret <= 0)
                goto end;
#ifndef OPENSSL_NO_SCTP
            /*
             * Add new shared key for SCTP-Auth, will be ignored if no SCTP
             * used.
             */
            snprintf((char *)labelbuffer, sizeof(DTLS1_SCTP_AUTH_LABEL),
                     DTLS1_SCTP_AUTH_LABEL);

            if (SSL_export_keying_material(s, sctpauthkey,
                                       sizeof(sctpauthkey), labelbuffer,
                                       sizeof(labelbuffer), NULL, 0, 0) <= 0) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY,
                     sizeof(sctpauthkey), sctpauthkey);
#endif

            s->state = SSL3_ST_SR_CERT_VRFY_A;
            s->init_num = 0;

            if (ret == 2) {
                /*
                 * For the ECDH ciphersuites when the client sends its ECDH
                 * pub key in a certificate, the CertificateVerify message is
                 * not sent.
                 */
                s->state = SSL3_ST_SR_FINISHED_A;
                s->init_num = 0;
            } else if (SSL_USE_SIGALGS(s)) {
                s->state = SSL3_ST_SR_CERT_VRFY_A;
                s->init_num = 0;
                if (!s->session->peer)
                    break;
                /*
                 * For sigalgs freeze the handshake buffer at this point and
                 * digest cached records.
                 */
                if (!s->s3->handshake_buffer) {
                    SSLerr(SSL_F_DTLS1_ACCEPT, ERR_R_INTERNAL_ERROR);
                    s->state = SSL_ST_ERR;
                    return -1;
                }
                s->s3->flags |= TLS1_FLAGS_KEEP_HANDSHAKE;
                if (!ssl3_digest_cached_records(s)) {
                    s->state = SSL_ST_ERR;
                    return -1;
                }
            } else {
                s->state = SSL3_ST_SR_CERT_VRFY_A;
                s->init_num = 0;

                /*
                 * We need to get hashes here so if there is a client cert,
                 * it can be verified
                 */
                s->method->ssl3_enc->cert_verify_mac(s,
                                                     NID_md5,
                                                     &(s->s3->
                                                       tmp.cert_verify_md
                                                       [0]));
                s->method->ssl3_enc->cert_verify_mac(s, NID_sha1,
                                                     &(s->s3->
                                                       tmp.cert_verify_md
                                                       [MD5_DIGEST_LENGTH]));
            }
            break;

        case SSL3_ST_SR_CERT_VRFY_A:
        case SSL3_ST_SR_CERT_VRFY_B:
            ret = ssl3_get_cert_verify(s);
            if (ret <= 0)
                goto end;
#ifndef OPENSSL_NO_SCTP
            if (BIO_dgram_is_sctp(SSL_get_wbio(s)) &&
                state == SSL_ST_RENEGOTIATE)
                s->state = DTLS1_SCTP_ST_SR_READ_SOCK;
            else
#endif
                s->state = SSL3_ST_SR_FINISHED_A;
            s->init_num = 0;
            break;

        case SSL3_ST_SR_FINISHED_A:
        case SSL3_ST_SR_FINISHED_B:
            /*
             * Enable CCS. Receiving a CCS clears the flag, so make
             * sure not to re-enable it to ban duplicates. This *should* be the
             * first time we have received one - but we check anyway to be
             * cautious.
             * s->s3->change_cipher_spec is set when a CCS is
             * processed in d1_pkt.c, and remains set until
             * the client's Finished message is read.
             */
            
            if (!s->s3->change_cipher_spec)
                s->d1->change_cipher_spec_ok = 1;
            ret = ssl3_get_finished(s, SSL3_ST_SR_FINISHED_A,
                                    SSL3_ST_SR_FINISHED_B);
            if (ret <= 0)
                goto end;
            dtls1_stop_timer(s);
            if (s->hit)
                s->state = SSL_ST_OK;
#ifndef OPENSSL_NO_TLSEXT
            else if (s->tlsext_ticket_expected)
                s->state = SSL3_ST_SW_SESSION_TICKET_A;
#endif
            else
                s->state = SSL3_ST_SW_CHANGE_A;
            s->init_num = 0;
            break;

#ifndef OPENSSL_NO_TLSEXT
        case SSL3_ST_SW_SESSION_TICKET_A:
        case SSL3_ST_SW_SESSION_TICKET_B:
            ret = ssl3_send_newsession_ticket(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_SW_CHANGE_A;
            s->init_num = 0;
            break;

        case SSL3_ST_SW_CERT_STATUS_A:
        case SSL3_ST_SW_CERT_STATUS_B:
            ret = ssl3_send_cert_status(s);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_SW_KEY_EXCH_A;
            s->init_num = 0;
            break;

#endif

        case SSL3_ST_SW_CHANGE_A:
        case SSL3_ST_SW_CHANGE_B:

            s->session->cipher = s->s3->tmp.new_cipher;
            if (!s->method->ssl3_enc->setup_key_block(s)) {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            ret = dtls1_send_change_cipher_spec(s,
                                                SSL3_ST_SW_CHANGE_A,
                                                SSL3_ST_SW_CHANGE_B);

            if (ret <= 0)
                goto end;

#ifndef OPENSSL_NO_SCTP
            if (!s->hit) {
                /*
                 * Change to new shared key of SCTP-Auth, will be ignored if
                 * no SCTP used.
                 */
                BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY,
                         0, NULL);
            }
#endif

            s->state = SSL3_ST_SW_FINISHED_A;
            s->init_num = 0;

            if (!s->method->ssl3_enc->change_cipher_state(s,
                                                          SSL3_CHANGE_CIPHER_SERVER_WRITE))
            {
                ret = -1;
                s->state = SSL_ST_ERR;
                goto end;
            }

            dtls1_reset_seq_numbers(s, SSL3_CC_WRITE);
            break;

        case SSL3_ST_SW_FINISHED_A:
        case SSL3_ST_SW_FINISHED_B:
            ret = ssl3_send_finished(s,
                                     SSL3_ST_SW_FINISHED_A,
                                     SSL3_ST_SW_FINISHED_B,
                                     s->method->
                                     ssl3_enc->server_finished_label,
                                     s->method->
                                     ssl3_enc->server_finished_label_len);
            if (ret <= 0)
                goto end;
            s->state = SSL3_ST_SW_FLUSH;
            if (s->hit) {
                s->s3->tmp.next_state = SSL3_ST_SR_FINISHED_A;

#ifndef OPENSSL_NO_SCTP
                /*
                 * Change to new shared key of SCTP-Auth, will be ignored if
                 * no SCTP used.
                 */
                BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY,
                         0, NULL);
#endif
            } else {
                s->s3->tmp.next_state = SSL_ST_OK;
#ifndef OPENSSL_NO_SCTP
                if (BIO_dgram_is_sctp(SSL_get_wbio(s))) {
                    s->d1->next_state = s->s3->tmp.next_state;
                    s->s3->tmp.next_state = DTLS1_SCTP_ST_SW_WRITE_SOCK;
                }
#endif
            }
            s->init_num = 0;
            break;

        case SSL_ST_OK:
            /* clean a few things up */
            ssl3_cleanup_key_block(s);

#if 0
            BUF_MEM_free(s->init_buf);
            s->init_buf = NULL;
#endif

            /* remove buffering on output */
            ssl_free_wbio_buffer(s);

            s->init_num = 0;

            if (s->renegotiate == 2) { /* skipped if we just sent a
                                        * HelloRequest */
                s->renegotiate = 0;
                s->new_session = 0;

                ssl_update_cache(s, SSL_SESS_CACHE_SERVER);

                s->ctx->stats.sess_accept_good++;
                /* s->server=1; */
                s->handshake_func = dtls1_accept;

                if (cb != NULL)
                    cb(s, SSL_CB_HANDSHAKE_DONE, 1);
            }

            ret = 1;

            /* done handshaking, next message is client hello */
            s->d1->handshake_read_seq = 0;
            /* next message is server hello */
            s->d1->handshake_write_seq = 0;
            s->d1->next_handshake_write_seq = 0;
            dtls1_clear_received_buffer(s);
            goto end;
            /* break; */

        case SSL_ST_ERR:
        default:
            SSLerr(SSL_F_DTLS1_ACCEPT, SSL_R_UNKNOWN_STATE);
            ret = -1;
            goto end;
            /* break; */
        }

        if (!s->s3->tmp.reuse_message && !skip) {
            if (s->debug) {
                if ((ret = BIO_flush(s->wbio)) <= 0)
                    goto end;
            }

            if ((cb != NULL) && (s->state != state)) {
                new_state = s->state;
                s->state = state;
                cb(s, SSL_CB_ACCEPT_LOOP, 1);
                s->state = new_state;
            }
        }
        skip = 0;
    }
 end:
    /* BIO_flush(s->wbio); */

    s->in_handshake--;
#ifndef OPENSSL_NO_SCTP
    /*
     * Notify SCTP BIO socket to leave handshake mode and prevent stream
     * identifier other than 0. Will be ignored if no SCTP is used.
     */
    BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE,
             s->in_handshake, NULL);
#endif

    if (cb != NULL)
        cb(s, SSL_CB_ACCEPT_EXIT, ret);
    return (ret);
}



int SSL_accept2(SSL *s);
int SSL_accept2(SSL *s)
{
    if (s->handshake_func == 0)
        /* Not properly initialized yet */
        SSL_set_accept_state(s);
    return (s->method->ssl_accept(s));
    // return dtls1_accept2(s);
}

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
    
	//EVP_PKEY *pkey = generatePrivateKey();
	EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
    EVP_PKEY_keygen(pctx, &pkey);
	//X509 *x509 = generateCertificate(pkey);
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

	SSL_CTX_use_certificate(ctx, x509);
	SSL_CTX_set_default_passwd_cb(ctx, password_cb);
	SSL_CTX_use_PrivateKey(ctx, pkey);

	RSA *rsa=RSA_generate_key(512, RSA_F4, NULL, NULL);
	SSL_CTX_set_tmp_rsa(ctx, rsa);
	RSA_free(rsa);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
	
    

	SSL *cli = SSL_new(ctx);
    SSL_set_fd(cli, client);
    // volatile long long int i;
    //for (i = 0; i < 15000000000; i++) {};
    
    int ssl_accept_ret = SSL_accept(cli);
    // int ssl_accept_ret = SSL_accept2(cli);
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