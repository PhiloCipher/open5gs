#include "enclave_amf.h"


int ecall_initialization()
{
    ocall_print_string("Hi from enclave");
    return 0;
}

int ecall_dtls_server_close()
{

    ocall_print_string("Close SGX client");

    return 0;

}


void ogs_log_printf(ogs_log_level_e level, int id,
    ogs_err_t err, const char *file, int line, const char *func,
    int content_only, const char *format, ...) {
    // Do nothing
    ocall_print_string(format);
}

ogs_pkbuf_t *ogs_pkbuf_alloc_debug(
        ogs_pkbuf_pool_t *pool, unsigned int size, const char *file_line)
{
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_cluster_t *cluster = NULL;

    // if (pool == NULL)
    //     pool = default_pool;
    // ogs_assert(pool);

    // ogs_thread_mutex_lock(&pool->mutex);

    // cluster = cluster_alloc(pool, size);
    cluster = (ogs_cluster_t *)malloc(sizeof(*cluster));
    cluster->buffer = (unsigned char*)malloc(size);
    // if (!cluster) {
    //     ogs_error("ogs_pkbuf_alloc() failed [size=%d]", size);
    //     ogs_thread_mutex_unlock(&pool->mutex);
    //     return NULL;
    // }

    // ogs_pool_alloc(&pool->pkbuf, &pkbuf);
    pkbuf = (ogs_pkbuf_t*)malloc(sizeof(*pkbuf));
    // if (!pkbuf) {
    //     ogs_error("ogs_pkbuf_alloc() failed [size=%d]", size);
    //     ogs_thread_mutex_unlock(&pool->mutex);
    //     return NULL;
    // }
    memset(pkbuf, 0, sizeof(*pkbuf));

    // OGS_OBJECT_REF(cluster);

    pkbuf->cluster = cluster;

    pkbuf->len = 0;

    pkbuf->data = cluster->buffer;
    pkbuf->head = cluster->buffer;
    pkbuf->tail = cluster->buffer;
    pkbuf->end = cluster->buffer + size;

    pkbuf->file_line = file_line; /* For debug */

    // pkbuf->pool = pool;

    // ogs_thread_mutex_unlock(&pool->mutex);

    return pkbuf;
}


void ogs_pkbuf_free(ogs_pkbuf_t *pkbuf)
{
    // ogs_pkbuf_pool_t *pool = NULL;
    // ogs_cluster_t *cluster = NULL;
    ogs_assert(pkbuf);

    // pool = pkbuf->pool;
    // ogs_assert(pool);

    // ogs_thread_mutex_lock(&pool->mutex);

    // cluster = pkbuf->cluster;
    // ogs_assert(cluster);

    // if (OGS_OBJECT_IS_REF(cluster))
    //     OGS_OBJECT_UNREF(cluster);
    // else
    //     cluster_free(pool, pkbuf->cluster);

    // ogs_pool_free(&pool->pkbuf, pkbuf);
    free(pkbuf->cluster);

    // ogs_thread_mutex_unlock(&pool->mutex);

}


// ogs_ngap_message_t trusted_ogs_ngap_decode(uint8_t* data, size_t len)
// {
//     ogs_ngap_message_t ngap_message;
//     ogs_pkbuf_t pkbuf;
//     pkbuf.data = data;
//     pkbuf.len = len;

//     int rc = ogs_ngap_decode(&ngap_message, &pkbuf);
//     // ocall_print_string(rc == OGS_OK ? "OK" : "NG");
//     // ogs_ngap_free(&ngap_message);


//     return ngap_message;
// }



int trusted_ogs_ngap_decode(ogs_ngap_message_t *message, ogs_pkbuf_t *pkbuf)
{
    int rv;
    ogs_assert(message);
    ogs_assert(pkbuf);
    ogs_assert(pkbuf->data);
    ogs_assert(pkbuf->len);

    rv = ogs_asn_decode(&asn_DEF_NGAP_NGAP_PDU,
            message, sizeof(ogs_ngap_message_t), pkbuf);
    if (rv != OGS_OK) {
        ogs_warn("Failed to decode NGAP-PDU");
        return rv;
    }
//     if (ogs_log_get_domain_level(OGS_LOG_DOMAIN) >= OGS_LOG_TRACE)
//         asn_fprint(stdout, &asn_DEF_NGAP_NGAP_PDU, message);
    return OGS_OK;
}

ogs_pkbuf_t *trusted_ogs_ngap_encode(ogs_ngap_message_t *message)
{
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(message);
    // if (ogs_log_get_domain_level(OGS_LOG_DOMAIN) >= OGS_LOG_TRACE)
    //     asn_fprint(stdout, &asn_DEF_NGAP_NGAP_PDU, message);
    pkbuf = ogs_asn_encode(&asn_DEF_NGAP_NGAP_PDU, message);
    if (!pkbuf) {
        ogs_error("ogs_asn_encode() failed");
        return NULL;
    }

    return pkbuf;
}


int ecall_ogs_ngap_process(uint8_t* input_buffer, size_t len, uint8_t* output_buffer)
{
    ogs_ngap_message_t ngap_message;
    ogs_pkbuf_t pkbuf;
    pkbuf.data = input_buffer;
    pkbuf.len = len;


    int r = trusted_ogs_ngap_decode(&ngap_message, &pkbuf);
    
    mask_ngap_message(&ngap_message);

    ogs_pkbuf_t* pkbuf2 = trusted_ogs_ngap_encode(&ngap_message);



    // memcpy(output_buffer, input_buffer, len);
    memcpy(output_buffer, pkbuf2->data, len);
    free(pkbuf2->data);


    return 0;

}



int sgx_rand(void)
{
    int ret;
    if(sgx_read_rand((unsigned char *)&ret, sizeof(ret)) == SGX_SUCCESS)
        return ret;
    else
       ocall_print_string("Error in sgx_rand");
    
    return -1;
}