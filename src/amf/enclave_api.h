
#include "enclave_amf_u.h"
#include "sgx_urts.h"
#include "ogs-app.h"
#include "ogs-ngap.h"

# define ENCLAVE_FILENAME "libenclave_amf.signed.so"


typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;



int initialize_enclave(void);
int enclave_terminate(void);
void print_error_message(sgx_status_t ret);
int sgx_ogs_ngap_decode(ogs_ngap_message_t *message, ogs_pkbuf_t *pkbuf);
int sgx_ogs_ngap_process(ogs_pkbuf_t *pkbuf, ogs_pkbuf_t *pkbuf_out);

#if defined(__cplusplus)
extern "C" {
#endif


#if defined(__cplusplus)
}
#endif


