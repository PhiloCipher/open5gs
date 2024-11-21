#include "enclave_maf.h"
#include "enclave_maf_t.h" /* print_string */




int ecall_initialization()
{
    ocall_print_string("Hi from enclave");
    ogs_pkbuf_t *pkbuf = NULL;
    return 5;
}

int ecall_dtls_server_close()
{

    ocall_print_string("Close SGX client");

    return 0;

}
