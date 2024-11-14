#include "enclave_maf.h"
#include "enclave_maf_t.h" /* print_string */




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
