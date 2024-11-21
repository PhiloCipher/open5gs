
#include "enclave_api.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;


void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    ogs_error("%s", str);
}

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                ogs_error("Info: %s\n", sgx_errlist[idx].sug);
            ogs_error("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	ogs_error("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}


int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    // void *retval = ogs_malloc(sizeof(int));
    // ret = ecall_initialization(global_eid, retval);
    // if (ret != SGX_SUCCESS) {
    //     print_error_message(ret);
    //     return -1;
    // }
    return 0;
}


int enclave_terminate(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_destroy_enclave(global_eid);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    return 0;
}
