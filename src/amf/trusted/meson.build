

enclave_name = 'enclave_amf'

enclave_object =  'lib' + enclave_name + '.so'
signed_enclave_object = '@0@.signed.so'.format(enclave_object.split('.so')[0])
enclave_test_key = enclave_name + '_private_test.pem'



# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
enclave_link_flags = mitigation_ld_flags + enclave_security_link_flags + [
    '-Wl,--no-undefined', '-nostdlib', '-nodefaultlibs', '-nostartfiles',
    '-L' + sgx_library_path,
    '-Wl,--whole-archive', '-l' + trts_library_name, '-Wl,--no-whole-archive',
    '-Wl,--whole-archive', '-lsgx_tprotected_fs', '-Wl,--no-whole-archive',
    '-Wl,--start-group',
    '-lsgx_tstdc',
    '-lsgx_tcxx',
    '-lsgx_pthread',
    '-lsgx_tkey_exchange',
    '-lsgx_protobuf',
    '-l' + crypto_library_name,
    '-l' + service_library_name,
    '-Wl,--end-group',
    '-Wl,-Bstatic', '-Wl,-Bsymbolic', '-Wl,--no-undefined', '-Wl,-pie,-eenclave_entry',
    '-Wl,--export-dynamic', '-Wl,--defsym,__ImageBase=0', '-Wl,--gc-sections',
    '-Wl,--version-script=' + meson.current_source_dir() + '/' + enclave_name + '.lds'
]


# Custom target to generate enclave_t.c and enclave_t.h
enclave_t = custom_target(enclave_name + '_t',
    output : [enclave_name + '_t.c', enclave_name + '_t.h'],
    input : enclave_name + '.edl',
    command : [sgx_edger8r, '--trusted', '@INPUT@', '--search-path', sgx_sdk / 'include', '--trusted-dir', meson.current_build_dir()]
)

# Define sources
enclave_source_files = [
    enclave_name + '.cpp',
    'anonymizer.cpp',
    enclave_t
]


# Define the Enclave target
enclave_file = shared_library(
    enclave_name,
    enclave_source_files,
    include_directories: enclave_include_paths,
    c_args: sgx_common_cflags + enclave_c_flags,
    cpp_args: sgx_common_cxxflags + enclave_cpp_flags + ['-DSGX_LIB_COMPILATION'],
    link_args: enclave_link_flags,
    dependencies : [sgx_libcore_dep, sgx_libngap_dep],
    name_prefix: 'lib',
    name_suffix: 'so'
)


if not fs.exists(enclave_test_key)
    message('There is no enclave test key<' + enclave_name + '_private_test.pem>.')
    message('The project will generate a key<' + enclave_name + '_private_test.pem> for test.')
    run_command('openssl', 'genrsa', '-out', join_paths(meson.current_build_dir(),enclave_test_key), '-3', '3072', check: true)
endif

signed_enclave = custom_target('signed_' + enclave_name,
    input: enclave_file,
    output: signed_enclave_object,
    command: [
        sgx_enclave_signer,
        'sign',
        '-key', join_paths(meson.current_build_dir(), enclave_test_key),
        '-enclave', '@INPUT@',
        '-out', signed_enclave_object,
        '-config', meson.current_source_dir() +'/' + enclave_name +'.config.xml'
    ],
    build_by_default: true
)
