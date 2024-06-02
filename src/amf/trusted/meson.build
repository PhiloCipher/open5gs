SGX_SDK = '/home/mahdi/Desktop/mysgx/sgxsdk'


gen_Enclave_t = custom_target('gen_Enclave_t',
  output: ['Enclave_t.h', 'Enclave_t.c'],
  input: 'Enclave.edl',
  command: ['sh', '-c', SGX_SDK+'/bin/x64/sgx_edger8r --trusted ../src/amf/trusted/Enclave.edl --search-path ../src/amf/trusted --search-path '+SGX_SDK+'/include'+ ' && mv Enclave_t.h ./src/amf/trusted/Enclave_t.h && mv Enclave_t.c ./src/amf/trusted/Enclave_t.c'],
  capture: false
)


Enclave_C_Files = ['./Enclave.c']
Enclave_Cpp_Files = ['./Edger8rSyntax/Arrays.cpp', './Edger8rSyntax/Functions.cpp', './Edger8rSyntax/Pointers.cpp', './Edger8rSyntax/Types.cpp', './TrustedLibrary/Libc.cpp', './TrustedLibrary/Libcxx.cpp', './TrustedLibrary/Thread.cpp']


Enclave_Include_Paths = include_directories('../Include', '.', SGX_SDK + '/include', SGX_SDK + '/include/tlibc',SGX_SDK + '/include/libcxx',SGX_SDK + '/../../Projects/open5gs_sgx/lib/ngap',SGX_SDK + '/../../Projects/open5gs_sgx/lib',SGX_SDK + '/../../Projects/open5gs_sgx/builddir/lib',SGX_SDK + '/../../Projects/open5gs_sgx/lib/asn1c/ngap',SGX_SDK + '/../../Projects/open5gs_sgx/lib/asn1c/common',SGX_SDK + '/../../Projects/open5gs_sgx/lib/core')

Enclave_C_Flags = ['-nostdinc', '-fvisibility=hidden', '-fpie', '-ffunction-sections', '-fdata-sections']
Enclave_Cpp_Flags = Enclave_C_Flags + ['-nostdinc++']

SGX_COMMON_FLAGS = ['-m64','-O0','-g', '-Wall', '-Wextra', '-Winit-self', '-Wpointer-arith', '-Wreturn-type',
'-Waddress', '-Wsequence-point', '-Wformat-security',  '-Wmissing-include-dirs', '-Wfloat-equal', '-Wundef', '-Wshadow','-Wcast-align', '-Wcast-qual','-Wconversion', '-Wredundant-decls']
SGX_COMMON_CFLAGS = SGX_COMMON_FLAGS + ['-Wjump-misses-init', '-Wstrict-prototypes', '-Wunsuffixed-float-constants']
SGX_COMMON_CXXFLAGS = SGX_COMMON_FLAGS + ['-Wnon-virtual-dtor', '-std=c++11']

Enclave_Security_Link_Flags = ['-Wl,-z,relro,-z,now,-z,noexecstack']

Enclave_Link_Flags = Enclave_Security_Link_Flags + ['-Wl,--no-undefined', '-nostdlib', '-nodefaultlibs', '-nostartfiles','-L'+SGX_SDK+'/lib64',
	'-Wl,--whole-archive' ,'-lsgx_trts_sim','-Wl,--no-whole-archive',
	'-Wl,--start-group', '-lsgx_tstdc', '-lsgx_tcxx', '-lsgx_tcrypto','-lsgx_tservice_sim', '-Wl,--end-group',
	'-Wl,-Bstatic', '-Wl,-Bsymbolic', '-Wl,--no-undefined',
	'-Wl,-pie','-eenclave_entry', '-Wl,--export-dynamic',
	'-Wl,--defsym','__ImageBase=0' ,'-Wl,--gc-sections',
	'-Wl,--version-script=../src/amf/trusted/Enclave.lds']


                    
executable('enclave.so',
  sources: [gen_Enclave_t[1]] + Enclave_Cpp_Files + Enclave_C_Files,
  dependencies: [ declare_dependency(sources: gen_Enclave_t)
  #,libngap_dep_sgx
  ],
  link_args: Enclave_Link_Flags + SGX_COMMON_CFLAGS + SGX_COMMON_CXXFLAGS, # Add any libraries to link with here
  include_directories: Enclave_Include_Paths, # Make sure Meson finds the generated header
  install: true
)

Enclave_private_test = custom_target('Enclave_private_test',
  output: ['Enclave_private_test.pem'],
  command: ['sh', '-c', 'openssl genrsa -out ./Enclave_private_test.pem -3 3072']
)

sgx_sign = custom_target('sgx_sign',
  depends: [Enclave_private_test],
  output: ['enclave.signed.so'],
  command: ['sh', '-c', SGX_SDK+'/bin/x64/sgx_sign sign -key ./Enclave_private_test.pem -enclave ./src/amf/trusted/enclave.so -out ./enclave.signed.so -config ../src/amf/trusted/Enclave.config.xml'],
  build_by_default: true
)
