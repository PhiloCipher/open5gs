

# Define base directories and flags
SGX_SDK = '/home/mahdi/Desktop/mysgx/sgxsdk'


# Common compiler flags
common_c_flags = ['-m64', '-O0', '-g', '-Wall', '-Wextra', '-Winit-self', '-Wpointer-arith', '-Wreturn-type', '-Waddress', '-Wsequence-point', '-Wformat-security', '-Wmissing-include-dirs', '-Wfloat-equal', '-Wundef', '-Wshadow', '-Wcast-align', '-Wcast-qual', '-Wconversion', '-Wredundant-decls', '-fPIC', '-Wno-attributes', '-DDEBUG', '-UNDEBUG', '-UEDEBUG']
common_cpp_flags = common_c_flags + ['-std=c++11']

# Compiler and linker flags specific to SGX
sgx_linker_flags = ['-L' + SGX_SDK + '/lib64', '-lpthread', '-lsgx_urts_sim']



SGX_EDGER8R = SGX_SDK + '/bin/x64/sgx_edger8r'



# Custom target for generating App/Enclave_u.h and App/Enclave_u.c using a custom script
gen_enclave = custom_target('gen_enclave',
  output: ['Enclave_u.h', 'Enclave_u.c'],
  input: '../../trusted/Enclave.edl',
  command: ['sh', '-c', SGX_SDK+'/bin/x64/sgx_edger8r --untrusted ../src/amf/trusted/Enclave.edl --search-path ../src/amf/trusted --search-path '+SGX_SDK+'/include' + ' && mv Enclave_u.h ./src/amf/untrusted/sgx/Enclave_u.h && mv Enclave_u.c ./src/amf/untrusted/sgx/Enclave_u.c'],
  capture: false
)

include_dirs = include_directories('../../Include', '.', SGX_SDK + '/include')

# Add generated C file to sources
app_sources = [ gen_enclave[1]]
edger8r_syntax_sources = ['./Edger8rSyntax/Arrays.cpp','./Edger8rSyntax/Functions.cpp','./Edger8rSyntax/Pointers.cpp','./Edger8rSyntax/Types.cpp']
trusted_library_sources = ['./TrustedLibrary/Thread.cpp','./TrustedLibrary/Libc.cpp','./TrustedLibrary/Libcxx.cpp']
# Define compiler
cc = meson.get_compiler('c')
cxx = meson.get_compiler('cpp')


# Assuming gen_enclave is your custom target generating Enclave_u.h
gen_dependency = declare_dependency(sources: gen_enclave)
sgx_linker_flags = ['-L' + SGX_SDK + '/lib64', '-lpthread', '-lsgx_urts_sim', '-lsgx_uprotected_fs']


libsgx_uprotected_fs = SGX_SDK + '/lib64/libsgx_uprotected_fs.a'


# Create a static library for all sources except App.c
libsgx = static_library('ogssgx',
  sources: app_sources + edger8r_syntax_sources + trusted_library_sources,
  dependencies: [gen_dependency],
      link_args: [libsgx_uprotected_fs],
  c_args: cc.get_supported_arguments(common_c_flags),
  cpp_args: cxx.get_supported_arguments(common_cpp_flags),
  include_directories: include_dirs,
)

libsgx_dep = declare_dependency(
    link_with : libsgx,
    include_directories : include_dirs,
    dependencies : gen_dependency,
    link_args: sgx_linker_flags)
    

