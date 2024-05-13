# Copyright (C) 2019-2022 by Sukchan Lee <acetcom@gmail.com>

# This file is part of Open5GS.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

libtgf_sources = files('''
    context.c
    event.c

    ntgf-handler.c
    


    sbi-path.c
    tgf-sm.c
    sess-sm.c

    init.c
'''.split())

SGX_SDK = '/home/mahdi/Desktop/mysgx/sgxsdk'


# Define sources for the enclave and SGX-related functionality
edger8r_syntax_sources = [
    'App/Edger8rSyntax/Arrays.cpp',
    'App/Edger8rSyntax/Functions.cpp',
    'App/Edger8rSyntax/Pointers.cpp',
    'App/Edger8rSyntax/Types.cpp'
]
trusted_library_sources = [
    'App/TrustedLibrary/Thread.cpp',
    'App/TrustedLibrary/Libc.cpp',
    'App/TrustedLibrary/Libcxx.cpp'
]

gen_enclave = custom_target('gen_enclave',
  output: ['Enclave_u.h', 'Enclave_u.c'],
  input: 'Enclave/Enclave.edl',
  command: ['sh', '-c', SGX_SDK+'/bin/x64/sgx_edger8r --untrusted ../src/tgf/Enclave/Enclave.edl --search-path ../src/tgf/Enclave --search-path '+SGX_SDK+'/include' + ' && mv Enclave_u.h ./src/tgf/Enclave_u.h && mv Enclave_u.c ./src/tgf/Enclave_u.c'],
  capture: false
)


libtgf = static_library('tgf',
    sources : edger8r_syntax_sources + trusted_library_sources+ libtgf_sources +gen_enclave[1],
    dependencies : [libdbi_dep,
                    libsbi_dep,
                    declare_dependency(sources: gen_enclave)],
    include_directories: [ include_directories('Include', 'App', SGX_SDK + '/include')],
    install : false)

libtgf_dep = declare_dependency(
    link_with : libtgf,
    dependencies : [libdbi_dep,
                    libsbi_dep])

tgf_sources = files('''
    app.c
    ../main.c
'''.split())



sgx_linker_flags = ['-L' + SGX_SDK + '/lib64', '-lpthread', '-lsgx_urts_sim']






executable('open5gs-tgfd',
    sources :  ['App/App.c',gen_enclave[1]] + tgf_sources,
    c_args : '-DDEFAULT_CONFIG_FILENAME="@0@/tgf.yaml"'.format(open5gs_sysconfdir),
    include_directories :[srcinc , include_directories('Include', 'App', SGX_SDK + '/include')],
    dependencies : [libtgf_dep,declare_dependency(sources: gen_enclave)],
    link_args: sgx_linker_flags,
    install_rpath : libdir,
    install : true)
    
    
    
    
    
 #Enclave  
 
 
 
  

gen_Enclave_t = custom_target('gen_Enclave_t',
  output: ['Enclave_t.h', 'Enclave_t.c'],
  input: 'Enclave/Enclave.edl',
  command: ['sh', '-c', SGX_SDK+'/bin/x64/sgx_edger8r --trusted ../src/tgf/Enclave/Enclave.edl --search-path ../src/tgf/Enclave --search-path '+SGX_SDK+'/include'+ ' && mv Enclave_t.h ./src/tgf/Enclave_t.h && mv Enclave_t.c ./src/tgf/Enclave_t.c'],
  capture: false
)


Enclave_C_Files = ['Enclave/Enclave.c']
Enclave_Cpp_Files = ['Enclave/Edger8rSyntax/Arrays.cpp', 'Enclave/Edger8rSyntax/Functions.cpp', 'Enclave/Edger8rSyntax/Pointers.cpp', 'Enclave/Edger8rSyntax/Types.cpp', 'Enclave/TrustedLibrary/Libc.cpp', 'Enclave/TrustedLibrary/Libcxx.cpp', 'Enclave/TrustedLibrary/Thread.cpp']


Enclave_Include_Paths = include_directories('Include', 'Enclave', SGX_SDK + '/include', SGX_SDK + '/include/tlibc',SGX_SDK + '/include/libcxx',SGX_SDK + '/../../Projects/open5gs-ngap/lib/ngap',SGX_SDK + '/../../Projects/open5gs-ngap/lib',SGX_SDK + '/../../Projects/open5gs-ngap/build/lib',SGX_SDK + '/../../Projects/open5gs-ngap/lib/asn1c/ngap',SGX_SDK + '/../../Projects/open5gs-ngap/lib/asn1c/common',SGX_SDK + '/../../Projects/open5gs-ngap/lib/core')

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
	'-Wl,--version-script=../src/tgf/Enclave/Enclave.lds']


                    
executable('enclave.so',
  sources: [gen_Enclave_t[1]] + Enclave_Cpp_Files + Enclave_C_Files,
  dependencies: [ declare_dependency(sources: gen_Enclave_t)
 # ,libngap_dep_sgx
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
  command: ['sh', '-c', SGX_SDK+'/bin/x64/sgx_sign sign -key ./Enclave_private_test.pem -enclave ./src/tgf/enclave.so -out ./enclave.signed.so -config ../src/tgf/Enclave/Enclave.config.xml'],
  build_by_default: true
)


