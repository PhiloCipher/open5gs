# Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>

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

project('open5gs', 'c', 'cpp',
    version : '2.7.2',
    license : 'AGPL-3.0-or-later',
    meson_version : '>= 0.43.0',
    default_options : [
        'warning_level=1',
        'c_std=gnu89',
    ],
)

libogslib_version = '2.7.2'

prefix = get_option('prefix')
bindir = join_paths(prefix, get_option('bindir'))
libdir = join_paths(prefix, get_option('libdir'))
sysconfdir = join_paths(prefix, get_option('sysconfdir'))
localstatedir = join_paths(prefix, get_option('localstatedir'))

open5gs_build_dir = meson.current_build_dir()

cc = meson.get_compiler('c')
host_system = host_machine.system()

git = find_program('git', required: false)
#python = import('python')
#python3 = python.find_installation('python3')
python3 = find_program('python3', 'python')
if meson.version().version_compare('>=0.55.0')
python3_exe = join_paths(python3.full_path())
else
python3_exe = join_paths(python3.path())
endif
mkdir_p = 'import os; os.makedirs("@0@", exist_ok=True) if not os.environ.get("DESTDIR") else False;'
symlink = 'import os; os.symlink("@0@", "@1@") if not os.environ.get("DESTDIR") and not os.path.islink("@1@") else False;'
install_conf = 'import os; import shutil; shutil.copy("@0@", "@1@") if not os.environ.get("DESTDIR") and not os.path.isfile(os.path.join("@1@", os.path.split("@0@")[1])) else False;'
cppcheck = find_program('cppcheck', required: false)
clangtidy = find_program('run-clang-tidy', required: false) # requires clang-tools package
if clangtidy.found() != true
    clangtidy = find_program('clang-tidy', required: false)
endif

meson.add_install_script(python3_exe, '-c',
        mkdir_p.format(join_paths(localstatedir, 'log', 'open5gs')))

# Compiler flags
if cc.get_id() == 'gcc' or cc.get_id() == 'clang'
    possible_cc_flags = [
        '-Wextra',
        '-Wlogical-op',
        '-Werror=pointer-arith',
        '-Werror=init-self',
        '-Wfloat-equal',
        '-Wsuggest-attribute=noreturn',
        '-Werror=missing-prototypes',
        '-Werror=missing-declarations',
        '-Werror=implicit-function-declaration',
        '-Werror=return-type',
        '-Werror=incompatible-pointer-types',
        '-Werror=format=2',
        '-Wstrict-prototypes',
        '-Wredundant-decls',
        '-Wimplicit-fallthrough=5',
        '-Wendif-labels',
        '-Wstrict-aliasing=3',
        '-Wwrite-strings',
        '-Werror=overflow',
        '-Werror=shift-count-overflow',
        '-Werror=shift-overflow=2',
        '-Wdate-time',
        '-Wnested-externs',
        '-Wunused',
        '-Wduplicated-branches',
        '-Wmisleading-indentation',

        '-Wno-sign-compare',
        '-Wno-unused-parameter',

        '-ffast-math',
        '-fdiagnostics-show-option',
        ## TODO : '-fvisibility=hidden',
        '-fstack-protector',
        '-fstack-protector-strong',
        '--param=ssp-buffer-size=4',
    ]

    if cc.get_id() == 'clang'
        possible_cc_flags += [
            '-Wno-typedef-redefinition',
            '-Wno-gnu-variable-sized-type-not-at-end',
        ]
    endif

    if get_option('buildtype') != 'debug'
        possible_cc_flags += [
            '-ffunction-sections',
            '-fdata-sections',
        ]
    endif
else
    possible_cc_flags = []
endif

add_project_arguments(
    cc.get_supported_arguments(possible_cc_flags),
    language : 'c')













ogs_mode = get_option('OGS_MODE') 
if ogs_mode == 'AnonyCore'
    anonycore_args = ['-DAnonyCore']
else
    anonycore_args = []
endif
add_project_arguments(anonycore_args, language : 'c')

message('OGS_MODE is set to: ' + ogs_mode)

if ogs_mode == 'AnonyCore'
    root_dir = meson.current_source_dir()


    sgx_sdk = get_option('SGX_SDK')
    if sgx_sdk == ''
        warning('import SGX SDK environment variable')
        sgx_sdk = '/opt/intel/sgxsdk/'
    endif
    sgx_sdk_path = sgx_sdk



    cxx = meson.get_compiler('cpp')
    common_flags = []
    cc_version = cc.version()
    if cc_version.version_compare('>=8')
        common_flags += ['-fcf-protection']
    endif

    # ------------------------------------------------------------------
    #  Define common variables
    # ------------------------------------------------------------------
    sgx_mode = get_option('SGX_MODE')
    sgx_arch = get_option('SGX_ARCH')
    sgx_debug = get_option('SGX_DEBUG')
    sgx_prerelease = get_option('SGX_PRERELEASE')

    #-------------------------------------------------------------------
    # Define common compile flags used for GCC and G++ 
    #-------------------------------------------------------------------
    common_flags += ['-ffunction-sections', '-fdata-sections']

    common_flags += [
        '-Wall', '-Wextra', '-Wchar-subscripts', '-Wno-coverage-mismatch', '-Winit-self',
        '-Wpointer-arith', '-Wreturn-type', '-Waddress', '-Wsequence-point', '-Wformat-security',
        '-Wmissing-include-dirs', '-Wfloat-equal', '-Wundef', '-Wshadow',
        '-Wcast-align', '-Wconversion', '-Wredundant-decls'
    ]

    if sgx_debug
        if sgx_prerelease
            error('Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!')
        endif
    endif

    if sgx_debug
        common_flags += ['-ggdb', '-DDEBUG', '-DDEBUG_LEVEL=TRACE_DEBUG']
    else
        common_flags += ['-O2', '-UDEBUG']
    endif

    c_flags = common_flags
    cpp_flags = common_flags

    # additional warnings flags for C
    c_flags += ['-Wjump-misses-init', '-Wstrict-prototypes', '-Wunsuffixed-float-constants']

    # additional warnings flags for C++
    cpp_flags += ['-Wnon-virtual-dtor', '-std=c++11']

    # ----------------------------------------------------------------
    #  Define common link options
    # ----------------------------------------------------------------
    common_link_args = ['-Wl,-z,relro,-z,now,-z,noexecstack']

    # Compiler and linker options for an Enclave
    #
    # We are using '--export-dynamic' so that `g_global_data_sim' etc.
    # will be exported to dynamic symbol table.
    #
    # When `pie' is enabled, the linker (both BFD and Gold) under Ubuntu 14.04
    # will hide all symbols from dynamic symbol table even if they are marked
    # as `global' in the LD version script.
    enclave_c_args = ['-ffreestanding', '-nostdinc', '-fvisibility=hidden', '-fpie']
    if cc_version.version_compare('>=8')
        enclave_c_args += ['-fcf-protection']
    endif
    enclave_cpp_args = enclave_c_args + ['-nostdinc++']
    enclave_link_args = common_link_args


    if host_machine.cpu_family() == 'x86' or get_option('cpp_args').contains('-m32')
        sgx_arch = 'x86'
    endif


    if sgx_arch == 'x86'
        sgx_common_flags = ['-m32']
        sgx_library_path = join_paths(sgx_sdk, 'lib')
        sgx_enclave_signer = join_paths(sgx_sdk, 'bin', 'x86', 'sgx_sign')
        sgx_edger8r = join_paths(sgx_sdk, 'bin', 'x86', 'sgx_edger8r')
    else
        sgx_common_flags = ['-m64']
        sgx_library_path = join_paths(sgx_sdk, 'lib64')
        sgx_enclave_signer = join_paths(sgx_sdk, 'bin', 'x64', 'sgx_sign')
        sgx_edger8r = join_paths(sgx_sdk, 'bin', 'x64', 'sgx_edger8r')
    endif

    sgx_common_flags += common_flags


    sgx_common_flags += [
        '-Wall', '-Wextra', '-Winit-self', '-Wpointer-arith', '-Wreturn-type',
        '-Waddress', '-Wsequence-point', '-Wformat-security',
        '-Wmissing-include-dirs', '-Wfloat-equal', '-Wundef', '-Wshadow',
        '-Wcast-align', '-Wconversion', '-Wredundant-decls'
    ]

    sgx_common_cflags = sgx_common_flags + [
        '-Wjump-misses-init', '-Wstrict-prototypes', '-Wunsuffixed-float-constants'
    ]

    sgx_common_cxxflags = sgx_common_flags + ['-Wnon-virtual-dtor', '-std=c++11']


    enclave_c_flags = [
        '-nostdinc',
        '-fvisibility=hidden',
        '-fpie',
        '-ffunction-sections',
        '-fdata-sections'
    ]


    cc_version = cc.version()
    cc_below_4_9 = cc_version.version_compare('<4.9')
    # 3. Conditional stack protection flag
    if cc_below_4_9
        enclave_c_flags += '-fstack-protector'
    else
        enclave_c_flags += '-fstack-protector-strong'
    endif

    enclave_cpp_flags = enclave_c_flags + ['-nostdinc++']


    if get_option('LAv2')
        enclave_c_flags += '-DSGX_USE_LAv2_INITIATOR'
        enclave_cpp_flags += '-DSGX_USE_LAv2_INITIATOR'
    endif

    sgx_sdk_include_dir = include_directories(sgx_sdk_path + '/include')

    enclave_include_paths = include_directories(
    join_paths(sgx_sdk, 'include'),
    join_paths(sgx_sdk, 'include/tlibc'),
    join_paths(sgx_sdk, 'include/libcxx')
    )




    
    build_mode = ''

    if sgx_mode == 'HW'
        if sgx_debug == true
            build_mode = 'HW_DEBUG'
        elif sgx_prerelease == true
            build_mode = 'HW_PRERELEASE'
        else
            build_mode = 'HW_RELEASE'
        endif
    endif

    if sgx_mode == 'SIM'
        if sgx_debug == true
            build_mode = 'SIM_DEBUG'
        elif sgx_prerelease == true
            build_mode = 'SIM_PRERELEASE'
        else
            build_mode = 'SIM_RELEASE'
        endif
    endif

    fs = import('fs')

    if sgx_mode != 'HW'
        trts_library_name = 'sgx_trts_sim'
        service_library_name = 'sgx_tservice_sim'
        urts_library_name = 'sgx_urts_sim'
        uae_service_library_name = 'sgx_uae_service_sim'
    else
        trts_library_name = 'sgx_trts'
        service_library_name = 'sgx_tservice'
        urts_library_name = 'sgx_urts'
        uae_service_library_name = 'sgx_uae_service'
    endif

    crypto_library_name = 'sgx_tcrypto'
    #crypto_library_name = 'sgx_mbedcrypto'

    enclave_security_link_flags = ['-Wl,-z,relro,-z,now,-z,noexecstack']

    mitigation_ld_flags = [] # TODO


    # Conditionally add simulation or hardware libraries based on SGX_MODE
    if sgx_mode == 'HW'
        sgx_linker_flags = ['-L' + sgx_sdk + '/lib64', '-lpthread', '-lsgx_urts', '-lsgx_uprotected_fs']
    else
        sgx_linker_flags = ['-L' + sgx_sdk + '/lib64', '-lpthread', '-lsgx_urts_sim', '-lsgx_uprotected_fs']
    endif

    libsgx_uprotected_fs = sgx_sdk + '/lib64/libsgx_uprotected_fs.a'



    cxx_flags = []
    c_flags = []
    if get_option('SGX_DEBUG')
    cxx_flags += ['-DDEBUG', '-UNDEBUG', '-UEDEBUG']
    c_flags += ['-DDEBUG', '-UNDEBUG', '-UEDEBUG']
    elif get_option('SGX_PRERELEASE')
    cxx_flags += ['-DEDEBUG', '-DNDEBUG', '-UDEBUG']
    c_flags += ['-DEDEBUG', '-DNDEBUG', '-UDEBUG']
    else
    cxx_flags += ['-DNDEBUG', '-UEDEBUG', '-UDEBUG']
    c_flags += ['-DNDEBUG', '-UEDEBUG', '-UDEBUG']
    endif



    # Common compiler flags for untrusted library
    common_c_flags = ['-m64', '-O0', '-g', '-Wall', '-Wextra', '-Winit-self', '-Wpointer-arith', '-Wreturn-type', '-Waddress', '-Wsequence-point', '-Wformat-security', '-Wmissing-include-dirs', '-Wfloat-equal', '-Wundef', '-Wshadow', '-Wcast-align', '-Wcast-qual', '-Wconversion', '-Wredundant-decls', '-fPIC', '-Wno-attributes', '-DDEBUG', '-UNDEBUG', '-UEDEBUG']
    common_cpp_flags = common_c_flags + ['-std=c++11']

    app_link_flags = [sgx_common_cflags, '-l' + urts_library_name , '-L'+sgx_library_path, '-l' + uae_service_library_name, '-lpthread', libsgx_uprotected_fs, '-lrats_u', '-lsgx_dcap_ql', '-lsgx_dcap_quoteverify', '-lsgx_ukey_exchange' ] 




    message('The project has been set up in ' + build_mode + ' mode.')
    message('SGX mode is set to: ' + sgx_mode)
    message('SGX arch is: ' + sgx_arch)
    message('SGX debug is ' + (sgx_debug ? 'enabled' : 'disabled'))
    message('SGX pre-release mode is ' + (sgx_prerelease ? 'enabled' : 'disabled'))
    message('SGX SDK path is set to: ' + sgx_sdk)
endif





subdir('configs')
subdir('lib')
subdir('src')
subdir('misc')
# Don't build the tests unless we can run them (either natively or in an exe wrapper)
build_tests = not meson.is_cross_build() or (meson.is_cross_build() and meson.has_exe_wrapper())
if build_tests
    subdir('tests')
endif

# Check if the 'fuzzing' option is defined
if get_option('fuzzing')
    subdir('tests/fuzzing')
endif

message('\n'.join([
  '',
  '        prefix:                       ' + prefix,
  '        libdir:                       ' + libdir,
  '        bindir:                       ' + bindir,
  '        sysconfdir:                   ' + sysconfdir,
  '        localstatedir:                ' + localstatedir,
  '        build location:               ' + meson.current_build_dir(),
  '        source location:              ' + meson.current_source_dir(),
  '        compiler:                     ' + cc.get_id(),
  '        debugging support:            ' + get_option('buildtype'),
  '',
]))


if cppcheck.found()
    run_target('analyze-cppcheck',
    command : [ 'misc/static-code-analyze.sh',
        meson.version().version_compare('>=0.55.0') ?
          cppcheck.full_path() : cppcheck.path(),
        meson.current_build_dir(),
        meson.current_source_dir()
        ]
    )
endif

if clangtidy.found()
    run_target('analyze-clang-tidy',
    command : [ 'misc/static-code-analyze.sh',
        meson.version().version_compare('>=0.55.0') ?
          clangtidy.full_path() : clangtidy.path(),
        meson.current_build_dir(),
        meson.current_source_dir()
        ]
    )
endif
