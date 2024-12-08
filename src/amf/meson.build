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

libamf_sources = files('''
    metrics.h

    context.c
    event.c
    timer.c

    nausf-build.c
    nausf-handler.c

    nudm-build.c
    nudm-handler.c

    nsmf-build.c
    nsmf-handler.c

    npcf-build.c
    npcf-handler.c

    nnssf-build.c
    nnssf-handler.c

    nnrf-build.c
    nnrf-handler.c

    namf-build.c
    namf-handler.c
    sbi-path.c

    ngap-sctp.c
    ngap-build.c
    ngap-handler.c
    ngap-path.c
    ngap-sm.c

    nas-security.c

    gmm-build.c
    gmm-handler.c
    nas-path.c
    gmm-sm.c

    amf-sm.c

    init.c
    metrics.c
'''.split())


if ogs_mode == 'AnonyCore'
    subdir('trusted')

    # Custom target for generating enclave_u.h and enclave_u.c using a custom script
    gen_enclave = custom_target('gen_enclave',
    output: [enclave_name + '_u.h', enclave_name + '_u.c'],
    input: meson.current_source_dir() + '/trusted/'+ enclave_name + '.edl',
    command : [sgx_edger8r, '--untrusted', '@INPUT@', '--search-path', sgx_sdk / 'include', '--search-path', sgx_sdk / 'trusted',
    '&&', 'mv', open5gs_build_dir / enclave_name + '_u.h', meson.current_build_dir(),
    '&&', 'mv', open5gs_build_dir / enclave_name + '_u.c', meson.current_build_dir()],
    capture: false
    )



    # Assuming gen_enclave is the custom target generating Enclave_u.c and Enclave_u.h
    gen_dependency = declare_dependency(sources: gen_enclave)



    # Create a static library for all sources
    libsgx = static_library('ogssgx',
    sources: [gen_enclave[1]],
    dependencies: [gen_dependency],
    link_args: app_link_flags,
    c_args: cc.get_supported_arguments(common_c_flags),
    cpp_args: cxx.get_supported_arguments(common_cpp_flags),
    include_directories: sgx_sdk_include_dir,
    )

    libsgx_dep = declare_dependency(
        link_with : libsgx,
        include_directories : sgx_sdk_include_dir,
        dependencies : gen_dependency,
        link_args: sgx_linker_flags)       



    libamf = static_library('amf',
    sources : libamf_sources+ 'enclave_api.c',
    dependencies : [libmetrics_dep,
                    libsctp_dep,
                    libngap_dep,
                    libnas_5gs_dep,
                    libsbi_dep,
                    libsgx_dep],
    install : false)

    libamf_dep = declare_dependency(
        link_with : libamf,
        dependencies : [libmetrics_dep,
                        libsctp_dep,
                        libngap_dep,
                        libnas_5gs_dep,
                        libsbi_dep,
                        libsgx_dep])

else

libamf = static_library('amf',
    sources : libamf_sources,
    dependencies : [libmetrics_dep,
                    libsctp_dep,
                    libngap_dep,
                    libnas_5gs_dep,
                    libsbi_dep],
    install : false)

libamf_dep = declare_dependency(
    link_with : libamf,
    dependencies : [libmetrics_dep,
                    libsctp_dep,
                    libngap_dep,
                    libnas_5gs_dep,
                    libsbi_dep])

endif

amf_sources = files('''
    app.c
    ../main.c
'''.split())

if ogs_mode == 'AnonyCore'
    executable('open5gs-amfd',
    sources : amf_sources,
    c_args : '-DDEFAULT_CONFIG_FILENAME="@0@/amf.yaml"'.format(open5gs_sysconfdir),
    include_directories : [srcinc] + sgx_sdk_include_dir,
    dependencies : libamf_dep,
    install_rpath : libdir,
    install : true)
else

executable('open5gs-amfd',
    sources : amf_sources,
    c_args : '-DDEFAULT_CONFIG_FILENAME="@0@/amf.yaml"'.format(open5gs_sysconfdir),
    include_directories : srcinc,
    dependencies : libamf_dep,
    install_rpath : libdir,
    install : true)
endif
