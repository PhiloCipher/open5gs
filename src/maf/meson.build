

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





libmaf_sources = files('''
    context.c
    event.c

    nmaf-handler.c

    sbi-path.c
    maf-sm.c

    init.c
'''.split())

libmaf = static_library('maf',
    sources : libmaf_sources + 'enclave_api.c',
    dependencies : [libdbi_dep,
                    libsbi_dep,
                    libsgx_dep],
    install : false)

libmaf_dep = declare_dependency(
    link_with : libmaf,
    dependencies : [libdbi_dep,
                    libsbi_dep,
                    libsgx_dep
                    ])

maf_sources = files('''
    app.c
    ../main.c
'''.split())

executable('open5gs-mafd',
    sources : maf_sources,
    c_args : '-DDEFAULT_CONFIG_FILENAME="@0@/maf.yaml"'.format(open5gs_sysconfdir),
    include_directories : [srcinc] + sgx_sdk_include_dir,
    dependencies : libmaf_dep,
    install_rpath : libdir,
    install : true)



