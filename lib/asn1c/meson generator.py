import os
import sys

def generate_meson_build_sources(folder_path):
    c_files = [f for f in os.listdir(folder_path) if f.endswith('.c')]
    c_files.sort()

    meson_build_sources = 'libasn1c_lpp_sources = files(\'\'\'\n'
    for file in c_files:
        meson_build_sources += '    ' + file + '\n'
    meson_build_sources += '\'\'\'.split())'

    return meson_build_sources

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_folder>")
        sys.exit(1)

    folder_path = sys.argv[1]
    result = generate_meson_build_sources(folder_path)
    print(result)

