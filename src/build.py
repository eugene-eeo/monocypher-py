import os
import glob
import cffi


cwd = os.path.abspath(os.path.dirname(__file__))
c_source_dir = os.path.join(cwd, 'monocypher-3.1.1-src/')

header_file = os.path.join(cwd, 'monocypher_exposed.h')
include_dir = c_source_dir
sources     = glob.glob(os.path.join(c_source_dir, '*.c'))

ffi = cffi.FFI()
ffi.set_source(
    '_monocypher',
    '''
#include <stdlib.h>
#include <monocypher.h>
#include <monocypher-ed25519.h>
    ''',
    sources=sources,
    include_dirs=[include_dir],
    extra_compile_args=['-std=c99', '-O3', '-march=native'],
)
with open(header_file, 'r') as fp:
    ffi.cdef(fp.read())
