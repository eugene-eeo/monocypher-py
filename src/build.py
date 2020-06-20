import os
import glob
import cffi


cwd = os.path.abspath(os.path.dirname(__file__))
sources = os.path.join(cwd, 'monocypher-3.1.1-src/')

cdefs_file = os.path.join(cwd, 'monocypher_exposed.h')
include_dir = sources
sources     = glob.glob(os.path.join(sources, '*.c'))

ffi = cffi.FFI()
ffi.set_source(
    '_monocypher',
    '''
#include <stdlib.h>
#include <monocypher.h>
    ''',
    sources=sources,
    include_dirs=[include_dir],
    extra_compile_args=['-std=c99', '-O3', '-march=native'],
)
with open(cdefs_file, 'r') as fp:
    ffi.cdef(fp.read())
