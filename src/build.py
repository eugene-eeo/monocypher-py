import os
import glob
import cffi


cwd = os.path.abspath(os.path.dirname(__file__))
sources = os.path.join(cwd, 'monocypher-3.1.2-src/')

cdefs_file = os.path.join(cwd, 'monocypher_exposed.h')
include_dir = sources
sources     = glob.glob(os.path.join(sources, '**/*.c'), recursive=True)

ffi = cffi.FFI()
ffi.set_source(
    '_monocypher',
    '''
#include <stdlib.h>
#include <monocypher.h>
#include <optional/monocypher-ed25519.h>
    ''',
    sources=sources,
    include_dirs=[include_dir],
)
with open(cdefs_file, 'r') as fp:
    ffi.cdef(fp.read())


if __name__ == "__main__":
    ffi.compile(verbose=True)
