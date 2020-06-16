import os
import glob
import cffi


cwd = os.path.abspath(os.path.dirname(__file__))
c_source_dir = os.path.join(cwd, 'monocypher-3.1.0-src/')

header_file = os.path.join(cwd, 'monocypher_exposed.h')
include_dir = c_source_dir
sources     = glob.glob(os.path.join(c_source_dir, '*.c'))

print(header_file)
print(include_dir)
print(sources)


ffi = cffi.FFI()
ffi.set_source(
    'monocypher._monocypher',
    '''
#include <stdlib.h>
#include <monocypher.h>
#include <monocypher-ed25519.h>
    ''',
    sources=sources,
    include_dirs=[include_dir],
)
with open(header_file, 'r') as fp:
    ffi.cdef(fp.read())
