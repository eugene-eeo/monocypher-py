import re
from base64 import b64encode, b64decode
from monocypher.utils import ensure, ensure_bytes, random
from monocypher.utils.crypto_pwhash import crypto_argon2i
from monocypher.utils.crypto_cmp import crypto_verify32, crypto_verify16, crypto_verify64


__all__ = ('pwhash', 'verify', 'argon2i')


argon2i_param = re.compile(r'(v|m|t|p)=([0-9]+),?')


def _encode_base64(data):
    return b64encode(data).rstrip(b'=').decode('ascii')


def _decode_base64(data):
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return b64decode(data)


argon2i = crypto_argon2i


def pwhash(password, salt=None, nb_blocks=100000, nb_iterations=3, hash_size=64):
    if salt is None:
        salt = random(16)

    ensure_bytes('password', password)
    ensure_bytes('salt', salt)

    digest = crypto_argon2i(
        password=password,
        salt=salt,
        hash_size=hash_size,
        nb_blocks=nb_blocks,
        nb_iterations=nb_iterations,
    )
    digest = _encode_base64(digest)

    # formatting
    v = '19'
    M = nb_blocks
    T = nb_iterations
    salt = _encode_base64(salt)

    return f'$argon2i$v={v}$m={M},t={T},p=1${salt}${digest}'.encode('ascii')


def verify(password, hash):
    ensure_bytes('password', password)
    ensure_bytes('hash', hash)
    ensure(len(hash) >= 1 and hash[0] == ord(b'$'), RuntimeError, 'invalid hash')

    hash = hash.decode('ascii')
    parts = hash[1:].split('$')

    ensure(len(parts) == 5, RuntimeError, 'invalid hash')

    name, version, params, salt, digest = parts
    params = dict([(k, int(v)) for k, v in argon2i_param.findall(params)])
    salt   = _decode_base64(salt)
    digest = _decode_base64(digest)

    ensure(name == 'argon2i', RuntimeError, 'unsupported hash function')
    ensure(version == 'v=19', RuntimeError, 'unsupported argon2i version')
    ensure(set(params.keys()) == {'m', 't', 'p'}, RuntimeError, 'invalid hash')
    ensure(len(salt) >= 8, RuntimeError, 'invalid salt')
    ensure(params['p'] == 1, RuntimeError, 'unsupported parallelism value')
    ensure(len(digest) in {16, 32, 64}, RuntimeError, 'unsupported digest length')

    hash_size     = len(digest)
    nb_blocks     = params['m']
    nb_iterations = params['t']
    digest2       = crypto_argon2i(
        password, salt=salt,
        nb_blocks=nb_blocks, nb_iterations=nb_iterations,
        hash_size=hash_size,
    )

    if hash_size == 16:
        return crypto_verify16(digest2, digest)
    if hash_size == 32:
        return crypto_verify32(digest2, digest)
    return crypto_verify64(digest2, digest)
