import json
import random
import itertools
import contextlib
import concurrent.futures
from porridge._ffi import ffi, lib


DEFAULT_RANDOM_SALT_LENGTH = 16
DEFAULT_HASH_LENGTH = 32
DEFAULT_TIME_COST = 2
DEFAULT_MEMORY_COST = 512
DEFAULT_FLAGS = lib.ARGON2_FLAG_CLEAR_PASSWORD | lib.ARGON2_FLAG_CLEAR_SECRET


# Taken from https://github.com/thusoy/porridge/blob/master/porridge/porridge.py
@contextlib.contextmanager
def argon2_context(
        password,
        salt,
        secret,
        ad,
        hash_len=DEFAULT_HASH_LENGTH,
        time_cost=DEFAULT_TIME_COST,
        memory_cost=DEFAULT_MEMORY_COST,
        flags=DEFAULT_FLAGS,
        version=lib.ARGON2_VERSION_NUMBER,
):
    csalt = ffi.new("uint8_t[]", salt)
    cout = ffi.new("uint8_t[]", hash_len)
    cpwd = ffi.new("uint8_t[]", password)

    csecret = ffi.new("uint8_t[]", secret)
    secret_len = len(secret)
    cad = ffi.new('uint8_t[]', ad)
    ad_len = len(ad)

    ctx = ffi.new("argon2_context *", dict(
        version=version,
        out=cout, outlen=hash_len,
        pwd=cpwd, pwdlen=len(password),
        salt=csalt, saltlen=len(salt),
        secret=csecret, secretlen=secret_len,
        ad=cad, adlen=ad_len,
        t_cost=time_cost,
        m_cost=memory_cost,
        lanes=1, threads=1,
        allocate_cbk=ffi.NULL, free_cbk=ffi.NULL,
        flags=flags,
    ))
    yield ctx


def random_bytes(n):
    return bytes(random.getrandbits(8) for _ in range(n))


def submit(password_length, salt_length, secret_length, ad_length, time_cost, memory_cost, hash_len):
    password = random_bytes(password_length)
    salt     = random_bytes(salt_length)
    secret   = random_bytes(secret_length)
    ad       = random_bytes(ad_length)

    with argon2_context(password=password,
                        salt=salt, secret=secret, ad=ad,
                        time_cost=time_cost,
                        memory_cost=memory_cost,
                        hash_len=hash_len) as ctx:
        rv = lib.argon2_ctx(ctx, lib.Argon2_i)
        if rv != lib.ARGON2_OK:
            raise Exception('wtf')
        raw_hash = bytes(ffi.buffer(ctx.out, ctx.outlen))
        return {
            'password':      password.hex(),
            'salt':          salt.hex(),
            'ad':            ad.hex(),
            'key':           secret.hex(),
            'nb_iterations': time_cost,
            'nb_blocks':     memory_cost,
            'hash_len':      hash_len,
            'hash':          raw_hash.hex(),
        }


def main():
    params = itertools.product(
        list(range(3, 5 + 1)),      # nb_blocks_pow
        list(range(1, 3 + 1)),      # nb_iterations
        [8, 16, 32, 64],            # hash_length
        list(range(0, 100, 20)),    # password_length
        list(range(8, 20 + 1, 3)),  # salt_length
        list(range(0, 20 + 1, 3)),  # secret_length
        list(range(0, 20 + 1, 3)),  # ad_length
    )
    table = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = []
        for nb_blocks_pow, nb_iterations, hash_length, password_length, salt_length, secret_length, ad_length in params:
            future = ex.submit(submit, password_length, salt_length, secret_length, ad_length, nb_iterations, int(2 ** nb_blocks_pow), hash_length)
            futures.append(future)

        for fut in concurrent.futures.as_completed(futures):
            data = fut.result()
            table.append(data)

    with open('tests/vectors/argon2i-vectors.json', 'w') as f:
        json.dump(table, f)


if __name__ == '__main__':
    main()
