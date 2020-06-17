import json
import argon2
import os


table = []


for nb_blocks_pow in range(3, 10):
    for nb_iterations in range(1, 5 + 1):
        for hash_len in [8, 16, 32, 64]:
            for password_length in range(0, 100, 15):
                for salt_length in range(8, 20 + 1, 3):
                    password = os.urandom(password_length)
                    salt     = os.urandom(salt_length)
                    raw_hash = argon2.low_level.hash_secret_raw(
                        password,
                        salt,
                        parallelism=1,
                        time_cost=nb_iterations,
                        memory_cost=int(2 ** nb_blocks_pow),
                        hash_len=hash_len,
                        type=argon2.low_level.Type.I,
                    )
                    table.append({
                        'password':      password.hex(),
                        'salt':          salt.hex(),
                        'hash':          raw_hash.hex(),
                        'nb_blocks':     int(2 ** nb_blocks_pow),
                        'nb_iterations': nb_iterations,
                        'hash_size':     hash_len,
                    })
                    print(len(table))


with open('tests/vectors/argon2i-vectors.json', 'w') as f:
    json.dump(table, f, indent=2)
    f.flush()
