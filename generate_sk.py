# PART 1 - 3.1.7.  Pseudorandom Key Generation
import random
import hashlib
from basic_utilities import generate_seed, toByte


def pseudorandom_function(s, bytes_):
    # PRF: SHA2-256(toByte(3, 32) || KEY || M)
    key = bytearray()
    key.extend(map(ord, s))

    converted = hashlib.sha256(bytes_ + key).hexdigest()
    out = bytearray()
    out.extend(map(ord, converted))
    return out


def generate_secret_key(length):
    secret_key = [bytes()] * length

    for i in range(length):
        SEED = generate_seed(length)  # Generating SEED string
        random.seed(SEED)  # Setting random generator's seed with seed value

        # initialize sk[i] with a uniformly random n-byte string;
        secret_key[i] = pseudorandom_function(SEED, toByte(i, 32))


    return secret_key
