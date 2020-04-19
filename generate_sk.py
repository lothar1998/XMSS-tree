# PART 1 - 3.1.7.  Pseudorandom Key Generation
import random
from basic_utilities import generate_seed


def pseudorandom_function(SEED, n):
    random.seed(SEED)  # Setting random generator's seed with seed value
    sk_element = list()
    for i in range(n):
        sign = random.randint(0, 255)
        sk_element.append('{:02x}'.format(sign))

    return bytearray(''.join(sk_element).encode(encoding='utf-8'))


def generate_secret_key(length, n):
    secret_key = [bytes()] * length

    for i in range(length):
        SEED = generate_seed(length)  # Generating SEED string

        # initialize sk[i] with a uniformly random n-byte string;
        secret_key[i] = pseudorandom_function(SEED, n)

    return secret_key
