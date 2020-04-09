# PART 1 - 3.1.7.  Pseudorandom Key Generation
import random
from basic_utilities import generate_seed, toByte


def generate_secret_key(length):
    """
        returns pseudorandom generated private key (or secret key list "sk") based on SEED.
    """

    SEED = generate_seed(length)                    # Generating SEED string
    random.seed(SEED)                               # Setting random generator's seed with seed value
    SEED = list(SEED)                               # Converting string to simple list's elements
    sk = list()                                     # Initializing sk list (array)
    for i in range(length):                         # Pseudo-randomly generating (sampling) secret key loop, works like (PRF)
        j = random.randint(0, length - 1 - i)       # Pseudo-randomly choosing index to append to sk from SEED
        sk.append(SEED[j])
        SEED.remove(SEED[j])                        # Removing appended SEED[j] to avoid repetitions

    return ''.join(_ for _ in sk).encode(encoding='utf-8')                   # Returning sk as a encoded string



