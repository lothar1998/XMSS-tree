import math
import random
import string


def calc_len(n, w):
    """
    n - mssage, private key, public key, signature element length in bytes.
    w - Winternitz parameter, number form a set {4, 16}.
    returns calculated parameter length based on "n" and "w" parameters.
    """
    len_1 = math.ceil(8 * n / math.log2(w)) + 1
    len_2 = math.floor(math.log2(len_1 * (w - 1)) / math.log2(w)) + 1

    return len_1 + len_2


def gen_seed(n):
    """
    returns pseudorandom generated string SEED based on latin alphabet.
    """
    alphabet = string.ascii_letters + string.digits
    seed = ''.join(random.choice(alphabet) for _ in range(n))  # Pseudo-randomly choosing letter from latin alphabet
    return seed


def gen_sk(length):
    """
        returns pseudorandom generated private key (or secret key list "sk") based on SEED.
    """

    SEED = gen_seed(length)                 # Generating SEED string
    random.seed(SEED)                       # Setting random generator's seed with seed value
    SEED = list(SEED)                       # Converting string to simple list's elements
    sk = list()                             # Initializing sk list (array)
    for i in range(length):                 # Pseudo-randomly generating (sampling) secret key loop, works like (PRF)
        j = random.randint(0, length - 1 - i)  # Pseudo-randomly choosing index to append to sk from SEED
        sk.append(SEED[j])
        SEED.remove(SEED[j])                # Removing appended SEED[j] for avoiding repetitions

    return ''.join(_ for _ in sk)           # Returning sk as a string





