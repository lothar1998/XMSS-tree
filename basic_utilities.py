import math
import random
import string


# PART 1 - 3.1.7.  Pseudorandom Key Generation

def calculate_length(n, w):
    """
    n - mssage, private key, public key, signature element length in bytes.
    w - Winternitz parameter, number form a set {4, 16}.
    returns calculated parameter length based on "n" and "w" parameters.
    """
    len_1 = math.ceil(8 * n / math.log2(w))
    len_2 = math.floor(math.log2(len_1 * (w - 1)) / math.log2(w)) + 1

    return len_1 + len_2


def generate_seed(n):
    """
    returns pseudorandom generated string SEED based on latin alphabet.
    """
    alphabet = string.ascii_letters + string.digits
    seed = ''.join(random.choice(alphabet) for _ in range(n))  # Pseudo-randomly choosing letter from latin alphabet
    return seed


def toByte(value, bytes_count):
    return value.to_bytes(bytes_count, byteorder='big')


def XOR(one, two):
    return bytes(a ^ b for (a, b) in zip(one, two))
