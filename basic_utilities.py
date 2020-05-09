import random
import string
from math import floor, log2, log, ceil

from binascii import unhexlify


# PART 1 - 3.1.7.  Pseudorandom Key Generation
def generate_seed(n):
    """
    returns pseudorandom generated string SEED based on latin alphabet.
    """
    alphabet = string.ascii_letters + string.digits
    seed = ''.join(random.choice(alphabet) for _ in range(n))  # Pseudo-randomly choosing letter from latin alphabet
    return seed


def bytes_needed(n):
    if n == 0:
        return 1
    return int(log(n, 256)) + 1


# compute all required lengths
def lengths(n: int, w: int in {4, 16}):
    len_1 = ceil(8 * n / log2(w))
    len_2 = floor(log2(len_1 * (w - 1)) / log2(w)) + 1
    len_all = len_1 + len_2
    return len_1, len_2, len_all


def toByte(value, bytes_count):
    return value.to_bytes(bytes_count, byteorder='big')


def XOR(one: bytearray, two: bytearray) -> bytearray:
    return bytearray(a ^ b for (a, b) in zip(one, two))


def long_to_bytes (val, bytes):
    byteVal = toByte(val, bytes)
    acc = bytearray()
    for i in range(len(byteVal)):
        if byteVal[i] < 16:
            acc.extend(b'0')
        curr = hex(byteVal[i])[2:]
        acc.extend(curr.encode())
    return acc


if __name__ == '__main__':

    value = long_to_bytes(256, 4)
    print(value)
