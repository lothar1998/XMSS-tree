import math
import random
import string

def calc_len(n, w):
    """
    n - mssage, private key, public key, signature element length in bytes.
    w - Winternitz parameter, number form a set {4, 16}.
    returns calculated parameter length based on "n" and "w" parameters.
    """
    len_1 = math.ceil(8*n / math.log2(w)) + 1
    len_2 = math.floor(math.log2(len_1 * (w- 1)) / math.log2(w)) + 1
    
    return len_1 + len_2

def gen_seed(n):
    """
    returnes pseudorandomly generated string SEED based on latin alphabet.
    """
    alphabet = string.ascii_letters + string.digits
    seed = ''.join(random.choice(alphabet) for i in range(n))
    return seed

def gen_pk(len_):
    """
    returnes pseudorandomly generated private key (or seckret key "sk") based on SEED.
    """
    i  =  0
    sk = list()
    seed = gen_seed(len_)
    random.seed(seed)
    seed = [c for c in seed]

    for i in range(len_):
        j = random.randint(0, len_ - 1 - i)
        sk.append(seed[j])
        seed.remove(seed[j])
        
    return ''.join(c for c in sk)
    
    

# Little test 
len_ = calc_len(20, 16)
print(f'Calculated length: {len_}')
sk = gen_pk(len_)
print(f'Private key: {sk}')
