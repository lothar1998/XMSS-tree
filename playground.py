from ADRS import ADRS
from basic_utilities import generate_seed, calculate_length
from generate_sk import generate_secret_key
from generate_pk_kuglan import generate_public_key
from compute_l_tree import compute_tree_leaves
from WOTS_sign import *

msg_len = 6
w = 16
length = calculate_length(msg_len, w)
SEED = generate_seed(msg_len)
adrs = ADRS()

sk = generate_secret_key(length, msg_len)
pk = generate_public_key(sk, length, w, SEED, adrs)

print(" SECRET KEYS | PUBLIC KEYS ", end='')
for sk_key, pk_key in zip(sk, pk):
    print(sk_key, pk_key)


l_tree = compute_tree_leaves(pk, adrs, SEED, length)

print("L-TREE VALUE")
print(l_tree)

signature = WOTS_sign("ABCDEF".encode(), sk, 16, SEED, adrs)
print(signature)
