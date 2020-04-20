from ADRS import ADRS
from basic_utilities import generate_seed, calculate_length
from generate_sk import generate_secret_key
from generate_pk_kuglan import generate_public_key
from compute_l_tree import compute_tree_leaves
from WOTS_sign import *
from WOTS_sign_ver import *

msg_len = 1
w = 16
length = calculate_length(msg_len, w)
SEED = generate_seed(msg_len)
adrs = ADRS()

sk = generate_secret_key(length, msg_len)
pk = generate_public_key(sk, length, w, SEED, adrs)

print(" SECRET KEYS | PUBLIC KEYS ", end='\n')
for sk_key, pk_key in zip(sk, pk):
    print(sk_key, pk_key)


l_tree = compute_tree_leaves(pk, adrs, SEED, length)

print("L-TREE VALUE")
print(l_tree)

msg = "A" * msg_len
msg = msg.encode()

print("SIGNATURE")
signature = WOTS_sign(msg, sk, 16, SEED, adrs)
print(signature)

adrs2 = ADRS()

pk_from_signature = WOTS_sign_ver(msg, signature, 16, adrs2, SEED)

print()
print(pk)
print(pk_from_signature)
print()

for a, b in zip(pk, pk_from_signature):
    print(a, b, a == b)

