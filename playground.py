from ADRS import ADRS
from basic_utilities import generate_seed, calculate_length
from generate_sk import generate_secret_key
from generate_pk_kuglan import generate_public_key
from compute_l_tree import compute_tree_leaves
msg_len = 25
w = 16
length = calculate_length(msg_len, w)
SEED = generate_seed(msg_len)
adrs = ADRS()

sk = generate_secret_key(length)
pk = generate_public_key(sk, length, w, SEED, adrs)
print(sk)
print(pk)
pk = list(pk[0].decode('utf-8'))
l_tree = compute_tree_leaves(pk, adrs, SEED)
# print(l_tree)



