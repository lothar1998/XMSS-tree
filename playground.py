from ADRS import ADRS
from basic_utilities import generate_seed
from generate_sk import generate_secret_key
from generate_pk_kuglan import WOTS_genPK
from compute_l_tree import ltree
from WOTS_sign import *
from WOTS_sign_ver import *
from XMSS_keyGen import *

msg_len = 6
w = 16
len_1, len_2, length_all = lengths(msg_len, w)

SEED = generate_seed(msg_len)
adrs = ADRS()

sk = generate_secret_key(length_all, msg_len)
pk = WOTS_genPK(sk, length_all, w, SEED, adrs)

print(" SECRET KEYS | PUBLIC KEYS ", end='\n')
for sk_key, pk_key in zip(sk, pk):
    print(sk_key, pk_key)

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

i = 0
for a, b in zip(pk, pk_from_signature):
    print(a, b, a == b, i)
    i += 1

# SK = XMSSPrivateKey()
# SK.setWOTS_SK(sk)
# SK.setSEED(SEED)
# adrs3 = ADRS()
#
# rootNode = treeHash(SK, 0, 1, adrs3, w, length_all, len_1)
#
# print(rootNode)

keypair = XMSS_keyGen(2, msg_len, w)
print(keypair)