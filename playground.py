from ADRS import ADRS
from basic_utilities import generate_seed
from generate_sk import generate_secret_key
from generate_pk_kuglan import WOTS_genPK
from ltree import ltree
from WOTS_sign import *
from WOTS_pkFromSig import *
from XMSS_keyGen import *
from treeSig import *
from XMSS_sign import *
from XMSS_rootFromSig import *
from XMSS_verify import *

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

msg = bytearray(b'0e4575aa2c51')

print("SIGNATURE")
signature = WOTS_sign(msg, sk, 16, SEED, adrs)
print(signature)

adrs2 = ADRS()

pk_from_signature = WOTS_pkFromSig(msg, signature, 16, adrs2, SEED)

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
adrs3 = ADRS()

keypair = XMSS_keyGen(2, msg_len, w, adrs3)

# Sig = treeSig(msg, keypair.getSK(), adrs3, w, length_all, int.from_bytes(adrs3.getTreeIndex(), byteorder='big'))
# print(Sig)

Sig = XMSS_sign(msg, keypair.getSK(), w, adrs3)

value = XMSS_rootFromSig(Sig.idx_sig, Sig.sig.getSig_ots(), Sig.sig.getAuth(), msg, int.from_bytes(adrs3.getTreeHeight(), byteorder='big'), w, SEED, adrs3)

result = XMSS_verify(Sig, msg, keypair.getPK(), w, SEED, adrs3)

print(result)
#


