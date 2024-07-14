# Use VENV for external modules
# https://stackoverflow.com/questions/56658553/why-do-i-get-a-modulenotfounderror-in-vs-code-despite-the-fact-that-i-already

import hashlib
import bip32utils
import mnemonic
import bech32

def hash160(pubkey_bytes):
    sha = hashlib.sha256(pubkey_bytes).digest()
    ripemd = hashlib.new('ripemd160')
    ripemd.update(sha)
    return ripemd.digest()

def pubkey_to_bech32_address(pubkey_bytes):
    hashed_pubkey = hash160(pubkey_bytes)
    witprog = hashed_pubkey
    return bech32.encode('bc', 0, witprog)

mnemonic_words = "tomato gesture keen humor evil strike initial chunk high anger crater online"

mobj = mnemonic.Mnemonic("english")
seed = mobj.to_seed(mnemonic_words)

root_key_obj = bip32utils.BIP32Key.fromEntropy(seed)
print("Fingerprint: ", root_key_obj.Fingerprint().hex())

account_0_key = root_key_obj.ChildKey(
    84 + bip32utils.BIP32_HARDEN
).ChildKey(
    0 + bip32utils.BIP32_HARDEN
).ChildKey(
    0 + bip32utils.BIP32_HARDEN
)

receive_key = account_0_key.ChildKey(0)
receive_key_0 = receive_key.ChildKey(0)
receive_pub_key_0 = receive_key_0.PublicKey()
receive_address_0 = pubkey_to_bech32_address(receive_pub_key_0)
print("Receive Address 0: ", receive_address_0)
