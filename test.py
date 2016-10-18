from config import ffi, lib
import sys

password = b"Correct Horse Battery"
message = b"Foo bar foo"

# Create 16 byte random salt
assert lib.crypto_pwhash_saltbytes() == 16
salt = ffi.new("unsigned char[]", lib.crypto_pwhash_saltbytes())
lib.randombytes_buf(salt, lib.crypto_pwhash_saltbytes())

# Create 12 byte random nonce
assert lib.crypto_aead_chacha20poly1305_ietf_npubbytes() == 12
nonce = ffi.new("unsigned char[]",
    lib.crypto_aead_chacha20poly1305_ietf_npubbytes())
lib.randombytes_buf(nonce,
    lib.crypto_aead_chacha20poly1305_ietf_npubbytes())

key = ffi.new("unsigned char[]",
    lib.crypto_aead_chacha20poly1305_ietf_keybytes())

# pwhash salt and create key.
if lib.crypto_pwhash(key, lib.crypto_aead_chacha20poly1305_ietf_keybytes(),
                     password, len(password), salt,
                     lib.crypto_pwhash_opslimit_moderate(),
                     lib.crypto_pwhash_memlimit_moderate(),
                     lib.crypto_pwhash_alg_default()) != 0:
    print("Out of memory")
    sys.exit(-1)

ciphertext = ffi.new("unsigned char[]",
    len(message) + lib.crypto_aead_chacha20poly1305_ietf_abytes())
ciphertext_len = ffi.new("unsigned long long *")

# Encrypt message to ciphertext
retcode = lib.crypto_aead_chacha20poly1305_ietf_encrypt(
    ciphertext, ciphertext_len, message, len(message), ffi.NULL, 0, ffi.NULL,
    nonce, key)
assert retcode == 0

decrypted = ffi.new("unsigned char[]", len(message))
decrypted_len = ffi.new("unsigned long long *")

# Decrypt message.
retcode = lib.crypto_aead_chacha20poly1305_ietf_decrypt(
    decrypted, decrypted_len, ffi.NULL, ciphertext, ciphertext_len[0],
    ffi.NULL, 0, nonce, key)
assert retcode == 0

result = ffi.buffer(decrypted, decrypted_len[0])[:]
assert result == message

sys.exit(0)

