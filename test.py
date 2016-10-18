from config import ffi, lib
import sys

password = b"Correct Horse Battery"
message = b"Foo bar foo"

hashed_password = ffi.new("char[]",
    lib.crypto_pwhash_strbytes())

if lib.crypto_pwhash_str(hashed_password, password, len(password),
                         lib.crypto_pwhash_opslimit_moderate(),
                         lib.crypto_pwhash_memlimit_moderate()) != 0:
    print("Out of memory")
    sys.exit(-1)

print("Hashed password.")

# We now have the password hash to use as the key text.

if lib.crypto_pwhash_str_verify(hashed_password,
                                password, len(password)) != 0:
    print("wrong password")
    sys.exit(-1)

print("keybytes =", lib.crypto_aead_chacha20poly1305_ietf_keybytes())
print("hashed =", lib.crypto_pwhash_strbytes())

nonce = ffi.new("unsigned char[]",
    lib.crypto_aead_chacha20poly1305_ietf_npubbytes())
key = ffi.new("unsigned char[]",
    lib.crypto_aead_chacha20poly1305_ietf_keybytes())
ciphertext = ffi.new("unsigned char[]",
    len(message) + lib.crypto_aead_chacha20poly1305_ietf_abytes())
ciphertext_len = ffi.new("unsigned long long *")

lib.randombytes_buf(key, lib.crypto_aead_chacha20poly1305_ietf_keybytes())
lib.randombytes_buf(nonce, lib.crypto_aead_chacha20poly1305_ietf_npubbytes())

lib.crypto_aead_chacha20poly1305_ietf_encrypt(
    ciphertext, ciphertext_len, message, len(message), ffi.NULL, 0, ffi.NULL,
    nonce, key)

decrypted = ffi.new("unsigned char[]", len(message))
decrypted_len = ffi.new("unsigned long long *")

retcode = lib.crypto_aead_chacha20poly1305_ietf_decrypt(
    decrypted, decrypted_len, ffi.NULL, ciphertext, ciphertext_len[0],
    ffi.NULL, 0, nonce, key)
assert retcode == 0

result = ffi.buffer(decrypted, decrypted_len[0])[:]
print(result)

