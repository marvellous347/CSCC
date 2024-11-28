import string

def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))

def decrypt(ciphertext, key):
    """Decrypts the message using XOR."""
    return bytes([x ^ y for x, y in zip(ciphertext, key * (len(ciphertext) // len(key)) + key[:len(ciphertext) % len(key)])])

# Known ciphertext-plaintext pairs
known_pairs = [
    (bytes.fromhex('2e2b0a35373d3a46'), b'CRYPTO_2024{'),  # Example pair
    (bytes.fromhex('3d003d10'), b'd}')  # Example pair
]

# Calculate key parts
key_parts = []
for ciphertext, plaintext in known_pairs:
    key_parts.append(xor_bytes(ciphertext, plaintext))

# Attempt to assemble the full key (simple concatenation)
key = b''.join(key_parts)  # May need a more complex assembly algorithm

# Decrypt the entire message
ciphertext = bytes.fromhex('2e2b0a35373d3a46017d7f1e1a1f00231153330b155d36380c2a3918200e52423a0701233d003d10')
plaintext = decrypt(ciphertext, key)

# Check the result
try:
    decoded_plaintext = plaintext.decode('ascii')
    if all(c in string.printable for c in decoded_plaintext):
        print(decoded_plaintext)
    else:
        print("Розшифрований текст містить недруковані символи. Можливо, ключ складено неправильно.")
except UnicodeDecodeError:
    print("Розшифрований текст містить недруковані символи. Можливо, ключ складено неправильно.")