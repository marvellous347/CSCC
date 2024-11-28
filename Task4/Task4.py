import os
from Cryptodome.Cipher import AES, DES
from Cryptodome.PublicKey import RSA, ElGamal
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15

def generate_rsa_keys():
    print("Generating RSA keys...")
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("CSCC/Task4/private.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("CSCC/Task4/public.pem", "wb") as pub_file:
        pub_file.write(public_key)
    print("RSA keys generated.")

def generate_elgamal_keys():
    from Cryptodome.PublicKey import ElGamal
    from Cryptodome.Random import get_random_bytes
    
    print("Generating ElGamal keys...")
    key = ElGamal.generate(512, get_random_bytes)
    
    # Збереження приватного ключа
    with open("CSCC/Task4/elgamal_private.key", "wb") as priv_file:
        priv_file.write(key.p.to_bytes(64, 'big'))
        priv_file.write(key.g.to_bytes(64, 'big'))
        priv_file.write(key.y.to_bytes(64, 'big'))
        priv_file.write(key.x.to_bytes(64, 'big'))  # Save private key component
    
    # Збереження публічного ключа
    with open("CSCC/Task4/elgamal_public.key", "wb") as pub_file:
        pub_file.write(key.p.to_bytes(64, 'big'))
        pub_file.write(key.g.to_bytes(64, 'big'))
        pub_file.write(key.y.to_bytes(64, 'big'))
    
    print("ElGamal keys generated.")

def load_elgamal_private_key(file_path):
    with open(file_path, 'rb') as file:
        p = int.from_bytes(file.read(64), 'big')
        g = int.from_bytes(file.read(64), 'big')
        y = int.from_bytes(file.read(64), 'big')
        x = int.from_bytes(file.read(64), 'big')
    return ElGamal.construct((p, g, y, x))

def load_elgamal_public_key(file_path):
    with open(file_path, 'rb') as file:
        p = int.from_bytes(file.read(64), 'big')
        g = int.from_bytes(file.read(64), 'big')
        y = int.from_bytes(file.read(64), 'big')
    return ElGamal.construct((p, g, y))

def elgamal_encrypt(public_key, plaintext):
    k = get_random_bytes(64)
    while int.from_bytes(k, 'big') >= int(public_key.p):
        k = get_random_bytes(64)
    k = int.from_bytes(k, 'big')
    c1 = pow(int(public_key.g), k, int(public_key.p))
    s = pow(int(public_key.y), k, int(public_key.p))
    c2 = (int.from_bytes(plaintext, 'big') * s) % int(public_key.p)
    return (c1, c2)

def elgamal_decrypt(private_key, ciphertext):
    c1, c2 = ciphertext
    s = pow(int(c1), int(private_key.x), int(private_key.p))  # Convert to int
    s_inv = pow(s, -1, int(private_key.p))  # Convert to int
    plaintext = (int(c2) * s_inv) % int(private_key.p)  # Convert to int
    return plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')

def encrypt_file(file_path, public_key_path, mode='AES', cipher_mode='ECB'):
    print(f"Encrypting file: {file_path} with {mode} in {cipher_mode} mode...")
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    # Generate symmetric key
    if mode == 'AES':
        sym_key = get_random_bytes(32)  # AES-256
    elif mode == 'DES':
        sym_key = get_random_bytes(8)  # DES
    else:
        raise ValueError("Unsupported mode. Use 'AES' or 'DES'.")

    # Read file data
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Encrypt file data
    if mode == 'AES':
        if cipher_mode == 'ECB':
            cipher = AES.new(sym_key, AES.MODE_ECB)
            encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
        elif cipher_mode == 'CBC':
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(sym_key, AES.MODE_CBC, iv)
            encrypted_data = iv + cipher.encrypt(pad(file_data, AES.block_size))
        elif cipher_mode == 'GCM':
            cipher = AES.new(sym_key, AES.MODE_GCM)
            encrypted_data, tag = cipher.encrypt_and_digest(file_data)
            encrypted_data = cipher.nonce + tag + encrypted_data
        else:
            raise ValueError("Unsupported cipher mode. Use 'ECB', 'CBC', or 'GCM'.")
    elif mode == 'DES':
        if cipher_mode == 'ECB':
            cipher = DES.new(sym_key, DES.MODE_ECB)
            encrypted_data = cipher.encrypt(pad(file_data, DES.block_size))
        elif cipher_mode == 'CBC':
            iv = get_random_bytes(DES.block_size)
            cipher = DES.new(sym_key, DES.MODE_CBC, iv)
            encrypted_data = iv + cipher.encrypt(pad(file_data, DES.block_size))
        else:
            raise ValueError("Unsupported cipher mode. Use 'ECB' or 'CBC'.")
    else:
        raise ValueError("Unsupported mode. Use 'AES' or 'DES'.")

    # Encrypt symmetric key with ElGamal public key
    public_key = load_elgamal_public_key(public_key_path)
    encrypted_sym_key = elgamal_encrypt(public_key, sym_key)

    # Save encrypted data and encrypted symmetric key
    encrypted_file_path = os.path.join(os.path.dirname(file_path), f"encrypted_{os.path.basename(file_path)}.enc")
    with open(encrypted_file_path, 'wb') as enc_file:
        enc_file.write(encrypted_sym_key[0].to_bytes(64, 'big'))
        enc_file.write(encrypted_sym_key[1].to_bytes(64, 'big'))
        enc_file.write(encrypted_data)

def decrypt_file(file_path, private_key_path, mode='AES', cipher_mode='ECB'):
    print(f"Decrypting file: {file_path} with {mode} in {cipher_mode} mode...")
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    # Read encrypted data and encrypted symmetric key
    with open(file_path, 'rb') as enc_file:
        encrypted_sym_key = (int.from_bytes(enc_file.read(64), 'big'), int.from_bytes(enc_file.read(64), 'big'))
        encrypted_data = enc_file.read()

    # Decrypt symmetric key with ElGamal private key
    private_key = load_elgamal_private_key(private_key_path)
    sym_key = elgamal_decrypt(private_key, encrypted_sym_key)

    # Decrypt data with symmetric key
    if mode == 'AES':
        if cipher_mode == 'ECB':
            cipher = AES.new(sym_key, AES.MODE_ECB)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        elif cipher_mode == 'CBC':
            iv = encrypted_data[:AES.block_size]
            encrypted_data = encrypted_data[AES.block_size:]
            cipher = AES.new(sym_key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        elif cipher_mode == 'GCM':
            nonce = encrypted_data[:16]
            tag = encrypted_data[16:32]
            encrypted_data = encrypted_data[32:]
            cipher = AES.new(sym_key, AES.MODE_GCM, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
        else:
            raise ValueError("Invalid cipher mode. Use 'ECB', 'CBC', or 'GCM'.")
    elif mode == 'DES':
        if cipher_mode == 'ECB':
            cipher = DES.new(sym_key, DES.MODE_ECB)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)
        elif cipher_mode == 'CBC':
            iv = encrypted_data[:DES.block_size]
            encrypted_data = encrypted_data[DES.block_size:]
            cipher = DES.new(sym_key, DES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)
        else:
            raise ValueError("Invalid cipher mode. Use 'ECB' or 'CBC'.")
    else:
        raise ValueError("Invalid mode. Use 'AES' or 'DES'.")

    # Save decrypted data with a "decrypted_" prefix
    decrypted_file_path = os.path.join(os.path.dirname(file_path), f"decrypted_{os.path.basename(file_path).replace('encrypted_', '').replace('.enc', '')}")
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)

    # Open the decrypted file for viewing
    os.startfile(decrypted_file_path)

if __name__ == "__main__":
    print("Starting key generation and file encryption/decryption process...")
    generate_rsa_keys()
    generate_elgamal_keys()
    encrypt_file('CSCC/Task4/image.jpg', 'CSCC/Task4/elgamal_public.key', mode='AES', cipher_mode='CBC')
    decrypt_file('CSCC/Task4/encrypted_image.jpg.enc', 'CSCC/Task4/elgamal_private.key', mode='AES', cipher_mode='CBC')
    print("Process completed.")