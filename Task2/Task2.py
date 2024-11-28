import json
from base64 import b64decode
from Cryptodome.Cipher import DES, AES
from Cryptodome.Random import get_random_bytes

# Функція для шифрування файлу
def encrypt_file(key, iv, input_file, output_file, algorithm='AES'):
    with open(input_file, 'rb') as file:
        data = file.read()

    # Вибір алгоритму шифрування
    if algorithm == 'DES':
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Unsupported algorithm. Use 'DES' or 'AES'.")

    # Шифрування даних з додаванням відступів
    ct_bytes = cipher.encrypt(pad(data, cipher.block_size))

    # Запис зашифрованих даних у вихідний файл
    with open(output_file, 'wb') as file:
        file.write(iv + ct_bytes)

# Функція для розшифрування файлу
def decrypt_file(key, iv, input_file, output_file):
    with open(input_file, 'rb') as file:
        # Визначення довжини IV залежно від алгоритму
        if len(key) == 8:  # DES ключ довжиною 8 байтів
            iv = file.read(8)  # DES IV повинен бути 8 байтів
        elif len(key) in [16, 24, 32]:  # AES ключі довжиною 16, 24 або 32 байти
            iv = file.read(16)  # AES IV повинен бути 16 байтів
        else:
            raise ValueError("Unsupported key length. Use 8 bytes for DES or 16, 24, or 32 bytes for AES.")
        ct = file.read()

    # Вибір алгоритму розшифрування
    if len(key) == 8:  # DES довжина ключа
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif len(key) in [16, 24, 32]:  # AES довжина ключа
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Unsupported key length. Use 8 bytes for DES or 16, 24, or 32 bytes for AES.")

    # Розшифрування даних з видаленням відступів
    pt = unpad(cipher.decrypt(ct), cipher.block_size)

    # Запис розшифрованих даних у вихідний файл
    with open(output_file, 'wb') as file:
        file.write(pt)

# Функція для додавання відступів до даних
def pad(data, block_size):
    padding_len = block_size - len(data) % block_size
    padding = bytes([padding_len] * padding_len)
    return data + padding

# Функція для видалення відступів з даних
def unpad(data, block_size):
    padding_len = data[-1]
    if padding_len > block_size:
        raise ValueError("Invalid padding length.")
    return data[:-padding_len]

# Основна функція
def main():
    operation = input("Enter the operation (encrypt/decrypt): ").strip().lower()
    algorithm = input("Enter the encryption algorithm (DES/AES): ").strip().upper()
    key_iv_file = input("Enter the filename to load the key and IV: ")

    # Завантаження ключа та IV з файлу
    with open(key_iv_file, 'r') as file:
        data = json.load(file)
        key = b64decode(data['key'])
        iv = b64decode(data['iv'])

    input_file = input("Enter the path to the input file: ")

    # Виконання операції шифрування або розшифрування
    if operation == 'encrypt':
        encrypted_file = input_file.replace('.', f'_encrypted_{algorithm}.')
        encrypt_file(key, iv, input_file, encrypted_file, algorithm=algorithm)
        print(f"File encrypted as {encrypted_file}")
    elif operation == 'decrypt':
        decrypted_file = input_file.replace('.', '_decrypted.')
        decrypt_file(key, iv, input_file, decrypted_file)
        print(f"File decrypted as {decrypted_file}")
    else:
        print("Invalid operation. Please choose 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()
