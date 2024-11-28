import time
import os
from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import threading

# Функція для читання бінарних даних з файлу
def read_binary_file(filepath):
    with open(filepath, 'rb') as file:
        return file.read()

# Функція для запису бінарних даних у файл
def write_binary_file(filepath, data):
    with open(filepath, 'wb') as file:
        file.write(data)

# Функція для шифрування даних за допомогою DES у режимі ECB
def des_encrypt_ecb(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(data, DES.block_size))

# Функція для дешифрування даних за допомогою DES у режимі ECB
def des_decrypt_ecb(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(data), DES.block_size)

# Функція для шифрування даних за допомогою DES у режимі CBC
def des_encrypt_cbc(data, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, DES.block_size))

# Функція для дешифрування даних за допомогою DES у режимі CBC
def des_decrypt_cbc(data, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), DES.block_size)

# Функція для обробки файлу (шифрування або дешифрування) на основі заданого режиму
def process_file(filepath, key, mode, iv=None, encrypt=True):
    data = read_binary_file(filepath)
    # Збереження заголовка для файлів зображень
    header = data[:54] if filepath.lower().endswith(('.bmp', '.png', '.jpeg', '.jpg')) else b''
    data = data[54:] if header else data
    if encrypt:
        if mode == 'ECB':
            result = des_encrypt_ecb(data, key)
        elif mode == 'CBC':
            result = des_encrypt_cbc(data, key, iv)
    else:
        if mode == 'ECB':
            result = des_decrypt_ecb(data, key)
        elif mode == 'CBC':
            result = des_decrypt_cbc(data, key, iv)
    return header + result

# Функція для вимірювання часу виконання іншої функції
def measure_time(func, *args):
    start_time = time.time()
    result = func(*args)
    end_time = time.time()
    return result, end_time - start_time

# Основна функція для обробки введення користувача та виконання шифрування/дешифрування
def main():
    key = read_binary_file('CSCC/Task1/key.bin')
    mode = input('Enter encryption mode (ECB/CBC): ')
    operation = input('Enter operation (encrypt/decrypt): ')
    filepath = input('Enter file path: ')
    
    if operation == 'encrypt':
        iv = get_random_bytes(DES.block_size)
        encrypted_data, encryption_time = measure_time(process_file, filepath, key, mode, iv, True)
        output_filepath = f"{os.path.splitext(filepath)[0]}_{mode}_encrypted{os.path.splitext(filepath)[1]}"
        write_binary_file(output_filepath, encrypted_data)
        if mode == 'CBC':
            write_binary_file(f"{output_filepath}.iv", iv)
        print(f'Encryption time: {encryption_time} seconds')
    elif operation == 'decrypt':
        if mode == 'CBC':
            iv = read_binary_file(f"{filepath}.iv")
        else:
            iv = None
        decrypted_data, decryption_time = measure_time(process_file, filepath, key, mode, iv, False)
        output_filepath = f"{os.path.splitext(filepath)[0]}_{mode}_decrypted{os.path.splitext(filepath)[1]}"
        write_binary_file(output_filepath, decrypted_data)
        print(f'Decryption time: {decryption_time} seconds')

if __name__ == "__main__":
    main()
