import json
from base64 import b64encode, b64decode
from Cryptodome.Cipher import DES, AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes

def encrypt_file(key, input_file, output_file, algorithm='DES'):
    # відкриття вхідного файлу для зчитування байтів
    with open(input_file, 'rb') as file:
        plaintext = file.read()

    if algorithm == 'DES':
        cipher = DES.new(key, DES.MODE_CBC)
    elif algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_CBC)
    else:
        raise ValueError("Непідтримуваний алгоритм шифрування. Будь ласка, виберіть DES або AES.")

    # шифрування даних та кодування iv та шифртекусту у base64
    ct_bytes = cipher.encrypt(pad(plaintext, cipher.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')

    # запис результату у вихідний файл у форматі JSON
    with open(output_file, 'w') as file:
        json.dump({'algorithm': algorithm, 'iv': iv, 'ciphertext': ct}, file)

def decrypt_file(key, input_file, output_file):
    # зчитування JSON файлу
    with open(input_file, 'r') as file:
        b64 = json.load(file)

    # декодування base64 та вибір алгоритму шифрування
    algorithm = b64['algorithm']
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])

    if algorithm == 'DES':
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Непідтримуваний алгоритм шифрування.")

    # дешифрування даних та запис у вихідний файл
    pt = unpad(cipher.decrypt(ct), cipher.block_size)

    with open(output_file, 'wb') as file:
        file.write(pt)

def main():
    algorithm = input("Виберіть алгоритм шифрування (DES або AES): ")
    if algorithm not in ['DES', 'AES']:
        print("Непідтримуваний алгоритм шифрування. Будь ласка, виберіть DES або AES.")
        return

    # генерація випадкового ключа
    key_size = 8 if algorithm == 'DES' else 16
    key = get_random_bytes(key_size)

    # Зашифрувати файл
    input_file = input("Введіть адресу вхідного файлу: ")
    output_file = 'Lab2/encrypted.txt'
    encrypt_file(key, input_file, output_file, algorithm)
    print(f"Файл '{input_file}' зашифровано за допомогою '{algorithm}' та збережено як '{output_file}'")

    # Розшифрувати файл
    input_file = 'Lab2/encrypted.txt'
    output_file = 'Lab2/decrypted.txt'
    decrypt_file(key, input_file, output_file)
    print(f"Файл '{input_file}' розшифровано та збережено як '{output_file}'")

if __name__ == "__main__":
    main()
