import json
from base64 import b64encode
from Cryptodome.Random import get_random_bytes

def generate_key_iv(algorithm):
    if algorithm == 'DES':
        key = get_random_bytes(8)  # DES key must be 8 bytes long
        iv = get_random_bytes(8)   # DES IV must be 8 bytes long
    elif algorithm == 'AES':
        key = get_random_bytes(16)  # AES key must be either 16, 24, or 32 bytes long
        iv = get_random_bytes(16)   # AES IV must be 16 bytes long
    else:
        raise ValueError("Unsupported algorithm. Use 'DES' or 'AES'.")

    return key, iv

def save_key_iv(key, iv, filename):
    data = {
        'key': b64encode(key).decode('utf-8'),
        'iv': b64encode(iv).decode('utf-8')
    }
    with open(filename, 'w') as file:
        json.dump(data, file)

def main():
    algorithm = input("Enter the encryption algorithm (DES/AES): ").strip().upper()
    key, iv = generate_key_iv(algorithm)
    filename = input("Enter the filename to save the key and IV: ")
    save_key_iv(key, iv, filename)
    print(f"Key and IV saved to {filename}")

if __name__ == "__main__":
    main()