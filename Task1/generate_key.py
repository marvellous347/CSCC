from Cryptodome.Random import get_random_bytes

def write_binary_file(filepath, data):
    with open(filepath, 'wb') as file:
        file.write(data)

def generate_key(filepath):
    key = get_random_bytes(8)  # DES key size is 8 bytes
    write_binary_file(filepath, key)

if __name__ == "__main__":
    generate_key('CSCC/Task1/key.bin')
