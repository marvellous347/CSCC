import random
import time
from sympy import isprime
from concurrent.futures import ThreadPoolExecutor

# Генерую кандидата на просте число заданої довжини
def generate_prime_candidate(length):
    p = random.getrandbits(length)
    while p % 4 != 3:
        p = random.getrandbits(length)
    return p

# Генерую велике просте число заданої довжини
def generate_large_prime(length=64):  # Зменшено розмір простих чисел
    p = generate_prime_candidate(length)
    while not isprime(p):
        p = generate_prime_candidate(length)
    return p

# Обчислюю найбільший спільний дільник (НСД) двох чисел
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Генерую псевдовипадковий потік байтів за допомогою алгоритму Blum Blum Shub
def blum_blum_shub(p, q, seed, length):
    M = p * q
    x = seed
    result = []
    for _ in range(length):
        x = (x * x) % M
        result.append(x % 256)
    return result

# Обчислення періоду BBS з обмеженням на кількість ітерацій
def calculate_bbs_period(p, q, seed, max_iterations=10000000):  # Збільшено кількість ітерацій
    M = p * q
    x = seed
    initial_state = x
    period = 0
    while period < max_iterations:
        period += 1
        x = (x * x) % M
        if x == initial_state:
            break
    return period if period < max_iterations else -1  # Повертає -1, якщо період не знайдено

# Шифрую або дешифрую файл за допомогою XOR з псевдовипадковим потоком
def encrypt_decrypt(input_file, output_file, key_stream):
    with open(input_file, 'rb') as f:
        data = bytearray(f.read())
    
    # Обробляю частину даних
    def process_chunk(start, end):
        for i in range(start, end):
            data[i] ^= key_stream[i % len(key_stream)]
    
    chunk_size = len(data) // 4  # Розділяємо на 4 частини для розпаралелення
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for i in range(4):
            start = i * chunk_size
            end = (i + 1) * chunk_size if i < 3 else len(data)
            futures.append(executor.submit(process_chunk, start, end))
        for future in futures:
            future.result()
    
    with open(output_file, 'wb') as f:
        f.write(data)

# Вимірюю час, необхідний для генерації ключового потоку та шифрування/дешифрування файлу
def measure_time(p, q, seed, length, input_file, output_file):
    start_time = time.time()
    key_stream = blum_blum_shub(p, q, seed, length)
    encrypt_decrypt(input_file, output_file, key_stream)
    end_time = time.time()
    return end_time - start_time

# Основна функція
def main():
    p = generate_large_prime(64)  # Зменшено розмір простих чисел
    q = generate_large_prime(64)  # Зменшено розмір простих чисел
    seed = random.randint(2, p * q - 1)
    while gcd(seed, p * q) != 1:
        seed = random.randint(2, p * q - 1)
    
    input_file = './CSCC/Task3/input.txt'
    output_file = './CSCC/Task3/output.txt'
    length = 1000000 # Довжина ключового потоку
    times = []
    for size in [10, 100, 1000, 10000]:
        time_taken = measure_time(p, q, seed, size, input_file, output_file)
        times.append((size, time_taken))
        print(f"Size: {size}, Time taken: {time_taken} seconds")

    # Обчислення періоду BBS з обмеженням на кількість ітерацій
    start_time = time.time()
    period = calculate_bbs_period(p, q, seed, max_iterations=10000000)
    end_time = time.time()

    if period == -1:
        print("Період BBS не знайдено за максимальну кількість ітерацій")
    else:
        print(f"Період BBS: {period}")
    print(f"Час виконання: {end_time - start_time} секунд")

if __name__ == "__main__":
    main()