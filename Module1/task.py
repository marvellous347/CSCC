def decrypt_message(ciphertext, key):
    # Розшифровую повідомлення, використовуючи XOR з ключем
    return ''.join([chr(int(ciphertext[i:i+2], 16) ^ key) for i in range(0, len(ciphertext), 2)])

def find_secret_byte(ciphertext):
    # Перебираю всі можливі значення ключа від 1 до 255
    for key in range(1, 256):
        decrypted_message = decrypt_message(ciphertext, key)
        # Перевіряю, чи містить розшифроване повідомлення слово "CRYPTOLOGY"
        if "CRYPTOLOGY" in decrypted_message:
            print(f"Key: {key}, Decrypted message: {decrypted_message}")

# Зашифровані повідомлення
ciphertext1 = '26373c35312a292a223c1e3c5510173a3d55173a1104160e3a5418'
ciphertext2 = '3928232a2e3536353d2301234a0f0825224a08250e1b0911254807'
ciphertext3 = '3b2a21282c3734373f210321480d0a2720480a270c190b13274b05'
ciphertext4 = '3a2b20292d3635363e200220490c0b2621490b260d180a12264d04'
ciphertext5 = '25343f3632292a29213f1d3f561314393e5614391207150d39531b'
ciphertext6 = '35242f2622393a39312f0d2f460304292e4604290217051d2940460b'
ciphertext7 = '36272c25213a393a322c0e2c4500072a2d45072a0114061e2a424508'
ciphertext8 = '2839323b3f2427242c3210325b1e1934335b19341f0a180034535b16'
ciphertext9 = '36272c25213a393a322c0e2c4500072a2d45072a0114061e2a4c4508'

# Виконання завдань
print("Task 1:")
find_secret_byte(ciphertext1)

print("\nTask 2:")
find_secret_byte(ciphertext2)

print("\nTask 3:")
find_secret_byte(ciphertext3)

print("\nTask 4:")
find_secret_byte(ciphertext4)

print("\nTask 5:")
find_secret_byte(ciphertext5)

print("\nTask 6:")
find_secret_byte(ciphertext6)

print("\nTask 7:")
find_secret_byte(ciphertext7)

print("\nTask 8:")
find_secret_byte(ciphertext8)

print("\nTask 9:")
find_secret_byte(ciphertext9)
