from aesEncrypt import *
from aesDecrypt import *

plaintext = input('Enter plaintext: ')
key = input('Enter 128 bit key: ')

if (len(plaintext)!=16 or len(key)!=16):
    print('Input Data and key must be 32 hex digits long.')
else:
    ciphertext = encrypt(plaintext, key)
    decrypted_text = decrypt(ciphertext, key)
    print("\nCipher Text: ", ciphertext)
    print("Inverse Cipher Text: ", decrypted_text)
    print("Decrypted Text: ", bytes.fromhex(decrypted_text).decode('utf-8'))
