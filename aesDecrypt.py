from RoundKey import *
from InvSbox import *
from sbox import *

#Substitutes each byte of a word with a corresponding byte from the AES Inverse S-box.
def InvSubstitution(sbox, state_array):
    new_state_array = [[0 for x in range(4)] for x in range(4)]
    for i in range(4):
        for j in range(4):
            new_state_array[i][j] = inv_sbox[state_array[i][j]]
    return new_state_array

#Performs a circular right shift of the bytes in a word.
def InvShiftRows(state_array):
    new_state_array = [[0 for x in range(4)] for x in range(4)]
    for i in range(4):
        for j in range(4):
            new_state_array[i][(j+i)%4] = state_array[i][j]
    return new_state_array

#Each column of the state matrix is multiplied by a fixed polynomial matrix using Galois field arithmetic
def InvMixColumns(B):
    A = [['0x0e', '0x0b', '0x0d', '0x09'], ['0x09', '0x0e', '0x0b', '0x0d'], ['0x0d', '0x09', '0x0e', '0x0b'], ['0x0b', '0x0d', '0x09', '0x0e']]
    C = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
    for i in range(4):
        for j in range(4):
            for k in range(4):
                C[i][j] ^= gf_2_3_hex_mult(int(A[i][k], 16), int(B[k][j], 16))
    return [["0x{:02x}".format(elem) for elem in row] for row in C]


def gf_2_3_hex_mult(a, b):
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        a &= 0xff
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p

#Perform XOR operation with the state array and key
def addRoundKey(state_array, key):
    new_state_array = [[0 for x in range(4)] for x in range(4)]
    for i in range(4):
        for j in range(4):
            new_state_array[i][j] = hex(int(state_array[i][j],16)^int(key[j][i],16))
    return [["0x{:02x}".format(int(elem, 16)) for elem in row] for row in new_state_array]



#Decrypts a ciphertext using the AES decryption algorithm with a 128-bit key
def decrypt(ciphertext, keytext):
    hex_key = keytext.encode().hex()
    ciphertext_array = [[0 for x in range(4)] for x in range(4)]
    key_array = [[0 for x in range(4)] for x in range(4)]

    i=0
    for j in range(4):
        for k in range(4):
            ciphertext_array[k][j] = "0x{:02x}".format(int(ciphertext[i:i+2], 16))
            key_array[j][k] =  "0x{:02x}".format(int(hex_key[i:i+2], 16))
            i += 2

    keys = keyGeneration(key_array, sbox)

    state_array = addRoundKey(ciphertext_array, keys[40:44])
    j = 36

    for i in range(9):
        state_array = InvShiftRows(state_array)
        state_array = InvSubstitution(inv_sbox, state_array)
        state_array = addRoundKey(state_array, keys[j:j+4])
        state_array = InvMixColumns(state_array)        
        j -= 4
    
    
    state_array = InvShiftRows(state_array)
    state_array = InvSubstitution(inv_sbox, state_array)
    state_array = addRoundKey(state_array, keys[j:j+4])

    hex_plaintext = ""
    for i in range(4):
        for j in range(4):
            hex_plaintext += state_array[j][i][2:]
    
    return hex_plaintext