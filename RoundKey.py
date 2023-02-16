def shiftKey(key):
    new_key = [0 for x in range(4)]
    for i in range(4):
        new_key[i] = key[(i+1)%4]
    return new_key

def subKey(word, sbox):
    new_word = [0 for x in range(4)]
    for i in range(4):
        new_word[i] = sbox["0x{:02x}".format(int(word[i], 16))]    
    return ["0x{:02x}".format(int(elem, 16)) for elem in new_word]

def g(word, sbox, rcon):
    new_word = [0 for x in range(4)]
    word = shiftKey(word)
    word = subKey(word, sbox)
    for i in range(4):
        new_word[i] = hex(int(word[i], 16)^int(rcon[i],16))

    return ["0x{:02x}".format(int(elem, 16)) for elem in new_word]

#Expands a 128-bit key into a set of round keys for AES encryption.
def keyGeneration(key, sbox):
    key_arr = [[0 for x in range(4)] for x in range(44)]
    rcon = [['0x01', '0x00', '0x00', '0x00'], 
            ['0x02', '0x00', '0x00', '0x00'], 
            ['0x04', '0x00', '0x00', '0x00'],
            ['0x08', '0x00', '0x00', '0x00'],
            ['0x10', '0x00', '0x00', '0x00'],
            ['0x20', '0x00', '0x00', '0x00'],
            ['0x40', '0x00', '0x00', '0x00'],
            ['0x80', '0x00', '0x00', '0x00'],
            ['0x1b', '0x00', '0x00', '0x00'],
            ['0x36', '0x00', '0x00', '0x00']]

    for i in range(4):
        for j in range(4):
            key_arr[i][j] = key[i][j]
    
    for i in range(4,44,4):
        x = g(key_arr[i-1], sbox, rcon[(i//4)-1])
        for k in range(4):
            for j in range(4):
                if (k == 0):
                    key_arr[i+k][j] = int(key_arr[i+k-4][j], 16)^int(g(key_arr[i-1], sbox, rcon[(i//4)-1])[j], 16)
                else:
                    key_arr[i+k][j] = int(key_arr[i+k-1][j], 16)^int(key_arr[i+k-4][j], 16)
                key_arr[i+k][j] = "0x{:02x}".format(key_arr[i+k][j])
    return key_arr