import base64
from math import ceil
from base64 import b64decode
from binascii import a2b_base64
from Crypto.Cipher import AES

# Challenge 7
def decrypt_AES_128_ECBmode(text, key):
    return AES.new(key, AES.MODE_ECB).decrypt(text)

# Challenge 9
def pkcs7_pad(text, padded_length):
    if padded_length > len(text):
        pad_amount = padded_length - len(text) % padded_length
    else:
        pad_amount = 0
    return bytes(text.encode()) + (chr(pad_amount)*pad_amount).encode()

# Challenge 8
def Detect_AES_in_ECB(textfile):
    file = open("file.txt", "r")#opening the file in read mode
    if (file):
        print("File Loaded Successfully\n")
        Hexbyte_32 = []
        Hexbyte_16 = []
        n1 = 32
        n = 64
        for i in file:
            if len(i)%64 == 0 or len(i)%32 == 0:#first process dividing with 16 bytes(128 bits) or 32 bytes(256 bits)  In hex 1 digit is 4 bits so dividing by 64 and 32 for 64*4 = 256 bits 32*4 = 128 bits
                Hexbyte_32 = [(i[j:j+n]) for j in range(0, len(i), n)] # dividing the hexcode into 32 bytes and storing in Hexbyte_32
                Hexbyte_16 = [(i[j:j+n]) for j in range(0, len(i), n1)]# dividing the hexcode into 16 bytes and storing in Hexbyte_16
                duplicates = [number for number in Hexbyte_32 if Hexbyte_32.count(number) > 1]
                duplicates1 = [number for number in Hexbyte_16 if Hexbyte_16.count(number) > 1]# second process finding duplicates
                #print(i)# printin the hex-encoded cipher text
                #print(duplicates) #Second process of validation printing the duplicates
            
    file.close()# closing the file
    return i

# Challenge 10
def cbc_encrypt(msg, key, iv):
    padded_msg = pkcs7_pad(msg, block_size)
    msg_blocks = [ padded_msg[i:(i+block_size*2)] for i in range(0, len(padded_msg), block_size*2) ]

    iv_first_block = xor_hex_strings(iv, msg_blocks[0])
    
    (block_0, encryptor) = decrypt_AES_128_ECBmode(bytes.fromhex(iv_first_block), bytes.fromhex(key))
    block_i = block_0
    ctext = [block_i.hex()]
    for msg_block in msg_blocks:
        iv_i = xor_hex_strings(block_i.hex(), msg_block)
        (block_i, encryptor) = decrypt_AES_128_ECBmode(bytes.fromhex(iv_i), bytes.fromhex(key))
        ctext.append(block_i.hex())
    return ''.join(ctext)

def cbc_decrypt(ciphertext, key, iv):
    ctext_blocks = [ ciphertext[i:(i+block_size*2)] for i in range(0, len(ciphertext), block_size*2) ]

    CipherObj = Cipher(algorithms.AES(bytes.fromhex(key)), modes.ECB(), backend=default_backend() )
    iv_i = iv

    decrypted_text = []
    for ctext in ctext_blocks:
        d_i = aes_ecb_decrypt(CipherObj, bytes.fromhex(ctext)).hex()

        decrypted_text.append(xor_hex_strings(iv_i, d_i))
        iv_i = ctext
    return ''.join(decrypted_text[1:])