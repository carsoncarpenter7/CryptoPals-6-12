from random import randint
from base64 import b64encode
from base64 import b64decode
from hashlib import md5 # check this import
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
# from Crypto.Util import pad, unpad (NOT WORKING??)

# PycryptoDome Documentation: https://readthedocs.org/projects/pycryptodome/downloads/pdf/stable/

# Challenge 6
def key_sizes():
    start = 2
    end = 40
    return list(range(start, end + 1))


def ascii_to_bytes(text):
    return bytearray.fromhex(text.encode("utf-8").hex())


def xor_matching(a, b):
    return [a[i] ^ b[i] for i, x in enumerate(a)]


def hamming_distance(a, b):
    xor_bytes = xor_matching(a, b)
    # TODO: Finish


# Challenge 7 (Using Pycryptodome Crypto.Cipher Library)
def decrypt_AES_128_ECBmode(text, key):
    return AES.new(key, AES.MODE_ECB).decrypt(text)


# Challenge 8
def Detect_AES_in_ECB(textfile):
    file = open("file.txt", "r")
    if file:
        print("File Loaded Successfully\n")
        Hexbyte_32 = []
        Hexbyte_16 = []
        n1 = 32
        n = 64
        for hex_encoded in file:
            if (
                len(hex_encoded) % 64 == 0 or len(hex_encoded) % 32 == 0
            ):  # first process dividing with 16 bytes(128 bits) or 32 bytes(256 bits)
                Hexbyte_32 = [
                    (hex_encoded[j : j + n]) for j in range(0, len(hex_encoded), n)
                ]  # dividing the hexcode into 32 bytes and storing in Hexbyte_32
                Hexbyte_16 = [
                    (hex_encoded[j : j + n]) for j in range(0, len(hex_encoded), n1)
                ]  # dividing the hexcode into 16 bytes and storing in Hexbyte_16
                duplicates = [
                    number for number in Hexbyte_32 if Hexbyte_32.count(number) > 1
                ]
                duplicates1 = [
                    number for number in Hexbyte_16 if Hexbyte_16.count(number) > 1
                ]  # second process finding duplicates
                # print(hex_encoded) # print hex-encoded cipher text
                # print(duplicates)

    file.close()
    return hex_encoded


# Challenge 9
def pkcs7_pad(text, padded_length):
    if padded_length > len(text):
        pad_amount = padded_length - len(text) % padded_length
    else:
        pad_amount = 0
    return bytes(text.encode()) + (chr(pad_amount) * pad_amount).encode()
    # return bytes(text.encode('utf-8')) + (chr(pad_amount)*pad_amount).encode()  // TESTING


# Challenge 10
# Resource: https://www.dlitz.net/software/pycrypto/api/2.6/Crypto.Cipher.AES.AESCipher-class.html
class AESCipher:
    def __init__(self, key):
        self.key = md5(key.encode("utf8")).digest()

    def encrypt(self, plaintext):
        block_size = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, block_size)
        return b64encode(
            block_size
            + self.cipher.encrypt(pkcs7_pad(plaintext.encode("utf-8"), AES.block_size))
        )

    def decrypt(self, plaintext):
        text_decrypt = b64decode(plaintext)
        self.cipher = AES.new(self.key, AES.MODE_CBC, text_decrypt[: AES.block_size])
        return unpad(
            self.cipher.decrypt(text_decrypt[AES.block_size :]), AES.block_size
        )


# Challenge 11
def random_key(length):
    key = length
    for i in range(length):
        key[i] = chr(randint(0, 255))
    return key


# Challenge 12
