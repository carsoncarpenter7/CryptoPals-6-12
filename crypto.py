#!/usr/bin/env python3
#
# Carson Carpenter
# CPSC 353
# carson.carpenter7@csu.fullerton.edu
#
# chmod ugo+x crypto.py
# ./crypto.py
"""
This is my CryptoPal Challenges 6 - 12!
"""
# Added Imports
import base64
from base64 import b64decode
from binascii import a2b_base64
from random import randint
import os
from Crypto.Cipher import AES
# Import Functions from file
from crypto_functions import decrypt_AES_128_ECBmode, pkcs7_pad, Detect_AES_in_ECB
    
def main():
    """ This is my Main Challenge function. """
    
    print("==== Crypto Challenges Part 1 === \n")
    print("========== Challenge 6 ==========")
    print("========== Challenge 7 ==========")
    KEY = "YELLOW SUBMARINE"
    file = 'file7.txt'
    text = ""
    for line in open(file):
        text += line.strip()
    text = a2b_base64(text)
	# TODO: implement without built-in func
    decoded_data = decrypt_AES_128_ECBmode(text, KEY)
    print ("Decrypting AES-128 using Key '{}': \n{}\n".format(KEY, decoded_data))

    
    print("========== Challenge 8 ==========")
    file = "file.txt"
    print("Detecting AES in ECB: {} \n".format(Detect_AES_in_ECB(file)))
    
    print("\n==== Crypto Challenges Part 2 === \n")
    
    print("========== Challenge 9 ==========")
    input_text = "YELLOW SUBMARINE"
    print("Padding to 20 bytes: {} \n".format(pkcs7_pad(input_text, 20)))
    
    print("========== Challenge 10 ==========")
    
    print("========== Challenge 11 ==========")
    print("========== Challenge 12 ==========")


if __name__ == '__main__':
    main()