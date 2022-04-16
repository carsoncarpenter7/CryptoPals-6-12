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
from binascii import a2b_base64

# Import Functions from file
from crypto_functions import (
    decrypt_AES_128_ECBmode,
    pkcs7_pad,
    Detect_AES_in_ECB,
    AESCipher,
    key_sizes,
    ascii_to_bytes,
    xor_matching,
    hamming_distance,
    random_key
)


def main():
    """This is my Main Challenge function."""

    print("==== Crypto Challenges Part 1 ===")
    print("========== Challenge 6 ==========")
    file = open("file6.txt", "r")
    for i in file:
        # TODO: FIND KEY with function
        # key = min_haming distance(i)
        i = file.readlines()  # placeholder for now
        key = 0  # placeholder for now

    print("Key: {}".format(key))
    print("Breaking Repeating Key XOR: \n")

    # TODO: create function
    # decrypted = break_repeating_xor(i, key)
    print(
        "This challenge is not yet complete and requires additional functions to execute properly."
    )
    print(
        "Please Ignore printed results as they are placeholders for program execution.\n"
    )

    print("========== Challenge 7 ==========")
    KEY = "YELLOW SUBMARINE"
    file = "file7.txt"
    text = ""
    for line in open(file):
        text += line.strip()
    text = a2b_base64(text)
    # TODO/TRY: implement without built-in func
    print("\n IF FUNCTION BELOW RAISES STRING ERROR COMMENT OUT TO TEST OTHER CHALLENGES \n")
    decoded_data = decrypt_AES_128_ECBmode(text, KEY)
    print("Decrypting AES-128 using Key '{}': \n{}\n".format(KEY, decoded_data))

    print("========== Challenge 8 ==========")
    file = "file.txt"
    print("Detecting AES in ECB: {} \n".format(Detect_AES_in_ECB(file)))

    print("\n==== Crypto Challenges Part 2 ===")

    print("========== Challenge 9 ==========")
    input_text = "YELLOW SUBMARINE"
    print("Padding to 20 bytes: {} \n".format(pkcs7_pad(input_text, 20)))

    print("========== Challenge 10 ==========")
    print("Implement CBC mode:")
    with open("file10.txt", "r") as myfile:
        cte = myfile.readlines()
    message = cte
    key = "YELLOW SUBMARINE"
    # print('Decrypted:', AESCipher(key).encrypt(message).decode('utf-8'))
    print(
        "This class/function call has been commented out due to errors and to allow for program execution."
    )
    print(
        "The code can be viewed in crypto_functions.py (Bug: pad and unpad imports from Pycryptodome not recognized).\n"
    )

    print("========== Challenge 11 ==========")
    print("This challenge is not complete. Scroll up to see other challenges.\n ")

    print("========== Challenge 12 ==========")
    print("This challenge is not complete. Scroll up to see other challenges.")


if __name__ == "__main__":
    main()
