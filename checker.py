# a script that checks whether the program can travel over all possible passwords

import os
import subprocess
import re

def generate_zip(password):
    # generate a zip file with the given password
    # encryption method: AES-256
    # compression method: zip
    # password: password
    command = "./a.out test.zip {}".format(password)
    subprocess.run(command, shell=True)

def decrypt_zip(password_len):
    # decrypt the zip file with the given password
    # password: password
    command = "./a.out test.zip {}".format(password_len)
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def main():
    max_password = 99999
    for i in range(max_password + 1):
        password = f"{i:05d}"
        print(f"checking password: {password}")
        generate_zip(password)
        result = decrypt_zip(5)
        print(result)

if __name__ == "__main__":
    main()