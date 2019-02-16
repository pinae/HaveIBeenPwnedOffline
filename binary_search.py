#!/usr/bin/python3
# -*- coding: utf-8 -*-
from __future__ import division, print_function, unicode_literals
from hashlib import sha1
from os import stat
from argparse import ArgumentParser
from getpass import getpass
import signal

def handler(signum, frame):
    print('\nCtrl-C pressed')
    exit(0)

def binary_search(hex_hash, list_file, file_size):
    def get_full_line(file, pos):
        file.seek(pos)
        while pos > 0 and file.read(1) != "\n":
            pos -= 1
            file.seek(pos)
        return file.readline(), pos

    def search_hash(file, my_hash, start, end):
        if start >= end:
            return 0
        new_pos = start + (end - start) // 2
        candidate_line, pivot = get_full_line(file, new_pos)
        # print("Trying line at pos {:11d}: \"{}\" (pivot position: {})".format(
        #     new_pos, candidate_line.strip(), pivot))
        pwned_hash, count = candidate_line.split(':')
        if pwned_hash == my_hash:
            print("Password found at byte {:11d}: \"{}\"".format(pivot, candidate_line.strip()))
            return int(count.strip())
        if my_hash > pwned_hash:
            return search_hash(file, my_hash, file.tell(), end)
        else:
            return search_hash(file, my_hash, start, pivot)

    return search_hash(list_file, hex_hash, 0, file_size)

def check_pass(password, display_pass=True):
    if 'decode' in dir(str):
        password = password.decode('utf-8')
    encodings = ['utf-8', 'latin', 'iso8859-15', 'iso8859-1']
    hashes = []
    for encoding in encodings:
        try:
            hash_candidate = sha1(password.encode(encoding)).hexdigest().upper()
            if hash_candidate not in hashes:
                hashes.append(hash_candidate)
        except UnicodeEncodeError:
            continue
    count = 0
    for h in hashes:
        if  display_pass==True:
            print("Searching for hash {} of password \"{}\".".format(h, password))
            count += binary_search(h, pwned_passwords_file, pwned_passwords_file_size)
            if count > 0:
                print("Your password \"{}\" was in {} leaks or hacked databases!".format(password, count) +
                      " Please change it immediately.")
            else:
                print("Your password \"{}\" is not in the dataset. You may relax.".format(password))
        else:
            print("Searching for hash {} of password".format(h))
            count += binary_search(h, pwned_passwords_file, pwned_passwords_file_size)
            if count > 0:
                print("Your password was in {} leaks or hacked databases!".format(count) +
                      " Please change it immediately.")
            else:
                print("Your password is not in the dataset. You may relax.")


if __name__ == "__main__":
    parser = ArgumentParser(description='Test passwords locally.' +
                                        ' Each password you pass as an argument will be hashed and this script' +
                                        ' will search for the hash in the list.')
    parser.add_argument('passwords', nargs='*')
    parser.add_argument('-f', '--pwned-passwords-ordered-by-hash-filename', dest='password_file', required=False,
                        default="pwned-passwords-sha1-ordered-by-hash-v4.txt", help='use a different password file')
    parser.add_argument('-i', '--interactive', dest='interactive', action='store_true', required=False, help='ask for password(s) interactively.')
    args = parser.parse_args()
    with open(args.password_file, 'r') as pwned_passwords_file:
        pwned_passwords_file_size = stat(args.password_file).st_size
        #print("File size: {} Bytes".format(pwned_passwords_file_size))
        if (args.interactive==False) and (len(args.passwords) == 0):
            print ("No passwords given as argument.\n")
        for password in args.passwords:
            print("")
            check_pass(password)
        if args.interactive==True:
            print("\nNow running in interactive mode; passwords are not displayed\nEnter empty password or press Ctrl-C to exit.")
            signal.signal(signal.SIGINT, handler)
            while True:
                password=getpass('\nPassword: ')
                if(password==''):
                    exit(0)
                check_pass(password, False)
