import os
import oqs
import tkinter
import tkinter.filedialog
import tkinter as tk
from pathlib import Path
import hashlib
import oqs.rand as rand
import time
import secrets
from pqcrypto.kem.mceliece8192128 import generate_keypair




kemalg1 = "SIKE-p751-compressed"
kemalg2 = "FrodoKEM-1344-SHAKE"
kemalg3 = "HQC-256"
kemalg4 = "sntrup1277"
kemalg5 = "Classic-McEliece-8192128"

#Gather entropy for use in key generation for all algorithms
print ("Input text entropy:")
entropy = bytearray(input().encode())

seed1 = (hashlib.blake2b(bytearray(secrets.token_bytes(128))+entropy+bytearray(hex(int(time.time_ns())), 'utf-8')).digest())[:48]
seed2 = (hashlib.blake2b(bytearray(secrets.token_bytes(128))+entropy+bytearray(hex(int(time.time_ns())), 'utf-8')).digest())[:48]
seed3 = (hashlib.blake2b(bytearray(secrets.token_bytes(128))+entropy+bytearray(hex(int(time.time_ns())), 'utf-8')).digest())[:48]
seed4 = (hashlib.blake2b(bytearray(secrets.token_bytes(128))+entropy+bytearray(hex(int(time.time_ns())), 'utf-8')).digest())[:48]
seed5 = (hashlib.blake2b(bytearray(secrets.token_bytes(128))+entropy+bytearray(hex(int(time.time_ns())), 'utf-8')).digest())[:48]

#KeyGen 1
rand.randombytes_nist_kat_init_256bit(seed1)
rand.randombytes_switch_algorithm("NIST-KAT")

client1 = oqs.KeyEncapsulation(kemalg1)
publickey1 =client1.generate_keypair()
secretkey1 = client1.export_secret_key()

#KeyGen 2
rand.randombytes_nist_kat_init_256bit(seed2)

client2 = oqs.KeyEncapsulation(kemalg2)
publickey2 =client2.generate_keypair()
secretkey2 = client2.export_secret_key()

#KeyGen 3
rand.randombytes_nist_kat_init_256bit(seed3)

client3 = oqs.KeyEncapsulation(kemalg3)
publickey3 =client3.generate_keypair()
secretkey3 = client3.export_secret_key()

#KeyGen 4
rand.randombytes_nist_kat_init_256bit(seed4)

client4 = oqs.KeyEncapsulation(kemalg4)
publickey4 =client4.generate_keypair()
secretkey4 = client4.export_secret_key()

#KeyGen 5 - McEliece
rand.randombytes_nist_kat_init_256bit(seed5)
client5 = oqs.KeyEncapsulation(kemalg5)
publickey5 =client5.generate_keypair()
secretkey5 = client5.export_secret_key()

print ("Save Publickey:")
tk.Tk().withdraw()
t = tkinter.filedialog.asksaveasfile(mode="wb", title="Save Public Key")
t.write(publickey1+publickey2+publickey3+publickey4+publickey5)
tkinter.Tk().withdraw()

print ("Save Secretkey:")
tk.Tk().withdraw()
t = tkinter.filedialog.asksaveasfile(mode="wb", title="Save Secret Key")
t.write(secretkey1+secretkey2+secretkey3+secretkey4+secretkey5)
tkinter.Tk().withdraw()
