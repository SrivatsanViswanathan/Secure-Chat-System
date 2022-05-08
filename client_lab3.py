import socket                   # Import socket module
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from PIL import Image
import random
import ast

def key_encrypt(message):
    rsa_public_key = RSA.importKey(B_public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    encrypted = rsa_public_key.encrypt(message)
    return encrypted

def key_encrypt2(message):
    rsa_private_key = RSA.importKey(private_key)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    encrypted = rsa_private_key.encrypt(message)
    return encrypted

def key_decrypt(encrypted):
    rsa_private_key = RSA.importKey(private_key)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    decrypted = rsa_private_key.decrypt(encrypted)
    return decrypted

def nonce_creator():
    length = 8
    nonce = ''
    for i in range(length):
        nonce = nonce + str(random.randint(0,9))
    return nonce

def generate_key():
    key = get_random_bytes(8)
    return key

def encrypt(Plaintext_pad, key):
    nonce = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_OFB, nonce)
    encrypted_message = cipher.encrypt(Plaintext_pad)
    return nonce + encrypted_message

def decrypt(ciphertext, key):
    nonce = ciphertext[:8]
    ciphertext = ciphertext[8:]
    cipher = DES.new(key, DES.MODE_OFB, nonce)
    decrypted_message = cipher.decrypt(ciphertext)
    return nonce + decrypted_message

s = socket.socket()             # Create a socket object
port = 60000                    # Reserve a port for your service.

s.connect(('127.0.0.1', port))

key = RSA.generate(1024)
public_key = key.publickey().exportKey()
private_key = key.exportKey()

s.send(public_key)
B_public_key = s.recv(1024)

# Part 1:
nonce = nonce_creator()
message1 = nonce + 'INITIATOR A'
message1 = str.encode(message1)
encrypted_message1 = key_encrypt(message1)
s.send(encrypted_message1)
print("Message 1: ", message1)
print("Encrypted message 1: ", encrypted_message1)

# Part 2:
encrypted_message2 = s.recv(1024)
message2 = key_decrypt(ast.literal_eval(str(encrypted_message2)))
nonce2 = message2[8:]
print("Received encrypted message 2: ", encrypted_message2)
print("Received message 2: ", message2)

# Part 3:
message3 = nonce2
encrypted_message3 = key_encrypt(message3)
s.send(encrypted_message3)
print("Message 3: ", message3)
print("Encrypted message 3: ", encrypted_message3)

# Part 4:
session_key = generate_key()
message4 = key_encrypt2(session_key)
encrypted_message4 = key_decrypt(message4)
encrypted_message4 = key_encrypt(encrypted_message4)
s.send((encrypted_message4))
print("Session Key: ", session_key)
print("Encrypted message 4: ", encrypted_message4)

# DES Message:
auth_message = s.recv(1024)
print(auth_message)
send = True

file = open("lelouch.jpg", "rb")
image = file.read()
s.send(image)

while send:
    message = input("Please enter a message you want to send to the server: \n")
    encrypted_message = encrypt(message.encode("utf-8"), session_key)
    print("Message: ", message)
    print("Encrypted Message: ", encrypted_message)
    s.send(encrypted_message)
    if message == '0':
        send = False