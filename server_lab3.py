import socket                   # Import socket module
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from PIL import Image
import random
import ast

port = 60000                    # Reserve a port for your service.
s = socket.socket()             # Create a socket object
host = socket.gethostname()     # Get local machine name
print(host)
s.bind(('127.0.0.1', port))     # Bind to the port
s.listen(5)                     # Now wait for client connection.

def key_encrypt(message):
    rsa_public_key = RSA.importKey(A_public_key)
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

def encrypt(Plaintext_pad, key):
    nonce = get_random_bytes(8)
    cipher = DES.new(key.encode(), DES.MODE_OFB, nonce)
    encrypted_message = cipher.encrypt(Plaintext_pad.encode())
    return nonce + encrypted_message

def decrypt(ciphertext, key):
    nonce = ciphertext[:8]
    ciphertext = ciphertext[8:]
    cipher = DES.new(key, DES.MODE_OFB, nonce)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message

key = RSA.generate(1024)
public_key = key.publickey().exportKey()
private_key = key.exportKey()

conn, addr = s.accept()     # Establish connection with client.

conn.send(public_key)
A_public_key = conn.recv(1024)

# Part 1:
encrypted_message1 = conn.recv(1024)
message1 = key_decrypt(ast.literal_eval(str(encrypted_message1)))
nonce1 = message1.decode("utf-8")[:8]
print("Received encrypted message 1: ", encrypted_message1)
print("Received message 1: ", message1)

# Part 2:
nonce2 = nonce_creator()
message2 = nonce1 + nonce2
encrypted_message2 = key_encrypt(message2.encode("utf-8"))
conn.send(encrypted_message2)
print("Message 2: ", message2)
print("Encrypted message 2: ", encrypted_message2) 

# Part 3:
encrypted_message3 = conn.recv(1024)
message3 = key_decrypt(ast.literal_eval(str(encrypted_message3)))
print("Received encrypted message 3: ", encrypted_message3)
print("Received message 3: ", message3)

# Part 4:
encrypted_message4 = conn.recv(1024)
message4 = key_decrypt(ast.literal_eval(str(encrypted_message4)))
session_key = key_encrypt2(message4)
session_key = key_decrypt(session_key)
print("Received encrypted message 4: ", encrypted_message4)
print("Received session key: ", session_key)



# DES Messaging:
receive = True
conn.send(bytes("Messaging Application:", "utf-8"))

file = open("img.jpg", "wb")
image = conn.recv(170000)
file.write(image)
img = Image.open("img.jpg")
img.show()

print("Messaging Application:")
while receive:
    encrypted_message = conn.recv(1024)
    print("Received encrypted message: ", encrypted_message)
    message = decrypt(encrypted_message, session_key)
    print("Client sent: ", message)

    if message == '0':
        receive = False