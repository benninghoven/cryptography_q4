from cryptography.fernet import Fernet
import os
import random


class Message:
    def __init__(self, *, filename, sender, receiver, nonce, content=None):
        self.filename = filename
        self.sender = sender
        self.receiver = receiver
        self.nonce = nonce
        self.content = content

    def __str__(self):
        return f"{self.sender}\n{self.receiver}\n{self.nonce}\n{self.content}"


class User:
    def __init__(self, name):
        self.name = name
        self.master_key = Fernet.generate_key()


def GenNonce():
    return str(random.randint(0, 1000000))


def TransformNonce(nonce):
    nonce = int(nonce)
    return str(nonce + 1)


# 1. Generate Alice's master key Ka.
alice = User(name="Alice")

# 2. Generate Bob's master key KB.
bob = User(name="Bob")

print(f"{'Alices master key':<20} {alice.master_key}")
print(f"{'Bob master key':<20} {bob.master_key}")

# 3. Create directories folders: Alice, Bob, and KDC.
os.makedirs("Alice", exist_ok=True)
os.makedirs("Bob", exist_ok=True)
os.makedirs("KDC", exist_ok=True)

# 4. Create a file containing message (1) from Alice to KDC.
nonce_1 = GenNonce()
msg1 = Message(filename="msg1.txt", sender="Alice", receiver="KDC", nonce=nonce_1)

print("MESSAGE 1")
print(str(msg1))

# Alice saving the message to her directory
with open(f"Alice/{msg1.filename}", "w") as file:
    file.write(str(msg1))

# Alice sending a message to KDC
with open(f"KDC/{msg1.filename}", "w") as file:
    file.write(str(msg1))


# 5. Next, we will simulate the job of the KDC.
# Use openssl to generate a session key Ks based on a random password.
session_key = Fernet.generate_key()

# Encrypt the file using Alice's master key Ka.  The resulting file should be called msg2a.txt.enc.
# Next, put the contents of the message meant for Bob into file msg2b.txt.  Encrypt the file using Bob's master key KB.

msg2a = Message(filename="msg2a.txt", sender="KDC", receiver="Alice", nonce=msg1.nonce, content=session_key.decode())
msg2a_encrypted = Fernet(alice.master_key).encrypt(str(msg2a).encode())

print("PLAIN MESSAGE 2A")
print(str(msg2a))
print("ENCRYPTED MESSAGE 2A")
print(msg2a_encrypted.decode())

msg2b = Message(filename="msg2b.txt", sender="KDC", receiver="Bob", nonce=msg1.nonce, content=session_key.decode())
msg2b_encrypted = Fernet(bob.master_key).encrypt(str(msg2b).encode())

print("PLAIN MESSAGE 2B")
print(str(msg2b))
print("ENCRYPTED MESSAGE 2B")
print(msg2b_encrypted.decode())


# Copy the *.enc files to Alice's directory to represent the act of KDC sending the message to Alice.
with open("Alice/msg2a.txt.enc", "w") as file:
    file.write(msg2a_encrypted.decode())

with open("Alice/msg2b.txt.enc", "w") as file:
    file.write(msg2b_encrypted.decode())


# 5. Have Alice decrypt the part of the message from the KDC that is meant for her.
with open("Alice/msg2a.txt.enc", "r") as file:
    msg2a_encrypted = file.read()

msg2a_decrypted = Fernet(alice.master_key).decrypt(msg2a_encrypted.encode())
print("DECRYPTED MESSAGE 2A")
print(msg2a_decrypted.decode())


# 6. Copy the message that Alice received from the KDC into Bob's directory to represent Alice forwarding the message to Bob.
with open("Bob/msg2b.txt.enc", "w") as file:
    file.write(msg2b_encrypted.decode())

# Similar to the above, simulate the challenge response protocol in steps (4) and (5) of the diagram.  Please do not forget to encrypt the files where appropriate.

# Bob sends a challenge to Alice by sending a new Nonce encrypted with the session key.
# Alice must send back the Nonce through a transformation function to prove that she has the key, and bob
# can verify with the same transformation function. This transformation is crucial to prevent replay attacks, because it proves
# that the receiver has the key and is not just sending back the same message.

# Bob sends this to Alice
nonce_2 = GenNonce()

print("BOB SENDING CHALLENGE TO ALICE")

with open("Alice/challenge_from_bob.txt", "w") as file:
    encrypted_challenge = Fernet(session_key).encrypt(nonce_2.encode())
    file.write(encrypted_challenge.decode())

# Alice's end
with open("Alice/challenge_from_bob.txt", "r") as file:
    bobs_challenge = file.read()

decrypt_nonce = Fernet(session_key).decrypt(bobs_challenge.encode()).decode()
transformed_nonce = TransformNonce(decrypt_nonce)

# Alice sending bob the transformed nonce
with open("Bob/response.txt", "w") as file:
    encrypted_response = Fernet(session_key).encrypt(transformed_nonce.encode())
    file.write(encrypted_response.decode())

# Bob's end
with open("Bob/response.txt", "r") as file:
    decrypted_response = file.read()

transformed_response = Fernet(session_key).decrypt(decrypted_response.encode()).decode()

if int(transformed_response) == int(nonce_2) + 1:
    print("Bob has verified that Alice has the key")
else:
    print("Bob has not verified that Alice has the key")
