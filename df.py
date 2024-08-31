import socket
import threading
from random import randint

# Diffie-Hellman Parameters (prime number and generator)
p = 23   # prime number
g = 5    # generator

# Generate random private key
private_key = randint(2, p - 2)
# Calculate the public key using the formula: g^private_key % p
public_key = pow(g, private_key, p)
# Initialize the shared_secret variable as None
shared_secret = None

# Define a function to calculate the shared secret using the received public_key from the partner
def calculate_shared_secret(public_partner):
    global shared_secret
    shared_secret = pow(public_partner, private_key, p)
    print(f"Shared Secret Calculated: {shared_secret}")

# Define a function to receive the public key from the partner and send the public key
def receive_key_exchange(sock):
    try:
        public_partner = int(sock.recv(1024).decode())
        print(f"Received Public Key from Partner: {public_partner}")
        sock.send(str(public_key).encode())
        calculate_shared_secret(public_partner)
    except Exception as e:
        print(f"Error in receive_key_exchange: {e}")

def send_key_exchange(sock):
    try:
        sock.send(str(public_key).encode())
        print(f"Sent Public Key: {public_key}")
        public_partner = int(sock.recv(1024).decode())
        print(f"Received Public Key from Partner: {public_partner}")
        calculate_shared_secret(public_partner)
    except Exception as e:
        print(f"Error in send_key_exchange: {e}")

# Define a function for sending messages over the socket connection
def sending_messages(sock):
    while True:
        try:
            message = input("")
            encrypted_message = encrypt_message(message)
            sock.send(encrypted_message)
            print("you: " + message)
        except Exception as e:
            print(f"Error in sending_messages: {e}")
            break

# Define a function for receiving messages over the socket connection
def receiving_messages(sock):
    while True:
        try:
            encrypted_message = sock.recv(1024)
            message = decrypt_message(encrypted_message)
            print("partner: " + message)
        except Exception as e:
            print(f"Error in receiving_messages: {e}")
            break

# Define a function to encrypt a message using XOR with the shared_secret
def encrypt_message(message):
    encrypted_message = ""
    for char in message:
        encrypted_char = chr(ord(char) ^ shared_secret)
        encrypted_message += encrypted_char
    return encrypted_message.encode()

# Define a function to decrypt an encrypted message using XOR with the shared_secret
def decrypt_message(encrypted_message):
    decrypted_message = ""
    for char in encrypted_message.decode():
        decrypted_char = chr(ord(char) ^ shared_secret)
        decrypted_message += decrypted_char
    return decrypted_message

# Prompt the user to choose whether to host or connect
choice = input("Do you want to host (1) or connect (2): ")

# If the choice is '1', create a server socket, bind it to a local IP address and port, and listen for incoming connections
if choice == "1":
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 9999))  # Use localhost for testing
        server.listen()
        print("Server listening on 127.0.0.1:9999")
        client, _ = server.accept()
        print("Client connected")
        receive_key_exchange(client)
    except Exception as e:
        print(f"Error in server: {e}")

# If the choice is '2', create a client socket and connect it to the remote IP address and port
elif choice == "2":
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", 9999))  # Use localhost for testing
        print("Connected to server")
        send_key_exchange(client)
    except Exception as e:
        print(f"Error in client: {e}")

# If the choice is neither '1' nor '2', exit the program
else:
    print("Invalid choice, exiting.")
    exit()

# Start two threads for sending and receiving messages simultaneously
try:
    threading.Thread(target=sending_messages, args=(client,)).start()
    threading.Thread(target=receiving_messages, args=(client,)).start()
except Exception as e:
    print(f"Error starting threads: {e}")
