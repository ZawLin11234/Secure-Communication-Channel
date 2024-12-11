import socket
import multiprocessing
import time
from Crypto.PublicKey import DSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes
import binascii
import socket
import json
import random
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import ast
g = 56705145274788493372123339753307414772771433357371590841059782798927812940118223799284337539687371538118367224492351920948228463428961378601039774260709380812918240614378259324865193592687667856241564953729559590183118207565069655961332341295091388304541894289522707219532638077778384996392191249805485470186
p = 105988029256861104653763889357297631951411556959710364172707642322864173648786260017016656400238216846836106619501164850968441147754083671331806946898775858330328972906594018478104370955919114839860988020852327634139963653841544442844199631376655853780184695242469797606145199714957019861497296886048204965777
pk_S = 0
pk_R = 0
sk_S = 0
sk_R = 0
tmp_sks =0
mac_sender = ""
mac_receiver = ""


def encrypt_message(message, key):
    # Using AES in GCM mode for authenticated encryption
    key = key[:32]  # Use only the first 32 bytes for AES-256
    cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the message
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    
    # Get the authentication tag
    tag = encryptor.tag
    
    # Combine the ciphertext and tag for later verification
    encrypted_message = ciphertext + tag
    
    return encrypted_message

def decrypt_message(encrypted_message, key):
    # Extract the ciphertext and tag from the encrypted message
    ciphertext = encrypted_message[:-16]
    tag = encrypted_message[-16:]

    # Using AES in GCM mode for authenticated decryption
    key = key[:32]  # Use only the first 32 bytes for AES-256
    cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 16, tag), backend=default_backend())

    # Create a decryptor
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    # Convert to string
    decrypted_message_str = decrypted_message.decode('utf-8')

    # Remove trailing null bytes
    unpadded_message = decrypted_message_str.rstrip('\x00')

    return unpadded_message



def udp_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((ip, port))

    print(f"Server listening on {ip}:{port}")

    while True:
        data, client_address = server_socket.recvfrom(1024)
        print(f"Received message from {client_address}: {data.decode()}")
        receivedArray = json.loads(data.decode(), object_hook=custom_decoder)
        gr = receivedArray[0]
        C1 = receivedArray[1]
        #print(type(C1))
        C_original = C1.encode('latin1')
        C = C_original
        #C = bytes.fromhex(C1[2:-1])
        MAC = receivedArray[2]
        #print(gr)
        #print(C)
        #print(type(C))
        #print(MAC)
        sk_R = sk_S
        
        TK = pow(gr, sk_R, p)
        #print("Computed TK:", TK)
        #print(pk_S)
        #print(sk_R)
        #print(p)
        # Compute LK = (pk_S)^(sk_R)
        LK = pow(pk_R, sk_R, p)
        # Print the computed LK
        #print("hahaa LK:", LK)
        #print(C)	
        mac_sha1 = compute_mac_sha1(LK, gr, C)
        mac_sender = MAC
        mac_receiver = mac_sha1
        #print(mac_sender)
        #print(mac_receiver)
        #print(mac_sha1)
        TK_bytes = TK.to_bytes((TK.bit_length() + 7) // 8, byteorder='big')
       
        decrypted_message = decrypt_message(C, TK_bytes)
        # Print the decrypted message
        print("MAC is OK" if mac_sender == mac_receiver else "MAC is NOT OK")
        print("Decrypted Message (M'):", decrypted_message)
        
        sk_R = tmp_sks
        # Echo the received message back to the client
        server_socket.sendto(data, client_address)
        
def custom_encoder(obj):
    if isinstance(obj, bytes):
        return {'__bytes__': base64.b64encode(obj).decode('utf-8')}
    raise TypeError("Object of type %s not serializable" % type(obj).__name__)

def custom_decoder(dct):
    if '__bytes__' in dct:
        return base64.b64decode(dct['__bytes__'])
    return dct
    
def compute_mac_sha1(LK, gr, C):
    hash_input = str(LK) + str(gr) + C.hex() + str(LK)
    mac_sha1 = hashlib.sha1(hash_input.encode()).hexdigest()
    return mac_sha1 

def udp_client(server_ip, server_port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        while True:
            message = input("Enter message to send (type 'exit' to quit): ")

            # Check for an empty input
            if not message:
                print("Empty message. Please enter a valid message.")
                continue

            if message.lower() == 'exit':
                print("Exiting...")
                break
               

		
            # Send a message to the server
            # Step 1: Choose a random number r (nonce) from Z_p starting from 2
            r = random.randint(2, p-1)
            # Step 2: Compute g^r
            gr = pow(g, r, p)
            # Step 3: Compute TK = (pk_R)^r
            TK = pow(pk_R, r, p)
            #print("gr:", gr)
            #print("TK:", TK)
            
            # Convert TK to bytes
            TK_bytes = TK.to_bytes((TK.bit_length() + 7) // 8, byteorder='big')
            
            # Step 5: Compute LK = (pk_R)^(sk_s)
            LK = pow(pk_R, sk_S, p)
            #print("LK:", LK)
            
            C = encrypt_message(message, TK_bytes)
            C_str = C.decode('latin1')
            #print(type(C))
            #print(C_str)
            #print("this is C:{C}")
            # Step 6: Compute MAC = H(LK || g^r || C || LK)
            def compute_mac_sha1(LK, gr, C):
            	hash_input = str(LK) + str(gr) + C.hex() + str(LK)
            	mac_sha1 = hashlib.sha1(hash_input.encode()).hexdigest()
            	return mac_sha1
            
            # Assuming LK, gr, and C are available
            mac_sha1 = compute_mac_sha1(LK, gr, C)
            mac_sender = mac_sha1
            
            messageArray = [gr,C_str,mac_sha1]
            serialized_array = json.dumps(messageArray, default=custom_encoder)
            
            message_str = json.dumps(messageArray)
            
            client_socket.sendto(message_str.encode(), (server_ip, server_port))
            print(f"Sent message to {server_ip}:{server_port}: {messageArray}")

            # Receive the echoed message from the server
            data, _ = client_socket.recvfrom(1024)
            print(f"Received echoed message: {data.decode()}")
       
            

    except (EOFError, KeyboardInterrupt):
        # Handle EOFError (Ctrl+D or closed input stream) and KeyboardInterrupt (Ctrl+C)
        print("\nExiting...")
    finally:
        client_socket.close()

if __name__ == "__main__":
    # Ask the user for the file name
    file_name = input("Enter the file name: ")

    # Read user information from the specified file
    try:
        with open(file_name, "r") as file:
            user1_ip = file.readline().strip()
            user1_port = int(file.readline().strip())
            user2_ip = file.readline().strip()
            user2_port = int(file.readline().strip())
            sk_S1 = int(file.readline().strip())
            pk_R1 = int(file.readline().strip())
            pk_S1 = int(file.readline().strip())
            pk_S = pk_S1
            pk_R = pk_R1
            sk_S =sk_S1
            tmp_sks = sk_S1
            server_process = multiprocessing.Process(target=udp_server, args=(user1_ip, user1_port))
        server_process.start()

        # Wait a bit to ensure the server is ready
        time.sleep(1)

        while True:
            # User 1 sends message to User 2
            udp_client(user2_ip, user2_port)

            # User 2 sends message to User 1
            udp_client(user1_ip, user1_port)

            exit_input = input("Do you want to exit? (type 'exit' to quit): ")
            if exit_input.lower() == 'exit':
                break

        server_process.terminate()
    except FileNotFoundError:
        print(f"Error: File '{file_name}' not found.")
    except Exception as e:
        print(f"Error: {e}")
        
        
"""
        # Run the server in a separate process
        server_process = multiprocessing.Process(target=udp_server, args=(user1_ip, user1_port))
        server_process.start()

        # Wait a bit to ensure the server is ready
        time.sleep(1)

        while True:
            # User 1 sends message to User 2
            udp_client(user2_ip, user2_port)

            # User 2 sends message to User 1
            udp_client(user1_ip, user1_port)

            exit_input = input("Do you want to exit? (type 'exit' to quit): ")
            if exit_input.lower() == 'exit':
                break

        server_process.terminate()

    except FileNotFoundError:
        print(f"Error: File '{file_name}' not found.")
    except Exception as e:
        print(f"Error: {e}")
        """
