import socket
import base64
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from shared_info import SharedInfo

"""
This file represents the CA Server.
"""

def start_server():
    """
    Start CA server and listen for incoming connections.
        -For the purpose of the lab, the server doesn't run in a loop.
        -When server connects, steps 1-2 are done then CA server closes and terminates.
    """
    # Create INET socket. With will automatically close server socket at the end of code block.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # To avoid the error 'Address already in use'.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind socket to the host and port.
        server_socket.bind((info.HOST, info.PORT_CA))
        print("Waiting for application server to connect...")
        # Listen for incoming connections.
        server_socket.listen()
        # Accept connection from client.
        client_connect, client_addr = server_socket.accept()
        # Client socket will automatically close after end of with block.
        with client_connect:
            print('Server has connected. Address: ', client_addr)
            while True:
                # Receive server registration request from server in Step 1.
                ciphertext = client_connect.recv(1024)
                # Create new cipher object (Uses PKCS1_OAEP) with the CA private key.
                cipher = PKCS1_OAEP.new(ca_private_key)
                plaintext = cipher.decrypt(ciphertext)
                # Parse the plaintext (getting rid of prepended lengths) using split_message().
                registration_request = info.split_message(plaintext.decode('utf-8'))
                print("***********************************************************************")
                print("Step 2 (CA decrypts message from S):")
                print("Received Ciphertext:")
                print(base64.b64encode(ciphertext).decode('utf-8'))
                print("-----------------------------------------------------------------------")
                print("Plaintext(Printed as bytes with prepended length):", plaintext)
                print("Parsed Plaintext:", registration_request)
                print("Received Ktmp1:", registration_request[0])
                print("***********************************************************************")
                # Create new key pair for server.
                new_key_pair = generate_key_pair()
                # Create a certificate for server.
                certificate = generate_certificate(new_key_pair[0])
                encoded_certificate = base64.b64encode(certificate).decode('utf-8')
                # Generate the encrypted message with key pair and certificate to send to server.
                ciphertext = generate_final_message(registration_request[0], new_key_pair, encoded_certificate)

                print("Step 2 (CA sends encrypted key pair and certificate to S):")
                print("Sent Ciphertext:")
                print(ciphertext.decode('utf-8'))
                print("-----------------------------------------------------------------------")
                print("Sent Public Key:")
                print(new_key_pair[0].export_key())
                print("-----------------------------------------------------------------------")
                print("Sent Private Key:")
                print(new_key_pair[1].export_key())
                print("-----------------------------------------------------------------------")
                print("Sent Certificate:")
                print(encoded_certificate)
                print("***********************************************************************")

                client_connect.sendall(ciphertext)
                break
        print("Connection with client ended.")

def generate_final_message(ktmp1, key_pair, certificate):
    """
    Generate the encrypted message containing the key pair and certificate for server.
    """
    # Set DES key to Ktmp1.
    info.set_des_key(bytes(ktmp1, 'utf-8'))
    # Prepend lengths to all components of message.
    public_key = info.prepend_length(base64.b64encode(key_pair[0].export_key()).decode('utf-8'))
    private_key = info.prepend_length(base64.b64encode(key_pair[1].export_key()).decode('utf-8'))
    ID_S = info.prepend_length(info.ID_Server)
    timestamp = info.prepend_length(str(int(time.time())))
    contents = public_key + private_key + info.prepend_length(certificate) + ID_S + timestamp
    return info.encrypt_message(contents)

def generate_certificate(s_public_key):
    """
    Generate the certificate.
        -Sign the message (ID_S + ID_CA + PK_S) using CA private key.
    """
    message = info.ID_Server.encode('utf-8') + info.ID_CA.encode('utf-8') + s_public_key.export_key()
    # Compute SHA256 hash of message.
    digest = SHA256.new(message)
    # Create the certificate by signing the hash (digest) using the CA private key.
    certificate = pkcs1_15.new(ca_private_key).sign(digest)
    return certificate

def generate_key_pair():
    """
    Create a key pair.
    """
    # 2048 bits a sufficient length for the modulus n.
    key = RSA.generate(2048)
    # Get the private key object from key.
    private_key = key
    # Get the public key object from key.
    public_key = key.publickey()
    # Return key pair.
    return (public_key, private_key)

def write_public_key(public_key, name):
    """
    Publish the public key.
        -Writes the public key as a PEM file to folder public_keys.
    """
    publicKeyFile = open('./public_keys/' + name + '_public_key.pem', 'wb')
    publicKeyFile.write(public_key.export_key('PEM'))
    publicKeyFile.close()

if __name__ == '__main__':
    # Creates SharedInfo object. Used to access various functions or shared information between servers and clients.
    info = SharedInfo()
    # Create new CA public key and private key. Returns key pair. Public key is also written to a file.
    key_pair = generate_key_pair()
    # Make CA public key public.
    write_public_key(key_pair[0], 'ca')
    ca_private_key = key_pair[1]
    # Start the CA server.
    start_server()
