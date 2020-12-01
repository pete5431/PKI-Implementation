import socket
import base64
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from shared_info import SharedInfo

"""
This file represents the Application server.
"""

def start_server():
    """
    Start the Application server.
    """
    # Fetch keys and certificate from the information obtained from CA.
    s_public_key = base64.b64decode(registration_info[0])
    s_private_key = base64.b64decode(registration_info[1])
    certificate = registration_info[2]
    # Print the received key pair and certificate from CA.
    print("Server Public Key:")
    print(s_public_key)
    print("-----------------------------------------------------------------------")
    print("Server Private Key:")
    print(s_private_key)
    print("-----------------------------------------------------------------------")
    print("Certificate:")
    print(certificate)
    print("***********************************************************************")
    # Create INET socket. With will automatically close server socket at the end of code block.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # To avoid the error 'Address already in use'.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind socket to the host and port.
        server_socket.bind((info.HOST, info.PORT_S))
        print("Waiting for client to connect...")
        # Listen for incoming connections.
        server_socket.listen()
        # Accept connection from client.
        client_connect, client_addr = server_socket.accept()
        # Client socket will automatically close after end of with block.
        with client_connect:
            print("***********************************************************************")
            print('Client has connected')
            incoming_message = client_connect.recv(1024)
            print("***********************************************************************")
            print('Step 3 (C -> S):')
            print("Received Plaintext:", incoming_message.decode('utf-8'))
            print("***********************************************************************")
            timestamp = info.prepend_length(str(int(time.time())))
            # Generate the message to sent to client in step 4.
            outgoing_message = info.prepend_length(s_public_key.decode('utf-8')) + info.prepend_length(certificate) + timestamp
            print('Step 4 (S -> C, send s public key and certificate):')
            print("Sent Plaintext:")
            print(outgoing_message.encode('utf-8'))
            client_connect.sendall(bytes(outgoing_message, 'utf-8'))
            print("***********************************************************************")
            # Receive the encrypted client identity and network address along with Ktmp2 in step 5.
            ciphertext = client_connect.recv(1024)
            # Decrypt using s private key and obtain Ktmp2 and client id.
            cipher = PKCS1_OAEP.new(RSA.import_key(s_private_key))
            plaintext = cipher.decrypt(ciphertext)
            parsed_plaintext = info.split_message(plaintext.decode('utf-8'))
            ktmp2 = parsed_plaintext[0]
            ID_C = parsed_plaintext[1]
            print('Step 5 (Server receives encrypted client identity/address + Ktmp2):')
            print("Received Session Key Request:", base64.b64encode(ciphertext).decode('utf-8'))
            print("Ktmp2:", ktmp2)
            print("***********************************************************************")
            # Generate the Ksess key.
            ksess = info.generate_des_key()
            # Generate the encrypted message using Ktemp2 to send Ksess to client.
            ciphertext = generate_sent_session(ktmp2, ksess, ID_C)
            print('Step 6 (Send Ksess encrypted using Ktemp2)')
            print("Sent Ciphertext:", ciphertext.decode('utf-8'))
            print("Ksess:", ksess)
            client_connect.sendall(ciphertext)
            print("***********************************************************************")
            # Receive the data request from client in step 7.
            ciphertext = client_connect.recv(1024)
            print('Step 7 (Server receives data request from client):')
            print('Received Service Request:', ciphertext.decode('utf-8'))
            info.set_des_key(ksess.encode('utf-8'))
            plaintext = info.decrypt_message(ciphertext)
            parsed_plaintext = info.split_message(plaintext)
            print('Received Req:', parsed_plaintext[0])
            print("***********************************************************************")
            # Data to be sent to client for step 8.
            data = 'take cis3319 class this morning'
            contents = info.prepend_length(data) + info.prepend_length(str(int(time.time())))
            ciphertext = info.encrypt_message(contents)
            print('Step 8 (S -> C, data to be sent to client):')
            print('Sent Application Data:', ciphertext.decode('utf-8'))
            client_connect.sendall(ciphertext)
            print("***********************************************************************")

        print("Connection with client ended.")

def generate_sent_session(ktmp2, ksess, ID_C):
    """
    Create the message to send the Ksess key by encrypting message with Ktmp2.
    """
    # Set the DES key to be Ktmp2.
    info.set_des_key(ktmp2.encode('utf-8'))
    # Prepend lengths to components of message contents.
    Key = info.prepend_length(ksess)
    ID = info.prepend_length(ID_C)
    Lifetime = info.prepend_length(Lifetime_sess)
    timestamp = info.prepend_length(str(int(time.time())))
    contents = Key + Lifetime + ID + timestamp
    # Use DES to encrypt contents.
    return info.encrypt_message(contents)

def connect_to_CA():
    """
    Application Server connects to CA.
    """
    # With will automatically close the client_socket at the end of the code block.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # Connect to the CA server using the CA server host and port.
        client_socket.connect((info.HOST, info.PORT_CA))
        print("Successfully connected to CA!")
        # Read CA's public key from the shared file.
        ca_public_key = RSA.import_key(open('./public_keys/ca_public_key.pem').read())
        # Create new cipher object (Uses PKCS1_OAEP) with the public key.
        cipher = PKCS1_OAEP.new(ca_public_key)
        # Create a temporary DES key (Ktemp1).
        ktmp1 = info.generate_des_key()
        # Prepend length to each component.
        ID_S = info.prepend_length(info.ID_Server)
        timestamp = info.prepend_length(str(int(time.time())))
        registration_request = info.prepend_length(ktmp1) + ID_S + timestamp
        ciphertext = cipher.encrypt(registration_request.encode('utf-8'))
        print("***********************************************************************")
        print("Step 1 (S -> CA):")
        print("Sent Ciphertext:", base64.b64encode(ciphertext).decode('utf-8'))
        print("Sent Ktmp1:", ktmp1)
        print("***********************************************************************")
        client_socket.sendall(ciphertext)
        # Requires a large buffer size because the keys are quite large.
        ciphertext = client_socket.recv(8192)
        print("Step 2 (Server receives key pair and certificate):")
        print("Received Ciphertext:")
        print(ciphertext.decode('utf-8'))
        print("-----------------------------------------------------------------------")
        info.set_des_key(bytes(ktmp1, 'utf-8'))
        parsed_plaintext = info.split_message(info.decrypt_message(ciphertext))

    return parsed_plaintext

if __name__ == '__main__':
    # Creates SharedInfo object. Used to access various functions or shared information between servers and clients.
    info = SharedInfo()
    # Lifetime of session.
    Lifetime_sess = '86400'
    # Connect to CA server to obtain key pair and certificate.
    registration_info = connect_to_CA()
    # Start up application server with key pair and certificate received from CA, and listens for client connections.
    start_server()
