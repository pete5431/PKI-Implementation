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

    print("Server Public Key:", s_public_key)
    print("Server Private Key:", s_private_key)
    print("Certificate:", certificate)

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
            print('Client has connected. Address: ', client_addr)
            incoming_message = client_connect.recv(1024)
            print("Received Plaintext:", incoming_message.decode('utf-8'))
            print("***********************************************************************")
            timestamp = info.prepend_length(str(int(time.time())))
            outgoing_message = info.prepend_length(s_public_key.decode('utf-8')) + info.prepend_length(certificate) + timestamp
            print("Sent Plaintext:", outgoing_message)
            client_connect.sendall(bytes(outgoing_message, 'utf-8'))

            print("***********************************************************************")
            ciphertext = client_connect.recv(1024)
            cipher = PKCS1_OAEP.new(RSA.import_key(s_private_key))
            plaintext = cipher.decrypt(ciphertext)
            parsed_plaintext = info.split_message(plaintext.decode('utf-8'))
            ktmp2 = parsed_plaintext[0]
            ID_C = parsed_plaintext[1]
            print("Received Session Key Request:", base64.b64encode(ciphertext).decode('utf-8'))
            print("Ktmp2:", ktmp2)
            print("***********************************************************************")
            ksess = info.generate_des_key()
            ciphertext = generate_sent_session(ktmp2, ksess, ID_C)
            print("Sent Ciphertext:", base64.b64encode(ciphertext).decode('utf-8'))
            print("Ksess:", ksess)
            client_connect.sendall(ciphertext)

        print("Connection with client ended.")

def generate_sent_session(ktmp2, ksess, ID_C):
    info.set_des_key(ktmp2.encode('utf-8'))
    Key = info.prepend_length(ksess)
    ID = info.prepend_length(ID_C)
    Lifetime = info.prepend_length(info.Lifetime_sess)
    timestamp = info.prepend_length(str(int(time.time())))
    contents = Key + Lifetime + ID + timestamp
    return info.encrypt_message(contents)

def connect_to_CA():
    """
    Application Server connects to CA.
    """
    # With will automatically close the client_socket at the end of the code block.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # Connect to the server using the server host and port.
        client_socket.connect((info.HOST, info.PORT_CA))
        print("Successfully connected to CA!")
        # Read CA's public key from the shared file.
        ca_public_key = RSA.import_key(open('./public_keys/ca_public_key.pem').read())
        # Create new cipher object (Uses PKCS1_OAEP) with the public key.
        cipher = PKCS1_OAEP.new(ca_public_key)
        # Create a temporary DES key (Ktemp1).
        temp_DES_key = info.generate_des_key()
        ID_S = info.prepend_length(info.ID_Server)
        timestamp = info.prepend_length(str(int(time.time())))
        registration_request = info.prepend_length(temp_DES_key) + ID_S + timestamp
        ciphertext = cipher.encrypt(registration_request.encode('utf-8'))
        print("***********************************************************************")
        print("Sent Ciphertext:", base64.b64encode(ciphertext).decode('utf-8'))
        print("Sent Ktmp1:", temp_DES_key)
        print("***********************************************************************")
        client_socket.sendall(ciphertext)

        ciphertext = client_socket.recv(5048)

        print("Received Ciphertext:")
        print("________________________________________________________________________")
        print(base64.b64encode(ciphertext).decode('utf-8'))
        print("________________________________________________________________________")

        info.set_des_key(bytes(temp_DES_key, 'utf-8'))
        parsed_plaintext = info.split_message(info.decrypt_message(ciphertext))
    return parsed_plaintext

if __name__ == '__main__':
    # Creates SharedInfo object. Used to access various functions or shared information between servers and clients.
    info = SharedInfo()

    # Connect to CA server to obtain key pair and certificate.
    registration_info = connect_to_CA()

    # Start up application server with key pair and certificate received from CA, and listens for client connections.
    start_server()
