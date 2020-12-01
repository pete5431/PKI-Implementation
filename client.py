import socket
import base64
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from shared_info import SharedInfo

"""
This file represents the client.
"""

def connect_to_server():
    """
    Client that connects to Application server.
    """
    # With will automatically close the client_socket at the end of the code block.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # Connect to the application server using the application server host and port.
        client_socket.connect((info.HOST, info.PORT_S))
        # Step 3 message that is sent to server.
        outgoing_message = info.ID_Server + str(int(time.time()))
        print("***********************************************************************")
        print('Step 3 (C -> S):')
        print("Sent Plaintext:", outgoing_message)
        print("***********************************************************************")
        client_socket.sendall(bytes(outgoing_message, 'utf-8'))
        # Receive the message from Server in step 4 and parse it. Obtain the certificate and server public key.
        incoming_message = client_socket.recv(1024)
        parsed_message = info.split_message(incoming_message.decode('utf-8'))
        certificate = parsed_message[1]
        s_public_key = parsed_message[0]
        print('Step 4 (S -> C, Received certificate and s public key):')
        print('Received Plaintext:')
        print(incoming_message)
        print("-----------------------------------------------------------------------")
        print('Parsed Plaintext:')
        print(parsed_message)
        print("***********************************************************************")
        # Validate the certificate and public key from server.
        if validate_certificate(certificate, s_public_key):
            # Generate Ktemp2 key.
            ktmp2 = info.generate_des_key()
            ciphertext = generate_session_request(s_public_key, ktmp2)
            print('Step 5 (Send encrypted Ktemp2 and client identity/address using PK_S):')
            print('Sent Session Key Request:')
            print(base64.b64encode(ciphertext).decode('utf-8'))
            print('Ktmp2:', ktmp2)
            client_socket.sendall(ciphertext)
            print("***********************************************************************")
            # Receive the encrypted Ksess key in step 6.
            ciphertext = client_socket.recv(1024)
            print('Step 6 (Client receives encrypted Ksess key):')
            print('Received Ciphertext:', ciphertext.decode('utf-8'))
            # Decrypt message using Ktemp2.
            info.set_des_key(ktmp2.encode('utf-8'))
            plaintext = info.decrypt_message(ciphertext)
            parsed_plaintext = info.split_message(plaintext)
            ksess = parsed_plaintext[0]
            print("Ksess:", ksess)
            print("***********************************************************************")
            # Set the DES key to Ksess.
            info.set_des_key(ksess.encode('utf-8'))
            # Request to be sent to server.
            req = 'memo'
            contents = info.prepend_length(req) + info.prepend_length(str(int(time.time())))
            ciphertext = info.encrypt_message(contents)
            print('Step 7 (C -> S, Send data request):')
            print('Sent Service Request:', ciphertext.decode('utf-8'))
            client_socket.sendall(ciphertext)
            print("***********************************************************************")
            # Receive encrypted data from server in step 8.
            ciphertext = client_socket.recv(1024)
            print('Step 8 (Client receives encrypted data from server):')
            print('Received Application Data:', ciphertext.decode('utf-8'))
            plaintext = info.decrypt_message(ciphertext)
            parsed_plaintext = info.split_message(plaintext)
            print('Received Data:', parsed_plaintext[0])
            print("***********************************************************************")
        else:
            client_socket.close()

    print("Connection has been closed.")

def generate_session_request(s_public_key, ktmp2):
    """
    Generates the session request to the application server for session key.
        -Message contents include client network address.
    """
    cipher = PKCS1_OAEP.new(RSA.import_key(s_public_key))
    Key = info.prepend_length(ktmp2)
    ID = info.prepend_length(ID_C)
    IP = info.prepend_length(IP_C)
    PORT = info.prepend_length(str(Port_C))
    timestamp = info.prepend_length(str(int(time.time())))
    contents = Key + ID + IP + PORT + timestamp
    return cipher.encrypt(contents.encode('utf-8'))

def validate_certificate(certificate, s_public_key):
    """
    Validates the certificate from Server.
        -Uses the same message signed for the certificate to check.
    """
    certificate = base64.b64decode(certificate)
    ca_public_key = RSA.import_key(open('./public_keys/ca_public_key.pem').read())
    # Same message (ID_S + ID_CA + PK_S).
    digest = SHA256.new(info.ID_Server.encode('utf-8') + info.ID_CA.encode('utf-8') + s_public_key.encode('utf-8'))
    try:
        pkcs1_15.new(ca_public_key).verify(digest, certificate)
        print("The signature is valid.")
        return True
    except (ValueError, TypeError):
        print("The signature is not valid.")
        return False

if __name__ == '__main__':
    # Creates SharedInfo object. Used to access various functions or shared information between servers and clients.
    info = SharedInfo()
    # Client ID.
    ID_C = "ID-Client"
    # Client network address.
    IP_C = '127.0.0.1'
    Port_C = 5000
    # Connect to server.
    connect_to_server()
