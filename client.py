import socket
import base64
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from shared_info import SharedInfo

def connect_to_server():
    """
    Client that connects to Application server.
    """
    # With will automatically close the client_socket at the end of the code block.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # Connect to the server using the server host and port.
        client_socket.connect((info.HOST, info.PORT_S))
        outgoing_message = info.ID_Server + str(int(time.time()))
        print("***********************************************************************")
        print("Sent Plaintext:", outgoing_message)
        print("***********************************************************************")
        client_socket.sendall(bytes(outgoing_message, 'utf-8'))
        incoming_message = client_socket.recv(1024)
        parsed_message = info.split_message(incoming_message.decode('utf-8'))
        certificate = parsed_message[1]
        s_public_key = parsed_message[0]
        print('Received Plaintext:', incoming_message.decode('utf-8'))
        print('Parsed Plaintext:', parsed_message)
        print("***********************************************************************")
        if validate_certificate(certificate, s_public_key):
            ktmp2 = info.generate_des_key()
            ciphertext = generate_session_request(s_public_key, ktmp2)
            print('Sent Session Key Request:', base64.b64encode(ciphertext).decode('utf-8'))
            print('Ktmp2:', ktmp2)
            client_socket.sendall(ciphertext)
            print("***********************************************************************")
            ciphertext = client_socket.recv(1024)
            print('Received Ciphertext:', base64.b64encode(ciphertext).decode('utf-8'))
            info.set_des_key(ktmp2.encode('utf-8'))
            plaintext = info.decrypt_message(ciphertext)
            parsed_plaintext = info.split_message(plaintext)
            print("Ksess:", parsed_plaintext[0])

        else:
            client_socket.close()

    print("Connection has been closed.")

def generate_session_request(s_public_key, ktmp2):
    cipher = PKCS1_OAEP.new(RSA.import_key(s_public_key))
    Key = info.prepend_length(ktmp2)
    ID = info.prepend_length(ID_C)
    IP = info.prepend_length(IP_C)
    PORT = info.prepend_length(str(Port_C))
    timestamp = info.prepend_length(str(int(time.time())))
    contents = Key + ID + IP + PORT + timestamp
    return cipher.encrypt(contents.encode('utf-8'))

def validate_certificate(certificate, s_public_key):
    certificate = base64.b64decode(certificate)
    ca_public_key = RSA.import_key(open('./public_keys/ca_public_key.pem').read())
    digest = SHA256.new(info.ID_Server.encode('utf-8') + info.ID_CA.encode('utf-8') + s_public_key.encode('utf-8'))
    try:
        pkcs1_15.new(ca_public_key).verify(digest, certificate)
        print("The signature is valid.")
        return True
    except (ValueError, TypeError):
        print("The signature is not valid.")
        return False

if __name__ == '__main__':
    # Creates the ServerInfo object. A host, port, and key can be passed otherwise it will use the defaults.
    info = SharedInfo()
    ID_C = "ID-Client"
    IP_C = '127.0.0.1'
    Port_C = 5000
    # Connect to server.
    connect_to_server()
