Language Used: Python 3.8.3
  - Python was installed through Anaconda installation.
IDE: Atom with python autocorrect.
  - Python was ran in a terminal.
Libraries Used: pycryptodome 3.9.8
  - pycryptodome dome version is in requirements.txt

RSA Signature:
https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_v1_5.html

RSA Encryption:
https://pycryptodome.readthedocs.io/en/latest/src/cipher/oaep.html

RSA Key Generation:
https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html

DES import:
from Crypto.Cipher import DES

RSA PublicKey generation import:
from Crypto.PublicKey import RSA

RSA Encryption import:
from Crypto.Cipher import PKCS1_OAEP

RSA Signature import:
from Crypto.Signature import pkcs1_15

Hash import:
from Crypto.Hash import SHA256

Installation Steps:
You can install python from the main website or through Anaconda (what I use).
To install pycryptodome I used 'pip-install pycryptodome'
Install pip if not already.

Running the code:
*The code will run once upon execution, and automatically complete the required steps then terminate.*
*Also a new CA public key is generated every time when serverCA.py is ran. Can uncomment in __main__ to stop and use current key.*
*Keys are stored in public_keys.*

Open 3 instances of command prompt or terminal.
Run in the following order.
In one instance, run serverCA.py using 'python serverCA.py'.
Wait for it to print waiting for application to connect.
In another instance, run server.py using 'python server.py'.
Wait for steps 1-2 to complete and waiting for client to connect.
In the last instance, run client.py using 'python client.py'.
The remaining steps will now run.
