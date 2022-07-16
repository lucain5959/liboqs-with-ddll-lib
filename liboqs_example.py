import oqs
from base64 import b64encode
import secrets

kemalg1 = "SIKE-p751-compressed"
client = oqs.KeyEncapsulation(kemalg1)
publickey1 =client.generate_keypair()
secretkey1 = client.export_secret_key()

print ("Public key:", b64encode(publickey1).decode())
print ()
print ("Secret Key:",  b64encode(secretkey1).decode())