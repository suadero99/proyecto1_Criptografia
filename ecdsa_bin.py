from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(ec.SECT571R1())
#Llave publica para verificar 
public_key = private_key.public_key()

data = b"this is some data I'd like to sign"

signature = private_key.sign(data,ec.ECDSA(hashes.SHA256()))
print(signature)

#Verificacion
public_key.verify(signature,data,ec.ECDSA(hashes.SHA256()))
