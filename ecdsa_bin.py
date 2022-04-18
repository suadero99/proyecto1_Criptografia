from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(ec.SECT571R1())

data = b"this is some data I'd like to sign"

signature = private_key.sign(data,ec.ECDSA(hashes.SHA256()))
print(signature)