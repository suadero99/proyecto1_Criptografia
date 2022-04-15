from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random


#########################################################
#                GENERACIÓN DE LA CLAVE                 #
#########################################################

# Generar pareja de claves RSA de 2048 bits de longitud
key = RSA.generate(2048)

# Passphrase para encriptar la clave privada
secret_code = "12345"

# Exportamos la clave privada
private_key = key.export_key(passphrase=secret_code)

# Guardamos la clave privada en un fichero
with open("private.pem", "wb") as f:
    f.write(private_key)

# Obtenemos la clave pública
public_key = key.publickey().export_key()

# Guardamos la clave pública en otro fichero
with open("public.pem", "wb") as f:
    f.write(public_key)



message = b'To be signed'
key2 = RSA.import_key(open('private.pem').read(), secret_code)
h = SHA256.new(message)
signature = pss.new(key2).sign(h)

key2 = RSA.import_key(open('public.pem').read(), secret_code)
h = SHA256.new(message)
verifier = pss.new(key2)
try:
    verifier.verify(h, signature)
    print("The signature is authentic.")
except (ValueError, TypeError):
    print("The signature is not authentic.")