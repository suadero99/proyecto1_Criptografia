from Crypto.Cipher import ChaCha20
import json
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from Crypto.Random import get_random_bytes

import matplotlib.pyplot
import time


#variables para cada cifrado
#CHACHA20 256
#AES-ECB 256
#AES-GCM 256

#-----------Hashes-----------
#SHA-2 384
#SHA-2 512
#SHA-3 384
#SHA-3 512

#RSA-OAEP 2048
#RSA-PSS 2048
#ECDSA prime field 521
#ECDSA binary field 571

num_exec = 10 #total executions


keyChaCha = get_random_bytes(32) #key de 256 para ChaCha20

data = b'data' #message
header = b'header' #for AES-GCM

def encryptionAES_GCM():
  key = get_random_bytes(32)
  cipher = AES.new(key, AES.MODE_GCM)
  cipher.update(header)
  ciphertext, tag = cipher.encrypt_and_digest(data)

  #This is only for showing coded message purposes
  json_k = ['nonce','header','ciphertext','tag']
  json_v = [b64encode(x).decode('utf-8') for x in [cipher.nonce,header,ciphertext,tag]]
  result = json.dumps(dict(zip(json_k,json_v)))
  print(result)

def encryptionAES_ECB():
  key = get_random_bytes(32)
  cipher = AES.new(key, AES.MODE_ECB)

  ciphertext = cipher.encrypt(pad(data,32))

  #This is only for showing coded message purposes
  print(ciphertext)
  
def encryptionChaCha20():
  cipher = ChaCha20.new(key=keyChaCha)
  ciphertext = cipher.encrypt(data)

  #This is only for showing coded message purposes
  nonce = b64encode(cipher.nonce).decode('utf-8')
  ct = b64encode(ciphertext).decode('utf-8')
  print(json.dumps({'nonce':nonce, 'ciphertext':ct}))

def main():
  print('---------Inicio: ChaCha20 para cifrado---------')
  for x in range(0,num_exec):
    encryptionChaCha20()
  print('---------Fin: ChaCha20 para cifrado---------\n')

  print('---------Inicio: AES-GCM para cifrado---------')
  for x in range(0,num_exec):
    encryptionAES_GCM()
  print('---------Fin: AES-GCM para cifrado---------\n')

  print('---------Inicio: AES-ECB para cifrado---------')
  for x in range(0,num_exec):
    encryptionAES_ECB()
  print('---------Fin: AES-ECB para cifrado---------\n')

  print('---------Inicio: SHA-2 256 hashing---------')

if __name__ == '__main__':
  main()