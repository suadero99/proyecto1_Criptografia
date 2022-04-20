from cProfile import label
from turtle import width
from Crypto.Cipher import ChaCha20
import json
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

from Crypto.Hash import SHA384,SHA512,SHA3_384,SHA3_512

from Crypto.Random import get_random_bytes

from matplotlib import pyplot as plt
import numpy as np
import binascii
import time

num_exec = 1000000 #total executions


keyChaCha = get_random_bytes(32) #key de 256 para ChaCha20

data = b'data' #message for AES_ECB
header = b'header' #for AES-GCM

def timesChaCha20():
  cipher = ChaCha20.new(key=keyChaCha)

  #Time to encrypt
  timeChaCha20encrypt = time.perf_counter()
  ciphertext = cipher.encrypt(data)
  timeChaCha20encrypt = round(time.perf_counter() - timeChaCha20encrypt, 4)

  #Time to decrypt
  timeChaCha20decrypt = time.perf_counter()
  plaintext = cipher.decrypt(ciphertext)
  timeChaCha20decrypt = timeChaCha20decrypt = round(time.perf_counter() - timeChaCha20decrypt, 4)

  #This is only for showing coded message purposes
  #nonce = b64encode(cipher.nonce).decode('utf-8')
  #ct = b64encode(ciphertext).decode('utf-8')
  #print(json.dumps({'nonce':nonce, 'ciphertext':ct}))

  return timeChaCha20encrypt, timeChaCha20decrypt

def timesAES_GCM():
  key = get_random_bytes(32)
  cipher = AES.new(key, AES.MODE_GCM)
  cipher.update(header)

  #Encryption time
  timeAES_GCM_encrypt = time.perf_counter()
  ciphertext,tag = cipher.encrypt_and_digest(data)
  timeAES_GCM_encrypt = round(time.perf_counter() - timeAES_GCM_encrypt, 4)

  #json_k = ['nonce','header','ciphertext','tag']
  #json_v = [b64encode(x).decode('utf-8') for x in [cipher.nonce,header,ciphertext,tag]]
  #result = json.dumps(dict(zip(json_k,json_v)))
  #This is only for showing coded message purposes
  #print(result)

  #Decryption time
  timeAES_GCM_decrypt = time.perf_counter()
  plaintext = cipher.decrypt_and_verify(ciphertext,tag)
  timeAES_GCM_decrypt = round(time.perf_counter() - timeAES_GCM_decrypt, 4)

  return timeAES_GCM_encrypt, timeAES_GCM_decrypt

def timesAES_ECB():
  key = get_random_bytes(32)
  cipher = AES.new(key, AES.MODE_ECB)

  #Time to encrypt
  timeAES_ECB_encrypt = time.perf_counter()
  ciphertext = cipher.encrypt(pad(data,32))
  timeAES_ECB_encrypt = round(time.perf_counter() - timeAES_ECB_encrypt, 4)

  #Time to decrypt
  timeAES_ECB_decrypt = time.perf_counter()
  plaintext = cipher.decrypt(binascii.unhexlify(binascii.hexlify(ciphertext)))
  timeAES_ECB_decrypt = round(time.perf_counter() - timeAES_ECB_decrypt, 4)

  #This is only for showing coded message purposes
  #print(ciphertext)

  return timeAES_ECB_encrypt, timeAES_ECB_decrypt

def timesSHA():
  h = SHA384.new()
  timeSHA2_384 = time.perf_counter()
  h.update(b'data')
  timeSHA2_384 = round(time.perf_counter() - timeSHA2_384,4)
  #print(h.hexdigest())

  h2 = SHA512.new()
  timeSHA2_512 = time.perf_counter()
  h2.update(b'data')
  timeSHA2_512 = round(time.perf_counter() - timeSHA2_512,4)
  #print(h2.hexdigest())

  h_obj = SHA3_384.new()
  timeSHA3_384 = time.perf_counter()
  h_obj.update(b'data')
  timeSHA3_384 = round(time.perf_counter() - timeSHA3_384,4)
  #print(h_obj.hexdigest())

  h_obj2 = SHA3_512.new()
  timeSHA3_512 = time.perf_counter()
  h_obj2.update(b'data')
  timeSHA3_512 = round(time.perf_counter() - timeSHA3_512,4)
  #print(h_obj2.hexdigest())

  return timeSHA2_384,timeSHA2_512,timeSHA3_384,timeSHA3_512

#Graph data vs time
#x and y are lists of our indexes values
#x = algorithm
#y = time
def impresion(x,y,graph_title,x_label,y_label):
  plt.style.use('fivethirtyeight')

  bar_width = 0.25
  x_indexes = np.arange(len(x))

  plt.bar(x_indexes, y, width= bar_width, label = 'a')

  plt.title(graph_title)
  plt.xlabel(x_label)
  plt.ylabel(y_label)

  #plt.legend()

  plt.xticks(ticks = x_indexes, labels = x)
  plt.xticks()

  plt.grid(True)

  plt.tight_layout()

  plt.show()


def main():
  
  #List of algorithms to display in xlabel of graph
  cypherList = ['ChaCha20','AES-GCM','AES-ECB','RSA-OAEP']
  decypherList = ['ChaCha20','AES-GCM','AES-ECB','RSA-OAEP']
  hashingList = ['SHA2-384','SHA2-512','SHA3-384','SHA3-512','ECDSA-Prime','ECDSA-Binary']
  signingList = []
  verifyingList = []
  
  #List of times to display in ylabel of graphs
  #where our times will be stored
  cypherTimes = [] 
  decypherTimes = []
  hashingTimes = []
  signingTimes = []
  verifyingTimes = []

  #variables for time count
  #for ChaCha20:
  timeChaCha20encrypt = 0
  timeChaCha20decrypt = 0
  #for AES_GCM:
  timeAES_GCM_encrypt = 0
  timeAES_GCM_decrypt = 0
  #for AES_ECB
  timeAES_ECB_encrypt = 0
  timeAES_ECB_decrypt = 0
  #for SHAs
  timeSHA2_384 = 0
  timeSHA2_512 = 0
  timeSHA3_384 = 0
  timeSHA3_512 = 0


  print('---------Inicio: ChaCha20---------')
  for x in range(0,num_exec):
    timeChaCha20encrypt,timeChaCha20decrypt += timesChaCha20()
  cypherTimes.append(timeChaCha20encrypt)
  decypherTimes.append(timeChaCha20decrypt)
  print('---------Fin: ChaCha20---------\n')

  print('---------Inicio: AES-GCM---------')
  for x in range(0,num_exec):
    timeAES_GCM_encrypt,timeAES_GCM_decrypt += timesAES_GCM()
  cypherTimes.append(timeAES_GCM_encrypt)
  decypherTimes.append(timeAES_GCM_decrypt)
  print('---------Fin: AES-GCM---------\n')
  
  print('---------Inicio: AES-ECB---------')
  for x in range(0,num_exec):
    timeAES_ECB_encrypt,timeAES_ECB_decrypt += timesAES_ECB()
  cypherTimes.append(timeAES_ECB_encrypt)
  decypherTimes.append(timeAES_ECB_decrypt)
  print('---------Fin: AES-ECB---------\n')

  print('---------Inicio: SHAs---------')
  for x in range(0,num_exec):
    timeSHA2_384,timeSHA2_512,timeSHA3_384,timeSHA3_512 += timesSHA()
  hashingTimes.append(timeSHA2_384)
  hashingTimes.append(timeSHA2_512)
  hashingTimes.append(timeSHA3_384)
  hashingTimes.append(timeSHA3_512)
  print('---------Fin: SHAs---------\n')

  #plot our encryption times
  graphtitle = "Encryption times for " + str(num_exec) + " iterations"
  impresion(cypherList,cypherTimes,graphtitle,'Algorithm','Time in seconds')

  #plot our decryption times
  graphtitle = "Decryption times for " + str(num_exec) + " iterations"
  impresion(decypherList,decypherTimes,graphtitle,'Algorithm','Time in seconds')

  #plot our hashing times
  graphtitle = "Hashing times for " + str(num_exec) + " iterations"
  impresion(hashingList,hashingTimes,graphtitle,'Algorithm','Time in seconds')

if __name__ == '__main__':
  main()