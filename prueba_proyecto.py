from cProfile import label
from turtle import width
from Crypto.Cipher import ChaCha20
import json
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from Crypto.Random import get_random_bytes

from matplotlib import pyplot as plt
import numpy as np
import time

#-----------Hashes-----------
#SHA-2 384
#SHA-2 512
#SHA-3 384
#SHA-3 512

#RSA-OAEP 2048
#RSA-PSS 2048
#ECDSA prime field 521
#ECDSA binary field 571

num_exec = 1000000 #total executions


keyChaCha = get_random_bytes(32) #key de 256 para ChaCha20

data = b'data' #message
header = b'header' #for AES-GCM

#---------------------------Encryption----------------------------
def encryptionAES_GCM():
  key = get_random_bytes(32)
  cipher = AES.new(key, AES.MODE_GCM)
  cipher.update(header)
  ciphertext, tag = cipher.encrypt_and_digest(data)

  #This is only for showing coded message purposes
  #json_k = ['nonce','header','ciphertext','tag']
  #json_v = [b64encode(x).decode('utf-8') for x in [cipher.nonce,header,ciphertext,tag]]
  #result = json.dumps(dict(zip(json_k,json_v)))
  #print(result)

def encryptionAES_ECB():
  key = get_random_bytes(32)
  cipher = AES.new(key, AES.MODE_ECB)

  ciphertext = cipher.encrypt(pad(data,32))

  #This is only for showing coded message purposes
  #print(ciphertext)
  
def encryptionChaCha20():
  cipher = ChaCha20.new(key=keyChaCha)
  ciphertext = cipher.encrypt(data)

  #This is only for showing coded message purposes
  #nonce = b64encode(cipher.nonce).decode('utf-8')
  #ct = b64encode(ciphertext).decode('utf-8')
  #print(json.dumps({'nonce':nonce, 'ciphertext':ct}))

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
  print('-------------------------')
  print('---------Cifrado---------')
  print('-------------------------')

  cypherList = ['ChaCha20','AES-GCM','AES-ECB'] #List of algorithms to display in xlabel of graph
  cypherTimes = [] #where our times will be stored


  print('---------Inicio: ChaCha20 para cifrado---------')
  timeChaCha20 = time.perf_counter()
  for x in range(0,num_exec):
    encryptionChaCha20()
  timeChaCha20 = round(time.perf_counter() - timeChaCha20, 4)
  cypherTimes.append(timeChaCha20)
  print('---------Fin: ChaCha20 para cifrado---------\n')

  print('---------Inicio: AES-GCM para cifrado---------')
  timeAESGCM = time.perf_counter()
  for x in range(0,num_exec):
    encryptionAES_GCM()
  timeAESGCM = round(time.perf_counter() - timeAESGCM, 4)
  cypherTimes.append(timeAESGCM)
  print('---------Fin: AES-GCM para cifrado---------\n')

  print('---------Inicio: AES-ECB para cifrado---------')
  timeAESECB = time.perf_counter()
  for x in range(0,num_exec):
    encryptionAES_ECB()
  timeAESECB = round(time.perf_counter() - timeAESECB, 4)
  cypherTimes.append(timeAESECB)
  print('---------Fin: AES-ECB para cifrado---------\n')

  #plot our encryption times
  graphtitle = "Encryption times for " + str(num_exec) + " iterations"
  impresion(cypherList,cypherTimes,graphtitle,'Algorithm','Time in seconds')

  #print('---------Inicio: SHA-2 256 hashing---------')

if __name__ == '__main__':
  main()