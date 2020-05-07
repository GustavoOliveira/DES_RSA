from des import DesKey
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import new as Random
from base64 import b64encode
from base64 import b64decode

import time
import os

class Cipher:
  def generate_key(self,key_lengthRSA, key_lengthDES):
    inicio = time.time()

    # Gera chave DES
    if (key_lengthDES == 8):
        DESkey = ("8bt__key")                
    elif (key_lengthDES == 16):
        DESkey = ("16bt_key__TRIPLE")          
    elif (key_lengthDES == 24):
        DESkey = ("a 24-byte key for TRIPLE")  

    with open('DES.key', 'w') as arquivo:
        arquivo.write(str(DESkey))

    # Gera chave RSA  
    assert key_lengthRSA in [1024,2048,4096]
    rng = Random().read
    self.key = RSA.generate(key_lengthRSA,rng)
    extKey = self.key.exportKey()

    with open('pvt.key', 'w') as arquivo:
        arquivo.write(extKey.decode("utf-8"))

    fim = time.time()
    tempo = fim - inicio
    return tempo


  def setKey(self):  
    with open('pvt.key') as arquivo:
        extRSAKey = arquivo.read()
    
    with open('DES.key') as arquivo:
        extDESKey = arquivo.read()

    self.RSAkey = RSA.importKey(extRSAKey)
    self.DESKey = extDESKey

  def encrypt(self,data):
    inicio = time.time()

    Cipher.setKey(self)
    DES = DesKey(self.DESKey.encode())
    plaintext =  DES.encrypt(data.encode(), padding=True) 

    rsa_encryption_cipher = PKCS1_v1_5.new(self.RSAkey)
    ciphertext = rsa_encryption_cipher.encrypt(plaintext)
    fim = time.time()

    return b64encode(ciphertext).decode(), (fim - inicio)

  def decrypt(self,data):
    inicio = time.time()

    Cipher.setKey(self)
    ciphertext = b64decode(data.encode())
    rsa_decryption_cipher = PKCS1_v1_5.new(self.RSAkey)
    plaintext = rsa_decryption_cipher.decrypt(ciphertext,16)
    
    DES = DesKey(self.DESKey.encode())
    decript = DES.decrypt(plaintext, padding=True)

    fim = time.time()
    return decript, (fim - inicio)

cipher = Cipher()
if not os.path.exists('pvt.key'):
  cipher.generate_key(1024, 8)

os.system('CLS')
while True:
  print(' ')
  print(' Selecione a opção:')
  print(' 1 - Criptografar texto')
  print(' 2 - Descriptografar  texto')
  print(' 3 - Gerar Chaves')
  print(' 4 - Sair')
  print(' ')

  opcao = input('Opção: ')
  if not opcao.isdigit():
    os.system('CLS')
    print("Digite apenas numeros!")
  else:
    if (int(opcao) == 1):
      msg = input('Digite a mensagem ')
      encript, timer = cipher.encrypt(msg)
      print('Mensagem Criptografada: \n'+encript)
      print('Tempo: '+str(timer))
    
    elif (int(opcao) == 2):
      msg = input('Digite a mensagem Criptografada: ')
      plaintext, timer = cipher.decrypt(msg)
      print('Mensagem Original: \n'+ plaintext.decode())
      print('Tempo: '+str(timer))

    elif (int(opcao) == 3):
      bChave = True
      while bChave: 
        print(' Qual o Tamanho das Chaves ?')
        print(' 1 - 1024 e 8')
        print(' 2 - 2048 e 16')
        print(' 3 - 4096 e 24')
        print(' 4 - Sair')

        chave = input('Opção: ')
        if not chave.isdigit():
          print('')
          print("Digite apenas numeros!")
          print('')

        if int(chave) == 1:
          timer = cipher.generate_key(1024, 8)
          os.system('CLS')
          print('Chave gerada em : ' + str(timer))
          bChave = False

        elif int(chave) == 2:
          timer = cipher.generate_key(2048, 16)
          os.system('CLS')
          print('Chave gerada em : ' + str(timer))
          bChave = False

        elif int(chave) == 3:
          timer = cipher.generate_key(4096, 24)
          os.system('CLS')
          print('Chave gerada em : ' + str(timer))
          bChave = False

        elif int(chave) == 4:
          bChave = False

    elif (int(opcao) == 4):
      break
    else:
      os.system('CLS')
      print("Digite um numero valido")

  

