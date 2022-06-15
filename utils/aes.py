from pydoc import plain
from Crypto.Cipher import AES
import json

class HAES:
  def __init__(self, key):
    self.key = key
    self.mode = AES.MODE_ECB
    self.aes = AES.new(self.key, self.mode)
    self.blocksize = 16

  def setKey(self, key):
    self.aes = AES.new(key, self.mode)
    self.key = key

  def _pad(self, data):
    padLength = 16 - (len(data) % 16)
    return data + (bytes([padLength])*padLength).decode()

  def _unpad(self, data):
    data = data[:-int.from_bytes(data[-1].encode(), "big")]
    return data

  def encryptString(self, plaintext):
    if(not (type(plaintext) is str)):
      raise Exception('This function need input type is string, received', type(plaintext))
    return self.aes.encrypt(self._pad(plaintext))

  def decryptToString(self, ciphertext):
    print(self.aes.decrypt(ciphertext))
    return self._unpad(self.aes.decrypt(ciphertext).decode())

  def encryptDict(self, data):
    if(not (type(data) is dict)):
      raise Exception('This function need input type is DICT, received', type(data))
    plaintext = json.dumps(data)
    return self.encryptString(plaintext)

  def decryptToDict(self, ciphertext):
    return json.loads(self.decryptToString(ciphertext))
    
