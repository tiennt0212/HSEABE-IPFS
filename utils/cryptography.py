from abe import HABE
from aes import HAES
import json
import ast
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.secretutil import SecretUtil
import pickle


# class Cryptography:
#   habe = HABE()
#   publicKey, masterKey = habe.setup()
#   aesKey = habe.genKeyAES(habe.randomGT());
#   def __init__(self, policy, msk=masterKey, pk=publicKey,):
#     self.policy = policy
#   def encrypt(self, msg, key):
#     cipherKey = 
#     cipherText = HAES(key).encryptString(msg) + "#@#" + 
#     # return masterKey, publicKey, secureKey, ciphertext, policyString



def objectToString(data):
  habe=HABE()
  # Cannot use json.dumps to convert an object to string/bytes
  # So, use this function to serialize each value from the object
  data['Cp'] = habe.serialize(data['Cp']).decode()
  for i in range(len(data['C_0'])):
    data['C_0'][i] = habe.serialize(data['C_0'][i]).decode()
  
  for key in data['C'].keys():
    for i in range(len(data['C'][key])):
      data['C'][key][i] = habe.serialize(data['C'][key][i]).decode()
  
  data['policy'] = str(data['policy'])

  return json.dumps(data)

def stringToObject(data):
  habe=HABE()
  data = json.loads(data)

  data['Cp'] = habe.deserialize(data['Cp'].encode())
  for i in range(len(data['C_0'])):
    data['C_0'][i] = habe.deserialize(data['C_0'][i].encode())
  
  for key in data['C'].keys():
    for i in range(len(data['C'][key])):
      data['C'][key][i] = habe.deserialize(data['C'][key][i].encode())
  
  data['policy'] = SecretUtil(habe.getGroup()).createPolicy(data['policy'])
  
  return data


def _combineData(cipherText, cipherKey):
  return cipherText.decode('iso8859-1') + "####" + objectToString(cipherKey)

def _seperateData(combinedData):
  seperatedData = combinedData.split("####")

  # cipherText was encrypted by AES
  # encode it with iso8859-1 to bytes data (for decryption)
  cipherText = seperatedData[0].encode('iso8859-1')

  cipherKey = stringToObject(seperatedData[1])

  return cipherText, cipherKey

def storeFile (policyStr, attr, msg):
  habe = HABE()
  publicKey, masterKey = habe.setup()
  random = habe.randomGT()

  cipherKey = habe.getCipherKey(publicKey, random, policyStr)

  secretKey = habe.genAccessKey(publicKey, masterKey, attr)

  aesKey = habe.genKeyAES(random)

  haes = HAES(aesKey)
  cipherText = haes.encryptString(msg)

  combinedData = _combineData(cipherText, cipherKey)

  return (publicKey, masterKey, secretKey, combinedData)

def decrypt(publicKey, userKey, ciphertext, cipherKey):
  habe = HABE()
  GT = habe.decryptCipherKey(publicKey, cipherKey, userKey)

  aesKey = habe.genKeyAES(GT)

  haes = HAES(aesKey)

  plaintext = haes.decryptToString(ciphertext)

  return plaintext






f = open("./test-plaintext.txt", "r")
testPlaintext = f.read()

(publicKey, masterKey, secretKey, combinedData) = storeFile("(OWNER and OWNERKEY)", ["OWNER", "OWNERKEY"], testPlaintext)

(cipherText, cipherKey) = _seperateData(combinedData)

decryptCipherText = decrypt(publicKey, secretKey, cipherText,cipherKey)

# for key in publicKey.keys():
#   print(type(publicKey[key]).__name__)
#   # print(type(publicKey[key]))
#   if(type(publicKey[key]) == list):
#     for i in range(len(publicKey[key])):
#       # print(type(publicKey[key][i]).__name__)
#       if(type(publicKey[key][i]).__name__ == 'Element'):
#         print('type is pairing element')


print(publicKey)
if (testPlaintext == decryptCipherText):
  print('Decrypt successfully')
else:
  print('Decrypt failed')
