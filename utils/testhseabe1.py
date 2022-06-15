from doctest import master
from abe import HABE
from aes import HAES
import json
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.secretutil import SecretUtil
from HSEABE import HSEABE

f = open("./test-plaintext.txt", "r")
testPlaintext = f.read()

policyStr = "(OWNER and OWNERKEY)"
myAttr = ["OWNER", "OWNERKEY"]
(publicKey, masterKey, secretKey, combinedData) = HSEABE().encryptContent(policyStr, myAttr, testPlaintext)

print('========PUBLIC KEY===========')
print(publicKey)
print('========MASTER KEY===========')
print(masterKey)
print('========SECRET KEY===========')
print(secretKey)

dataOnIPFS = combinedData #string #is also ciphertext
userKeptPublicKey = publicKey #string
userKeptSecretKey = secretKey #string

decryptedContent = HSEABE().decryptFile(userKeptPublicKey, userKeptSecretKey, dataOnIPFS)
print(decryptedContent)

