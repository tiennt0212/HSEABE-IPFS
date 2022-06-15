from charm.toolbox.pairinggroup import PairingGroup, GT
from ABE.ac17 import AC17CPABE
from ABE.bsw07 import BSW07
from sha import HSHA

class HABE:
  def __init__(self, id='SS512'):
    self.group = PairingGroup(id)
    self.cpabe = AC17CPABE(self.group, 2)

  def getGroup(self):
    return self.group

  def setup(self):
    # Generate random publicKey and masterKey
    (pk, msk) = self.cpabe.setup()
    return (pk, msk)

  def genAccessKey(self, publicKey, masterKey, attrList):
    # OWNER use this method in order to generate a key for the authorized user
    return self.cpabe.keygen(publicKey, masterKey, attrList)
  
  def randomGT(self):
    # randomGT will be encrypted by ABE cryptography to get a cipher key
    # or used to generate a key for encrypting plaintext
    return self.group.random(GT)

  def serialize(self, groupElement):
    return self.group.serialize(groupElement)

  def deserialize(self, str):
    # Deserialize str to Group Element
    return self.group.deserialize(str)
  
  def genKeyAES(self, randomGT):
    # serialize randomGT to bytes
    # hash these bytes to receive 32bytes of key
    print("randomGT has type ", type(randomGT) )
    return HSHA().hash(self.serialize(randomGT))

  def getCipherKey(self, publicKey, randomGT, policyStr):
    # use ABE to encrypt randomGT, will receive cipher key
    return self.cpabe.encrypt(publicKey, randomGT, policyStr)

  def decryptCipherKey(self, publicKey, ciphertext, key):
    print(key)
    return self.cpabe.decrypt(publicKey, ciphertext, key)

  

  