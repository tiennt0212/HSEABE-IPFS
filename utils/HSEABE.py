from abe import HABE
from aes import HAES
import json
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.secretutil import SecretUtil

class HSEABE:
  def __init__(self):
    self.habe = HABE()
    self.haes = HAES('0123456789ABCDEF')

  def _serializeElement(self, data):
    # Return data's type is bytes
    return self.habe.serialize(data)

  def _deserializeElement(self, data):
    # Receive data's type is bytes
    return self.habe.deserialize(data)

  def _serializeList(self, data):
    for i in range(len(data)):
      datatype = type(data[i]).__name__
      if(datatype == 'Element'):
        # Decode to have a string
        data[i] = self._serializeElement(data[i]).decode()
      else:
        raise Exception('May it not a LIST of ELEMENT data {0}, receive {1}'.format(data, datatype))
    return data
  
  def _deserializeList(self, data):
    for i in range(len(data)):
      datatype = type(data[i]).__name__
      if(datatype == 'str'):
        # Encode to have bytes
        data[i] = self._deserializeElement(data[i].encode())
      else:
        raise Exception('Re-checking this data, this list contain a weird data {0}, receive {1}'.format(data[i], datatype))
    return data
  
  def _objectToString(self, data):
    # # The input data is a ciphertext of ABE encryption
    # # But it's needed to stored
    # # I would like to convert it into string.
    # # Cannot use json.dumps to convert an object to string/bytes
    # # So, convert sub-value to a data-type that can be dump by JSON
    # data['Cp'] = self.habe.serialize(data['Cp']).decode()
    # for i in range(len(data['C_0'])):
    #   data['C_0'][i] = self.habe.serialize(data['C_0'][i]).decode()

    # for key in data['C'].keys():
    #   for i in range(len(data['C'][key])):
    #     data['C'][key][i] = self.habe.serialize(data['C'][key][i]).decode()

    # # convert policy to a string
    # data['policy'] = str(data['policy'])

    # return json.dumps(data)
    for key in data.keys():
      datatype = type(data[key]).__name__
      if(datatype == 'Element'):
        # decode() to have a string
        data[key] = self._serializeElement(data[key]).decode()
      elif(datatype == 'list'):
        data[key] = self._serializeList(data[key])
      elif(datatype == 'dict'):
        # Recursive function
        return self._objectToString(data[key])
      else:
        raise Exception('This dictionary key cannot serialize by a sub-data {0}, its type is {1}'.format(key, datatype))
    return json.dumps(data)

  def _stringToObject(self, data):
    # # The input data is a ciphertext of ABE encryption
    # # Currently, it's a string, and its value is bytes style
    # # It's needed to back into the right data-type before decryption

    # # convert it to an object first.
    # data = json.loads(data)

    # # convert each sub-value into the right data-type

    # # convert to Group.Element
    # data['Cp'] = self.habe.deserialize(data['Cp'].encode())
    # for i in range(len(data['C_0'])):
    #   data['C_0'][i] = self.habe.deserialize(data['C_0'][i].encode())
    
    # for key in data['C'].keys():
    #   for i in range(len(data['C'][key])):
    #     data['C'][key][i] = self.habe.deserialize(data['C'][key][i].encode())
    
    # # convert policy string by re-create it by createPolicy function.
    # data['policy'] = SecretUtil(self.habe.getGroup()).createPolicy(data['policy'])
    
    # return data

    # convert it to an object first.
    data = json.loads(data)

    for key in data.keys():
      datatype = type(data[key]).__name__
      if(datatype == 'str'):
        # encode() to have bytes
        data[key] = self._deserializeElement(data[key].encode())
      elif(datatype == 'list'):
        data[key] = self._deserializeList(data[key])
      elif(datatype == 'dict'):
        # Recursive function
        return self._stringToObject(data[key])
      else:
        raise Exception('This dictionary key cannot deserialize by a sub-data {0}, its type is {1}'.format(key, datatype))
    return data


  def _combineData(self, data1, data2):
    # is a function to append ciphertext and cipherkey in 1 string
    # the last string will be use to store on IPFS

    return data1 + "####" + data2

  def _seperateData(self, combinedData):
    # is a function to seperate data from a file into 2 pieces
    # the first piece is the metadata was encrypted by AES
    # the second one is the key was encrypted by ABE

    seperatedData = combinedData.split("####")

    # cipherText was encrypted by AES
    # encode it with iso8859-1 to bytes data (for decryption)
    cipherText = seperatedData[0].encode('iso8859-1')

    # the second value is string
    # it need a special convert to be the right dictionary.
    cipherKey = self._stringToObject(seperatedData[1])

    return cipherText, cipherKey

  def storeFile (self, policy, attr, content):
    # INPUT
    ## policy: string
    ## attr: array of string
    ## content: string (long)

    # Initial
    GT = self.habe.randomGT()

    # Gen key
    publicKey, masterKey = self.habe.setup()
    cipherKey = self.habe.getCipherKey(publicKey, GT, policy)
    secretKey = self.habe.genAccessKey(publicKey, masterKey, attr)
    aesKey = self.habe.genKeyAES(GT)

    # calculate data
    self.haes.setKey(aesKey)
    cipherText = self.haes.encryptString(content)
    combinedData = self._combineData(cipherText.decode('iso8859-1'), self._objectToString(cipherKey))

    # serialize data before return
    srlPublicKey = self._objectToString(publicKey)
    srlMasterKey = self._objectToString(masterKey)
    srlSecretKey = self._objectToString(secretKey)


    # Return data
    ## publicKey: ........... NEEDED to dumps
    ## masterKey: ........... NEEDED to dumps
    ## secretKey: ........... NEEDED to dumps
    ## combinedData: string, will be used to stored on IPFS

    return (srlPublicKey, srlMasterKey, srlSecretKey, combinedData)
