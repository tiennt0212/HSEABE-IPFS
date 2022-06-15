# Importing flask module in the project is mandatory
# An object of Flask class is our WSGI application.
from flask import Flask, request, jsonify
from operator import itemgetter
import json
from HSEABE import HSEABE
import requests


IPFS_END_POINT = 'http://192.168.199.151'
hseabe = HSEABE()

app = Flask(__name__)


@app.route('/encrypt', methods=['POST'])
def hello_world():
  data = json.loads(request.data.decode())
  policy, attrList, dataToEncrypt = itemgetter('policy', 'attrList','dataToEncrypt')(data)
  
  (publicKey, masterKey, secretKey, combinedData) = hseabe.encryptContent(policy, attrList, dataToEncrypt)
  # print('========PUBLIC KEY===========')
  # print(publicKey)
  # print('========MASTER KEY===========')
  # print(masterKey)
  # print('========SECRET KEY===========')
  # print(secretKey)

  return jsonify(
    publicKey=publicKey,
    masterKey=masterKey,
    secretKey=secretKey,
    combinedData=combinedData
  )


@app.route('/decrypt', methods=['GET', 'POST'])
def get_file():
  data = json.loads(request.data.decode())
  publicKey, secretKey, combinedData = itemgetter('publicKey', 'secretKey', 'combinedData')(data)
  # print('========PUBLIC KEY===========')
  # print(publicKey)
  # print('========SECRET KEY===========')
  # print(secretKey)
  # print('========COMBINED DATA===========')
  # print(combinedData)
  originData = hseabe.decryptFile(publicKey, secretKey, combinedData)
  
  return originData




# main driver function
if __name__ == '__main__':
  
    # run() method of Flask class runs the application 
    # on the local development server.
    app.run(host="0.0.0.0")