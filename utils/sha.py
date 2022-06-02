from Crypto.Hash import MD5

class HSHA:
  def __init__(self):
    self.md5 = MD5.new()
  
  def hash(self, message):
    typeMsg = type(message)
    if(typeMsg is str):
      self.md5.update(message.encode('utf-8'))
    elif(typeMsg is bytes):
      self.md5.update(message)
    else:
      raise Exception('Hash funciton need the input type is string or bytes')
    return self.md5.hexdigest()

