from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from base64 import b64decode
from base64 import b64encode

import json
import sys
import math
from random import randint

class Person:
  p = 0
  g = 0
  a = 0
  k = 0
  publicKey = 0
  recievedMessage = ""

  def modOfBigNums(self, num, toPow, modNum):
    #https://en.wikipedia.org/wiki/Modular_exponentiation#Pseudocode
    result = 1
    num = num % modNum
    while toPow > 0:
      if toPow % 2 == 1:
        result = (result * num) % modNum
      toPow = toPow >> 1
      num = (num * num) % modNum
    return result
      
  def sendPandG(self, p, g):
    self.initPublicKey(p, g)
    return {"p": p, "g": g}

  def initializeSymKey(self, othersPublicKey):
    s = str(self.modOfBigNums(othersPublicKey, self.a, self.p)).encode()
    h = SHA256.new()
    h.update(s)
    self.k = bytes(h.hexdigest()[0:32], 'utf-8')

  #returns both the IV used and the ciphertext
  def getEncryption(self, myMessage):
    cipher = AES.new(self.k, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(bytes(myMessage, 'utf-8'), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    return result
  
  def decryptMessage(self, encryptedMessageData):
    b64 = json.loads(encryptedMessageData)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(self.k, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

  def initPublicKey(self, p, g):
    self.p = p
    self.g = g
    self.a = randint(0, self.p - 1)
    self.publicKey = self.modOfBigNums(self.g, self.a, self.p)

  def sendMessageTo(self, person, message):
    encryptedMessage = self.getEncryption(message)
    print("CBC IV and cipher text of message: " + str(encryptedMessage))
    person.recievedMessage = person.decryptMessage(encryptedMessage)
    return encryptedMessage

#########################################################################################################
alice = Person()
bob = Person()
#p = 37
#g = 5
p = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
g = 0XA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5

print("using p: " + str(p))
print("using g: " + str(g))
print("\n")

# Alice sends p and g values to Bob and both initialize their public keys
aliceData = alice.sendPandG(p, g)
bob.initPublicKey(aliceData["p"], aliceData["g"])

# Initialize symmetric key for alice and bob
alice.initializeSymKey(bob.publicKey)
bob.initializeSymKey(alice.publicKey)

# Ensure symmetric key is the same for Alice and Bob
print("Alice calculated the symmetric key: " + str(alice.k))
print("Bob calculated the symmetric key: " + str(bob.k))
print("This two keys are equivalent?: " + str(alice.k == bob.k))
print("\n")

# Pass a message from Bob to Alice
message = "Hey Alice, this is Bob. I was walking past the grocery store today and thought of you. How are things at the pet shop?"
print("Sending message to Alice from Bob: " + message)
bob.sendMessageTo(alice, message)
print("Alice recieved the following: " + str(alice.recievedMessage))

# Pass a message from Alice to Bob
print("\n")
message = "Not so well unfortunately, Bob. I am low on money. I don't think I can feed them anymore, it's time to face reality and sell the shop."
print("Sending message to Bob from Alice: " + message)
alice.sendMessageTo(bob, message)
print("Bob recieved the following: " + str(bob.recievedMessage))


################################    TASK 2    ###########################################
print("\nTASK 2:")

#########################################################################################################
print("--- Part 1: Mallory tampers with the public keys of Alice and Bob ---")
#########################################################################################################
alice = Person()
bob = Person()
mallory = Person()

aliceData = alice.sendPandG(p, g)
bob.initPublicKey(aliceData["p"], aliceData["g"])

# Mallory MITM attack happens here. Mallory changes the public keys of alice and bob.
alice.publicKey = p
bob.publicKey = p
mallory.a = 1
mallory.p = p
mallory.publicKey = p
mallory.initializeSymKey(p) # We know what alice and bob's public keys are. We modified them both to be 'p'

# Initialize symmetric key for alice and bob. Their public keys have been modified by Mallory
alice.initializeSymKey(bob.publicKey)
bob.initializeSymKey(alice.publicKey)

# Pass a message from Bob to Alice
message = "Hey Alice, this is Bob. How is everything today!?"
print("Sending message to Alice from Bob: " + message)
encryptedMessageToAlice = bob.sendMessageTo(alice, message)
print("Alice recieved the following: " + str(alice.recievedMessage))
messageRecievedByMallory = mallory.decryptMessage(encryptedMessageToAlice)
print("MITM Attack! Mallory intercepted the following message to Alice: " + str(messageRecievedByMallory))

# Pass a message from Alice to Bob
print("\n")
message = "Hey Bob, this is Alice. Not bad!"
print("Sending message to Bob from Alice: " + message)
encryptedMessageToBob = alice.sendMessageTo(bob, message)
print("Bob recieved the following: " + str(bob.recievedMessage))
messageRecievedByMallory = mallory.decryptMessage(encryptedMessageToBob)
print("MITM Attack! Mallory intercepted the following message to Bob: " + str(messageRecievedByMallory))

#########################################################################################################
print("--- Part 2: Mallory tampers with g ---")
#########################################################################################################
alice = Person()
bob = Person()
mallory = Person()

# Mallory MITM attack happens here. Mallory changes g to equal 1
# If g = 1, then A and B = 1, so the symmetric key must be SHA256(1^a % p) = SHA256(1)
print("Mallory is modifying g to equal 1...")
g = 1
aliceData = alice.sendPandG(p, g)
bob.initPublicKey(aliceData["p"], aliceData["g"])

# s = A^b % p, so since the public key A = 1 in this case, s = 1
s = str(1).encode()
h = SHA256.new()
h.update(s)
mallory.k = bytes(h.hexdigest()[0:32], 'utf-8')

# Initialize symmetric key for alice and bob. Their public keys have been modified by Mallory
alice.initializeSymKey(bob.publicKey)
bob.initializeSymKey(alice.publicKey)

# Pass a message from Bob to Alice
message = "Hey Alice, this is Bob. I hope no one changes our g value!"
print("Sending message to Alice from Bob: " + message)
encryptedMessageToAlice = bob.sendMessageTo(alice, message)
print("Alice recieved the following: " + str(alice.recievedMessage))
messageRecievedByMallory = mallory.decryptMessage(encryptedMessageToAlice)
print("MITM Attack! Mallory intercepted the following message to Alice: " + str(messageRecievedByMallory))

# Pass a message from Alice to Bob
print("\n")
message = "Hi Bob. I also hope so."
print("Sending message to Bob from Alice: " + message)
encryptedMessageToBob = alice.sendMessageTo(bob, message)
messageRecievedByMallory = mallory.decryptMessage(encryptedMessageToBob)
print("MITM Attack! Mallory intercepted the following message to Bob: " + str(messageRecievedByMallory))

#########################################################################################################
alice = Person()
bob = Person()
mallory = Person()

# Mallory MITM attack happens here. Mallory changes g to equal p
# If g = p, then public key A = (p^a) %p, which is always 0, so the symmetric key must be SHA256(0^a % p) = SHA256(0)
print("Mallory is modifying g to equal p...")
g = p
aliceData = alice.sendPandG(p, g)
bob.initPublicKey(aliceData["p"], aliceData["g"])

# s = A^b % p, so since the public key A = 0 in this case, s = 0
s = str(0).encode()
h = SHA256.new()
h.update(s)
mallory.k = bytes(h.hexdigest()[0:32], 'utf-8')

# Initialize symmetric key for alice and bob. Their public keys have been modified by Mallory
alice.initializeSymKey(bob.publicKey)
bob.initializeSymKey(alice.publicKey)

# Pass a message from Bob to Alice
message = "Hey Alice, this is Bob. I hope no one changes our g value to be p!"
print("Sending message to Alice from Bob: " + message)
encryptedMessageToAlice = bob.sendMessageTo(alice, message)
print("Alice recieved the following: " + str(alice.recievedMessage))
messageRecievedByMallory = mallory.decryptMessage(encryptedMessageToAlice)
print("MITM Attack! Mallory intercepted the following message to Alice: " + str(messageRecievedByMallory))

# Pass a message from Alice to Bob
print("\n")
message = "Hi Bob. I also hope so, especially not p!"
print("Sending message to Bob from Alice: " + message)
encryptedMessageToBob = alice.sendMessageTo(bob, message)
messageRecievedByMallory = mallory.decryptMessage(encryptedMessageToBob)
print("MITM Attack! Mallory intercepted the following message to Bob: " + str(messageRecievedByMallory))

#########################################################################################################
alice = Person()
bob = Person()
mallory = Person()

# Mallory MITM attack happens here. Mallory changes g to equal p - 1
# If g = p - 1, then public key A = ((p - 1)^a) %p, which is either 1 (if a < p) or p - 1 (if a >= p) (discovered using try and error),
# so the symmetric key must be SHA256(1^a % p) = SHA256(1) or SHA256(p-1)
print("Mallory is modifying g to equal p-1...")
g = p - 1
aliceData = alice.sendPandG(p, g)
bob.initPublicKey(aliceData["p"], aliceData["g"])

# s = A^b % p, so since the public key A = 1 or p-1 in this case, s = 1 or p - 1
print("Public keys: " + str(bob.publicKey) + ", " + str(alice.publicKey))
s = ""
# if just one of the public keys is 1, then the symmetric key MUST equal 1 since s = (B^a)%p = (A^b)%p, and if A or B = 1,
# then s= (1^a)%p = 1%p = 1. Otherwise if both public keys are p-1, the symmetric key is p-1 
if(bob.publicKey == p - 1 and alice.publicKey == p -1):
  s = str(p-1).encode()
else:
  s = str(1).encode()

h = SHA256.new()
h.update(s)
mallory.k = bytes(h.hexdigest()[0:32], 'utf-8')

# Initialize symmetric key for alice and bob. Their public keys have been modified by Mallory
alice.initializeSymKey(bob.publicKey)
bob.initializeSymKey(alice.publicKey)

# Pass a message from Bob to Alice
message = "Hey Alice, this is Bob. I hope no one changes our g value to be p -1!"
print("Sending message to Alice from Bob: " + message)
encryptedMessageToAlice = bob.sendMessageTo(alice, message)
print("Alice recieved the following: " + str(alice.recievedMessage))
messageRecievedByMallory = mallory.decryptMessage(encryptedMessageToAlice)
print("MITM Attack! Mallory intercepted the following message to Alice: " + str(messageRecievedByMallory))

# Pass a message from Alice to Bob
print("\n")
message = "Hi Bob. I also hope so, especially not p-1!"
print("Sending message to Bob from Alice: " + message)
encryptedMessageToBob = alice.sendMessageTo(bob, message)
messageRecievedByMallory = mallory.decryptMessage(encryptedMessageToBob)
print("MITM Attack! Mallory intercepted the following message to Bob: " + str(messageRecievedByMallory))