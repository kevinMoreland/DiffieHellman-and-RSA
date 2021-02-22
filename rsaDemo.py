from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getRandomRange

from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Util.number import getPrime

from base64 import b64decode
from base64 import b64encode

import json
import sys
import math
from random import randint

class EuclieanEquation:
  # thetaN = mult*e + r 
  thetaN = 0
  mult = 0
  r = 0
  e = 0
  def __init__(self, thetaN, mult, r, e):
    self.thetaN = thetaN
    self.mult = mult
    self.r = r
    self.e = e
  def toString(self):
    return str(self.thetaN) + "=" + str(self.mult) + "*" + str(self.e) + "+" + str(self.r)

class Person:
  publicKey = {"n": 0, "e": 0}
  privateKey = {"n": 0, "d": 0}
  
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

  def getRandomNum(self, n):
    return getRandomRange(1, n)

  def getSHA256(self, s):
    h = SHA256.new()
    h.update(str(s).encode())
    k = bytes(h.hexdigest()[0:32], 'utf-8')
    return k
    
  def encryptWithCBC(self, m, symKey):
    k = self.getSHA256(symKey)
    cipher = AES.new(k, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(bytes(m, 'utf-8'), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    return result

  def decryptMessageWithCBC(self, encryptedMessageData, k):
    b64 = json.loads(encryptedMessageData)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(k, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

  def getSignature(self, m):
    return self.modOfBigNums(m, self.privateKey["d"], self.privateKey["n"])

  def verifySignature(self, s, othersPublicKey, hashOfSecret):
    return hashOfSecret == self.modOfBigNums(s, othersPublicKey["e"], othersPublicKey["n"])

  def encrypt(self, m, othersPublicKey):
    return self.modOfBigNums(m, othersPublicKey["e"], othersPublicKey["n"])

  def decrypt(self, c):
    return self.modOfBigNums(c, self.privateKey["d"], self.privateKey["n"])

  def getModularMultInverse(self, thetaN, e):
    eqList = []
    return self.getModularMultInverseHelper(thetaN, e, thetaN, eqList)

  def getModularMultInverseHelper(self, thetaN, e, originalThetaN, eqList):
    # base case
    if e == 1:
      lastEq = eqList[len(eqList) - 1]
      backtrace = {"x": lastEq.thetaN, "x#": 1, "y": lastEq.e, "y#": lastEq.mult}
      for x in range(1, len(eqList)):
        currEq = eqList[len(eqList) - x - 1]
        if backtrace["x"] == currEq.r:
          backtrace["y#"] = backtrace["y#"] + backtrace["x#"] * currEq.mult
          backtrace["x"] = currEq.thetaN
        else:
          backtrace["x#"] = backtrace["x#"] + backtrace["y#"] * currEq.mult
          backtrace["y"] = currEq.thetaN
      # Example: thetaN = 3000, e = 197, n = 3131, so our equation after doing extended Euclidean algorithm:
      # 1 = 533(197) - 35(3000)
      # take modulo thetaN of both sides. In this case, 35(3000) disappears because any number X times 3000 modulo 3000 = 0
      # 1 (mod 1) = 533(197) so, 533 is d in this case.
      ####
      # Notice that if the left coefficent is thetaN instead of the right, we have a negative d that needs to be 'wrapped' around thetaN:
      # Example: thetaN = 1088760, e = 197, n = 1125083 so our equation after doing extended Euclidean algorithm:
      # 1= 1088760(10) - 197(55267)
      # take modulo thetaN of both sides. In this case, 1088760(10) disappears, and we have:
      # 1 (mod 1088760) = -197(55267)
      # Lets make that -197(55267) positive by getting -55267 % 1088760, which is equivalent to 1088760 - 55267
      # 1 (mod 1088760) = 1033493(197)
      if backtrace["x"] == self.publicKey["e"]:
        return backtrace["x#"]
      return originalThetaN - backtrace["y#"]
    mult = thetaN // e
    r = thetaN - (mult * e)
    eq = EuclieanEquation(thetaN, mult, r, e)
    eqList.append(eq)
    return self.getModularMultInverseHelper(e, r, originalThetaN, eqList)

  def generateKeys(self):
    p = 156408916769576372285319235535320446340733908943564048157238512311891352879208957302116527435165097143521156600690562005797819820759620198602417583539668686152735534648541252847927334505648478214810780526425005943955838623325525300844493280040860604499838598837599791480284496210333200247148213274376422459183
    q = 153143042272527868798412612417204434156935146874282990942386694020462861918068684561281763577034706600608387699148071015194725533394126069826857182428660427818277378724977554365910231524827258160904493774748749088477328204812171935987088715261127321911849092207070653272176072509933245978935455542420691737433
    #p = 31
    #q = 101
    n = p * q
    #n = 1125083
    e = 65537
    #e = 197
    self.publicKey["n"] = n
    self.privateKey["n"] = n
    self.publicKey["e"] = e

    #thetaN = 1088760
    thetaN = (p - 1) * (q - 1)
    self.privateKey["d"] = self.getModularMultInverse(thetaN, e)
    print("D IS : : : : " + str(self.privateKey["d"]))

alice = Person()
bob = Person()

print("Bob wants to send a message to Alice, so Alice generates a public and private key.")
alice.generateKeys()

print("Alice generates the following public key to share with Bob:")
print(alice.publicKey)
print("Alice generates the following private key for decryption, which is NOT shared:")
print(alice.privateKey)

messageAsBytes = b"Hi Alice, RSA is really cool isn't it!"
print("\nBob sends the following to Alice: " + str(messageAsBytes.decode('utf-8')))
message = int(messageAsBytes.hex(), 16)
print("The message is converted to the following int so it can be encrypted: " + str(message))
cipher = bob.encrypt(message, alice.publicKey)
print("The message encrypts to: " + str(cipher))
# The [2:] converts a hex string like 0x4568 to just 4568 so it can be used by the function bytes.fromhex
decryptionHex = hex(alice.decrypt(cipher))[2:]
decodedMessage = bytes.fromhex(decryptionHex).decode('utf-8') 
print("Alice decrypts the cipher, and obtains: " + decodedMessage)

# STEP 2: MITM attack, a key exchange with a MITM attack
print("\n----- MITM attack -----")
alice = Person()
bob = Person()
mallory = Person()

print("Alice generates a public and private key.")
alice.generateKeys()

s = bob.getRandomNum(alice.publicKey["n"])
print("Bob privately chooses the following symmetric key: " + str(s))

c = bob.encrypt(s, alice.publicKey)
print("Bob encrypts the symmetric key into the following cipher: " + str(c))

symKeyComputedByAlice = alice.decrypt(c)
print("Alice decryption of the symmetric key, WITHOUT the MITM attack: " + str(symKeyComputedByAlice))

print("Mallory now modifies the cipher of the symmetric key before Alice recieves it so that Mallory can read any message Alice sends")
c = 1
# if c = 1, then for any 'd' value in the decryption s = c^d %n will cause s to equal 1, so Mallory knows the symmetric key now
symKeyComputedByAlice = alice.decrypt(c)
print("Because of the MITM attack, Alice believes she correctly decrypted the cipher and obtained the symmetric key: "+str(symKeyComputedByAlice))
messagePlainText = "Hi Bob! This is Alice."
messageToBob = alice.encryptWithCBC(messagePlainText, symKeyComputedByAlice)
print("Alice wants to send the following message to Bob: " + messagePlainText)
print("Alice encrypts her message with CBC into this: " + str(messageToBob))
print("Mallory reads: " + str(mallory.decryptMessageWithCBC(messageToBob, mallory.getSHA256(c))))

# This MITM attack could also be used to ensure that Alice and Bob cannot communicate with each other. If every time Alice 
# Tries sending a message to Bob the symmetric key cipher sent by Bob to Alice is modified, then Alice will never be able to create 
# a message that is decryptable for Bob

# STEP 3: Key signature attack
print("\n---Key Signature attack---")
alice = Person()
bob = Person()

print("Alice generates a public and private key.")
alice.generateKeys()

# first signature seen by Mallory
x = alice.getRandomNum(alice.publicKey["n"])
print("Alice picks the following random number to use for her signature: " + str(x))
hashOfSecret = int(alice.getSHA256(x).hex())
print("This value is hashed to: " + str(hashOfSecret))

aliceSignature = alice.getSignature(hashOfSecret)
print("Alice's signature: " + str(aliceSignature))
print("Bob attempts to verify Alice's signature using her public key. Was it verified?: ")
print(bob.verifySignature(aliceSignature, alice.publicKey, hashOfSecret))

# second signature seen by Mallory
x2 = alice.getRandomNum(alice.publicKey["n"])
print("Alice picks the following random number to use for her signature: " + str(x2))
hashOfSecret2 = int(alice.getSHA256(x2).hex())
print("This value is hashed to: " + str(hashOfSecret2))

aliceSignature2 = alice.getSignature(hashOfSecret2)
print("Alice's signature: " + str(aliceSignature2))
print("Bob attempts to verify Alice's signature using her public key. Was it verified?: ")
print(bob.verifySignature(aliceSignature2, alice.publicKey, hashOfSecret2))

# Now knowing these 2 signatures, Mallory attempts to construct a third valid signature
mallorySignature = (aliceSignature * aliceSignature2)
print("Mallory's signature:")
print(mallorySignature)
print("Bob tries verifying Mallory's signature. Was it verified?: ")
print(bob.verifySignature(mallorySignature, alice.publicKey, (hashOfSecret * hashOfSecret2) % alice.publicKey["n"]))
