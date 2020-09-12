#!/usr/bin/python3
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import os, hashlib, binascii, base64, random, ast


class Mtree:
    def __init__(self, value):
        self.left = None
        self.right = None
        self.value = value
        self.hashValue = hashlib.sha256(value.encode('utf-8')).hexdigest()


candidates = {"1": "Democrats 1", "2": "Republican 2"}
votes = {"Democrats 1": [], "Republican 2": []}
voterIds = {}
Key = random.SystemRandom().randrange(2 ** (51), 2 ** (52))
Iv = Random.new().read(AES.block_size)
nodeKey = random.SystemRandom().randrange(2 ** (51), 2 ** (52))
nodeIv = Random.new().read(AES.block_size)
mode = AES.MODE_CFB


def encrypt(self, message, key, key_size=256):
    message = self.pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(self, ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def register(uniqueId):
    uniqueIdHash = hashlib.sha256(uniqueId.encode('utf-8')).hexdigest()
    global voterIds
    voterIds[uniqueId] = uniqueIdHash
    return uniqueIdHash


def checkInVoterId(voterId):
    global voterIds
    return voterId in voterIds.values()


def vote(candidateNumber, voterId):
    s = "merkleNodeList" + candidateNumber + ".txt"
    merkleFile = "merkle" + candidateNumber + ".tree"
    if os.path.exists(s):
        with open(s) as f2:
            d = f2.readlines()
        encListString = d[0]
        e = base64.b64decode(encListString.encode('utf-8'))
        dec = AES.new(str(nodeKey).encode("utf8"), mode, nodeIv)
        plaintext = dec.decrypt(e)
        plaintext = plaintext.decode('utf-8').strip('\x10\x04\r\x08')
        merkleNodeList = ast.literal_eval(plaintext)
        merkleNodeList.append(voterId)
        buildTree(merkleNodeList, merkleFile)
        f1 = open(s, "w")
        cip = AES.new(str(nodeKey).encode("utf8"), mode, nodeIv)
        enc = cip.encrypt(str(merkleNodeList).encode('utf-8'))
        f1.write(base64.b64encode(enc).decode('utf-8'))
        f1.close()
    else:
        f1 = open(s, "w")
        l = []
        l.append(voterId)
        voterIdHash = hashlib.sha256(voterId.encode('utf-8')).hexdigest()
        cip = AES.new(str(nodeKey).encode("utf8"), mode, nodeIv)
        enc = cip.encrypt(str(l).encode('utf-8'))
        f1.write(base64.b64encode(enc).decode('utf-8'))
        f1.close()
        f = open(merkleFile, "w")
        s = "Merkle Tree Node : " + voterId + " | Hash : " + voterIdHash
        cip = AES.new(str(Key).encode("utf8"), mode, Iv)
        mEnc = cip.encrypt(s.encode('utf-8'))
        f.write(base64.b64encode(mEnc).decode('utf-8'))
        f.write("\n")
        f.close()

    candidate = candidates[candidateNumber]
    global votes
    votes[candidate].append(voterId)

def getHash(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def buildTree(leaves, merkleFile):
    f = open(merkleFile, "w")
    nodes = []
    for i in leaves:
        nodes.append(Mtree(i))

    while len(nodes) != 1:
        temp = []
        for i in range(0, len(nodes), 2):
            node1 = nodes[i]
            if i + 1 < len(nodes):
                node2 = nodes[i + 1]
            else:
                temp.append(nodes[i])
                break
            lcString = "Left child : " + node1.value + " | Hash : " + node1.hashValue
            rcString = "Right child : " + node2.value + " | Hash : " + node2.hashValue
            cip = AES.new(str(Key).encode("utf8"), mode, Iv)
            lcEnc = cip.encrypt(lcString.encode('utf-8'))
            rcEnc = cip.encrypt(rcString.encode('utf-8'))
            f.write(base64.b64encode(lcEnc).decode('utf-8'))
            f.write("\n")
            f.write(base64.b64encode(rcEnc).decode('utf-8'))
            f.write("\n")
            concatenatedHash = node1.hashValue + node2.hashValue
            parent = Mtree(concatenatedHash)
            parent.left = node1
            parent.right = node2
            parentString = "Parent(concatenation of " + node1.value + " and " + node2.value + ") : " + parent.value + " | Hash : " + parent.hashValue
            parentEnc = cip.encrypt(parentString.encode('utf-8'))
            f.write(base64.b64encode(parentEnc).decode('utf-8'))
            f.write("\n")
            temp.append(parent)
        nodes = temp
    f.close()

def combined(value1, value2):
    combinedValue = value1 + value2
    return combinedValue

def VoteTally(l1, l2):
    i = 0
    while i < len(l1):
        if l1[i] != l2[i]:
            break
        i += 1
    if i < len(l1):
        return []
    f = open("merkle.trees", "w")
    f.write("Merkle Tree for 1 Candidate \n")
    root1 = createTree(l1, f)
    f.write("\n\n")
    f.write("Merkle Tree for 2 Candidate \n")
    root2 = createTree(l2, f)
    f.close()
    out = []
    out.append(root1.hash)
    with open("merkle.trees") as f:
        data = f.readlines()

    tree2Index = 0
    for i in range(len(data)):
        if data[i].startswith("Merkle Tree 2"):
            tree2Index = i
    parentLines = []
    leftChildLines = []
    rightChildLines = []
    for i in range(tree2Index, len(data)):
        if data[i].startswith("Parent("):
            parentLines.append(data[i])

    for i in range(tree2Index, len(data)):
        if data[i].startswith("Left"):
            leftChildLines.append(data[i])

    for i in range(tree2Index, len(data)):
        if data[i].startswith("Right"):
            rightChildLines.append(data[i])
    out = []
    flag = False
    for i in range(len(parentLines)):
        if root1.hash in parentLines[i]:
            flag = True
            break
    if flag:
        values = []
        combinedHash = ''
        lc = root1.value
        while combinedHash != root2.hash:
            for i in range(len(leftChildLines)):
                if lc in leftChildLines[i].split(" ")[-6]:
                    rc = rightChildLines[i].split(" ")[-6]
                    values.append(getHash(rc))
                    break
            combinedValue = combined(getHash(lc), getHash(rc))
            combinedHash = getHash(combinedValue)
            lc = combinedValue

        out.append(root1.hash)
        out += values
        out.append(root2.hash)

    else:
        root1LeftChildValue = data[tree2Index - 5].split(" ")[-6]
        root1RightChildValue = data[tree2Index - 4].split(" ")[-6]
        root1RightChildSiblingValue = l2[l2.index(root1RightChildValue) + 1]
        values = []
        values.append(getHash(root1LeftChildValue))
        values.append(getHash(root1RightChildValue))
        values.append(getHash(root1RightChildSiblingValue))
        root1RightChildCombinedValue = combined(getHash(root1RightChildValue), getHash(root1RightChildSiblingValue))
        combinedHash = ''
        lc = root1LeftChildValue
        rc = root1RightChildCombinedValue
        while combinedHash != root2.hash:
            combinedValue = combined(getHash(lc), getHash(rc))
            combinedHash = getHash(combinedValue)
            lc = combinedValue
            for i in range(len(leftChildLines)):
                if lc in leftChildLines[i].split(" ")[-6]:
                    rc = rightChildLines[i].split(" ")[-6]
                    values.append(getHash(rc))
                    break

        out.append(root1.hash)
        out += values
        out.append(root2.hash)

    return out
def readMerkleNode(candidateNumber):
    filePath = "merkle" + candidateNumber + ".tree"
    with open(filePath) as f:
        data = f.readlines()
    tree = {}
    dec = AES.new(str(Key).encode("utf8"), mode, Iv)
    for i in range(len(data)):
        if data[i] != "\n":
            e = base64.b64decode(data[i].encode('utf-8'))
            plaintext = dec.decrypt(e)
            plaintext = plaintext.decode('utf-8').strip('\x10\x04\r\x08')
            lineArray = plaintext.split(" ")
            tree[lineArray[4]] = lineArray[8]
    return tree


def parseFile(candidateNumber):
    filePath = "merkle" + candidateNumber + ".tree"
    with open(filePath) as f:
        data = f.readlines()
    tree = {}
    dec = AES.new(str(Key).encode("utf8"), mode, Iv)
    for i in range(len(data)):
        if data[i] != "\n":
            e = base64.b64decode(data[i].encode('utf-8'))
            plaintext = dec.decrypt(e)
            plaintext = plaintext.decode('utf-8').strip('\x10\x04\r\x08')
            lineArray = plaintext.split(" ")
            if lineArray[0] == 'Parent(concatenation':
                tree[lineArray[6]] = lineArray[10]
            else:
                tree[lineArray[3]] = lineArray[7]
    return tree


def validate(voterId):
    global votes
    candidate = ""
    votesLength = 0
    for key, value in votes.items():
        if voterId in value:
            candidate = key
            votesLength = len(value)
            break
    candidateNumber = ""
    for key, value in candidates.items():
        if candidate in value:
            candidateNumber = key
            break
    tree = None
    if votesLength == 1:
        tree = readMerkleNode(candidateNumber)
    else:
        tree = parseFile(candidateNumber)

    op = []
    for key, value in tree.items():
        if voterId in key:
            op.append(value)
            voterId = value
    return op


def printMerkleTree(candidateNumber):
    filePath = "merkle" + candidateNumber + ".tree"
    with open(filePath) as f:
        data = f.readlines()
    dec = AES.new(str(Key).encode("utf8"), mode, Iv)
    for i in range(len(data)):
        if data[i] != "\n":
            e = base64.b64decode(data[i].encode('utf-8'))
            plaintext = dec.decrypt(e)
            plaintext = plaintext.decode('utf-8').strip('\x10\x04\r\x08')
            print(plaintext)
    f.close()


def alreadyRegistered(uniqueId):
    voterId = hashlib.sha256(uniqueId.encode('utf-8')).hexdigest()
    global voterIds
    for value in voterIds.values():
        if voterId in value:
            return True
    return False


def alreadyVoted(voterId):
    global votes
    for value in votes.values():
        if voterId in value:
            return True
    return False


if __name__ == "__main__":
    menu = {"1": "Voter Registration", "2": "Vote", "3": "Validate votes", "4": "View votes", "5": "Vote Count",
            "6": "Exit"}

    while True:
        print("Select your option from the given menu")
        for key, value in menu.items():
            print(key + "  :  " + value)
        selection = input()
        if selection == "1":
            uniqueId = input("Please enter your Social Security Number : ")
            if alreadyRegistered(uniqueId):
                print(
                    "You are a registerd user.")
            else:
                voterId = register(uniqueId)
                print("Your unique voter id number is : " + voterId)
                print("Please use this voter id number for voting.")
        elif selection == "2":
            voterId = input("Please enter your voter id number : ")
            if not checkInVoterId(voterId):
                print("Please enter a valid voter id number or register for casting vote")
            elif alreadyVoted(voterId):
                print("You have already voted in this election.")
            else:
                print("Please choose from below candidate")
                for key, value in candidates.items():
                    print(key + " : " + value)
                candidateNumber = input()
                if candidateNumber not in candidates.keys():
                    print("Invalid entry")
                else:
                    vote(candidateNumber, voterId)
                    print("Your vote has been casted successfully  " + candidates[candidateNumber])
                    print("Thank you for voting!!")
        elif selection == "3":
            voterId = input("Please enter your voter id number : ")
            if not checkInVoterId(voterId):
                print("Please enter a valid voter id number or register for casting vote")
            else:
                validation = validate(voterId)
                if len(validation) > 0:
                    print("Your vote was successfully cast and recorded in our database")
                    print("The vote trail is ", validation)
                else:
                    print("Your vote was not validated. Please verify that you have voted properly!!")
        elif selection == "4":
            print("The vote tally currently is")
            for key, value in votes.items():
                print(key + " : " + str(len(value)))
        elif selection == "5":
            candidateNumber = input("Please enter the candidate number : ")
            printMerkleTree(candidateNumber)
        elif selection == "6":
            print("Thanks for Polling")
            break
        else:
            print("You have selected a wrong option. Please choose the option from the given list of options")
