import socket
import sys
from cryptography.fernet import Fernet

from server import Server

########################################################################
# Echo Client class
########################################################################

class Client:

    # Set the server to connect to. If the server and client are running
    # on the same machine, we can use the current hostname.
    # SERVER_HOSTNAME = socket.gethostname()
    # SERVER_HOSTNAME = "192.168.1.22"
    SERVER_HOSTNAME = "localhost"
    encryptionKeys = {1803933:"M7E8erO15CIh902P8DQsHxKbOADTgEPGHdiY0MplTuY=",
1884159:"PWMKkdXW4VJ3pXBpr9UwjefmlIxYwPzk11Aw9TQ2wZQ=",
1853847:"UVpoR9emIZDrpQ6pCLYopzE2Qm8bCrVyGEzdOOo2wXw=",
1810192:"bHdhydsHzwKdb0RF4wG72yGm2a2L-CNzDl7vaWOu9KA=",
1891352:"iHsXoe_5Fle-PHGtgZUCs5ariPZT-LNCUYpixMC3NxI=",
1811313:"IR_IQPnIM1TI8h4USnBLuUtC72cQ-u4Fwvlu3q5npA0=",
1804841:"kE8FpmTv8d8sRPIswQjCMaqunLUGoRNW6OrYU9JWZ4w=",
1881925:"_B__AgO34W7urog-thBu7mRKj3AY46D8L26yedUwf0I=",
1877711:"dLOM7DyrEnUsW-Q7OM6LXxZsbCFhjmyhsVT3P7oADqk=",
1830894:"aM4bOtearz2GpURUxYKW23t_DlljFLzbfgWS-IRMB3U=",
1855191:"-IieSn1zKJ8P3XOjyAlRcD2KbeFl_BnQjHyCE7-356w=",
1821012:"Lt5wWqTM1q9gNAgME4T5-5oVptAstg9llB4A_iNAYMY=",
1844339:"M6glRgMP5Y8CZIs-MbyFvev5VKW-zbWyUMMt44QCzG4=",
1898468:"SS0XtthxP64E-z4oB1IsdrzJwu1PUq6hgFqP_u435AA=",
1883633:"0L_o75AEsOay_ggDJtOFWkgRpvFvM0snlDm9gep786I=",
1808742:"9BXraBysqT7QZLBjegET0e52WklQ7BBYWXvv8xpbvr8=",
1863450:"M0PgiJutAM_L9jvyfrGDWnbfJOXmhYt_skL0S88ngkU=",
1830190:"v-5GfMaI2ozfmef5BNO5hI-fEGwtKjuI1XcuTDh-wsg=",
1835544:"LI14DbKGBfJExlwLodr6fkV4Pv4eABWkEhzArPbPSR8=",
1820930:"zoTviAO0EACFC4rFereJuc0A-99Xf_uOdq3GiqUpoeU="}

    # Try connecting to the compeng4dn4 echo server. You need to change
    # the destination port to 50007 in the connect function below.
    # SERVER_HOSTNAME = 'compeng4dn4.mooo.com'

    # RECV_BUFFER_SIZE = 5 # Used for recv.    
    RECV_BUFFER_SIZE = 1024 # Used for recv.

    def __init__(self):
        self.get_socket()
        self.connect_to_server()
        # todo: replace function with one that sends once then closes connection
        #self.send_console_input_forever()
        #done
        self.send_console_input_once()

    def get_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Allow us to bind to the same port right away.            
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind the client socket to a particular address/port.
            # self.socket.bind((Server.HOSTNAME, 40000))
                
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        try:
            # Connect to the server using its socket address tuple.
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))
            print("Connected to \"{}\" on port {}".format(Client.SERVER_HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered, i.e., ignore blank lines.
        while True:
            self.input_text = input("Input: ")
            if self.input_text != "":
                break
            print(f"Command entered: {self.input_text}")
            # todo: print message explaining command verbosely (i.e. Requirement 3)
    
    # todo: write a version of this function that only sends input once and then closes connection
    #done
    def send_console_input_once(self):
        try:
            self.get_console_input()
            self.connection_send()
            self.connection_receive()
        except (KeyboardInterrupt, EOFError):
            print()
            print("Closing server connection ...")
            # If we get and error or keyboard interrupt, make sure
            # that we close the socket.
            self.socket.close()
            sys.exit(1)

    # def send_console_input_forever(self):
    #     while True:
    #         try:
    #             self.get_console_input()
    #             self.connection_send()
    #             self.connection_receive()
    #         except (KeyboardInterrupt, EOFError):
    #             print()
    #             print("Closing server connection ...")
    #             # If we get and error or keyboard interrupt, make sure
    #             # that we close the socket.
    #             self.socket.close()
    #             sys.exit(1)
                
    def connection_send(self):
        try:
            # Send string objects over the connection. The string must
            # be encoded into bytes objects first.
            self.socket.sendall(self.input_text.encode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self,key):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)
            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            encryption_key = encrptionKeys[key]
            encryption_key_bytes = encryption_key.encode('utf-8')
            fernet = Fernet(encryption_key_bytes)
            # todo: modify this to decrypt string from the bytes before printing (SEE assignment doc)
            # ?: Appropriate way of getting the key for decryption (since we can't grab it from the .csv)
            decrypted_message_bytes =fernet.decrypt(recvd_bytes)
            decrypted_message = decrypted_message_bytes.decode('utf-8')
            print("decrypted_message = ", decrypted_message)
            #print("Received: ", recvd_bytes.decode(Server.MSG_ENCODING))

        except Exception as msg:
            print(msg)
            sys.exit(1)