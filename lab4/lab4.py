#!/usr/bin/env python3

########################################################################

import json
import queue
import socket
import argparse
import sys
import threading
import time
import struct
import ipaddress

########################################################################
# Multicast Address and Port
########################################################################

# MULTICAST_ADDRESS = "239.0.0.10"
# # MULTICAST_ADDRESS = "239.0.0.11"
# MULTICAST_PORT    =  2000

# # Make them into a tuple.
# MULTICAST_ADDRESS_PORT = (MULTICAST_ADDRESS, MULTICAST_PORT)

# Ethernet/Wi-Fi interface address
IFACE_ADDRESS = "192.168.1.22"

CMD_FIELD_LEN = 1
CHATROOM_NAME_SIZE_FIELD_LEN  = 1 # 1 byte file name size field.
IP_ADDRESS_SIZE_BYTES = 4

SOCKET_TIMEOUT = 240

CRDP_PORT = 50001

SERVICE_DISCORERY_MSG = 'SERVICE DISCOVERY'

MSG_ENCODING = "utf-8"

CMD = {"getdir" : 1, "makeroom": 2, "deleteroom": 3, "chat": 4}

# Call recv to read bytecount_target bytes from the socket. Return a
# status (True or False) and the received butes (in the former case).
def recv_bytes(sock, bytecount_target):
    # Be sure to timeout the socket if we are given the wrong
    # information.
    sock.settimeout(SOCKET_TIMEOUT)
    try:
        byte_recv_count = 0 # total received bytes
        recv_bytes = b''    # complete received message
        while byte_recv_count < bytecount_target:
            # Ask the socket for the remaining byte count.
            new_bytes = sock.recv(bytecount_target-byte_recv_count)
            # If ever the other end closes on us before we are done,
            # give up and return a False status with zero bytes.
            if not new_bytes:
                return(False, b'')
            byte_recv_count += len(new_bytes)
            recv_bytes += new_bytes
        # Turn off the socket timeout if we finish correctly.
        sock.settimeout(None)            
        return (True, recv_bytes)
    # If the socket times out, something went wrong. Return a False
    # status.
    except socket.timeout:
        sock.settimeout(None)        
        print("recv_bytes: Recv socket timeout!")
        return (False, b'')

########################################################################
# Multicast Sender
########################################################################

class Server:

    HOSTNAME = socket.gethostname()
    TCP_PORT = 50000

    TIMEOUT = 2
    RECV_SIZE = 256
    
    MESSAGE =  HOSTNAME + " multicast beacon: "
    MESSAGE_ENCODED = MESSAGE.encode('utf-8')

    BYTE_ENCODED_SERVICE_NAME = f"Group 27's Chatting Service/{HOSTNAME}/{TCP_PORT}".encode(MSG_ENCODING)

    # Create a 1-byte maximum hop count byte used in the multicast
    # packets (i.e., TTL, time-to-live).
    TTL = 1 # Hops
    TTL_BYTE = TTL.to_bytes(1, byteorder='big')
    # Or: TTL_BYTE = struct.pack('B', TTL)
    # Or: TTL_BYTE = b'01'

    # Define a dictionary of commands. The actual command field value must
    # be a 1-byte integer. For now, we only define the "GET" command,
    # which tells the server to send a file.

    def __init__(self):
        # init a command handler/dispatcher
        self.CODE_TO_CMD_HANDLER = {
            1: self.handle_getdir,
            2: self.handle_makeroom,
            3: self.handle_deleteroom,
        }

        # create chatroom directory.
        # format: (chatroom name) -> (multicast ip, port)
        self.directory = dict()

        # create multicast send socket
        self.create_send_socket()

        # create tcp socket to handle commands
        # self.create_tcp_socket()
        self.tcp_socket = self.create_listen_socket(
            socket.SOCK_STREAM,
            Server.TCP_PORT,
            'chat client connections'
        )
        self.tcp_socket.setblocking(False)
        self.tcp_socket.listen(Server.BACKLOG)

        self.udp_socket = self.create_listen_socket(
            socket.SOCK_DGRAM,
            CRDP_PORT,
            'service discovery messages'
        )
        
        # handle tcp connections forever
        self.process_connections_forever()
        # ! logic inside function will be moved to client's chat mode
        # self.send_messages_forever()

    def create_listen_socket(self, socket_kind, port, message_type):
        try:

            # Create server listen socket
            sock = socket.socket(socket.AF_INET, socket_kind)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind( (Server.HOSTNAME, port) )
            print("Listening for {} on port {} ...".format(message_type, port))

            return sock
        except Exception as msg:
            print(msg)
            exit()
    
    def create_send_socket(self, chatroom_name, address, port):
        # modify function to only send data when prompted to specific group
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            ############################################################
            # Set the TTL for multicast.

            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)

            ############################################################
            # Bind to the interface that will carry the multicast
            # packets, or you can let the os decide, which is usually
            # ok for a laptop or simple desktop.

            # self.multicast_socket.bind((IFACE_ADDRESS, 30000))
            self.multicast_socket.bind((address, port)) # Have the system pick a port number.
            # store this port in directory
            #dict[chatroom_name] = sock
            self.sockdic[chatroom_name] = sock
            

        except Exception as msg:
            print(msg)
            sys.exit(1)

    # handle getdir command
    def handle_getdir(self, connection):
        try:
            connection.sendall(
                json.dumps(self.directory).encode(MSG_ENCODING)
            )
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            connection.close()
            return
        except Exception as msg:
            print(msg)
    
    # handle makeroom command
    def handle_makeroom(self, connection):
        # get chatroom name
        chatroom_name = self.get_chatroom_name(connection)
        
        addr_port = connection.recv(Server.RECV_BUFFER_SIZE).decode(MSG_ENCODING).split("/")

        # create socket
        self.create_send_socket(chatroom_name, addr_port[0], addr_port[1])

        self.directory[chatroom_name] = addr_port
        return
    
    def get_chatroom_name(self, connection):
        chatroom_name_size = self.get_chatroom_name_size(connection)

        status, chatroom_name_bytes = recv_bytes(connection, chatroom_name_size)
        if not status or not chatroom_name_bytes:
            raise Exception("Status or chatroom_name_bytes empty")

        chatroom_name = chatroom_name_bytes.decode(MSG_ENCODING)
        print('Received chatroom name = ', chatroom_name)

        return chatroom_name

    def get_chatroom_name_size(self, connection):
        # Read the chatroom name size (bytes).
        status, chatroom_name_size_field = recv_bytes(connection, CHATROOM_NAME_SIZE_FIELD_LEN)
        if not status:
            raise Exception("Didn't receive chatroom name size.")
        chatroom_name_size_bytes = int.from_bytes(chatroom_name_size_field, byteorder='big')
        if not chatroom_name_size_bytes:
            raise Exception("Chatroom name size empty.")
        print('Chatroom size (bytes) = ', chatroom_name_size_bytes)

        return chatroom_name_size_bytes
    
    def get_addr(self, connection):
        status, addr_bytes = recv_bytes(connection, IP_ADDRESS_SIZE_BYTES)
        if not status or not addr_bytes:
            raise Exception("Status or addr_bytes empty")

        addr = addr_bytes.decode(MSG_ENCODING)
        print('Received ip address = ', addr)

        return addr
    
    # deleteroom command
    def handle_deleteroom(self, connection):
        chatroom_name = self.get_chatroom_name(connection)
        try:
            if chatroom_name in self.directory:
                #close socket with chatroom
                self.directory[chatroom_name].close()
                #remove chatroom from directory and socket from other dictionary
                del self.directory[chatroom_name]
                del self.sockdic[chatroom_name]
        except KeyError:
            connection.sendall(b"Error: Invalid chatroom name")
    
    # handle chat
    def handle_chat(self, connection):
        # return the address and client
        chatroom_name = self.get_chatroom_name(connection)
        connection.sendall(self.directory[chatroom_name].encode(MSG_ENCODING))

    # handle connections
    def process_connections_forever(self):
        try:
            self.tcp_connected_clients = []
            # check for new connection on both TCP and UDP sockets
            #start a thread to check for new UDP connections
            udp_thread = threading.Thread(target=self.udp_server)
            udp_thread.start()
            while True:
                #check for new connection on the TCP socket
                self.check_for_new_tcp_connections()
                self.service_tcp_clients()
        except KeyboardInterrupt:
            print("Exiting server...")
        finally:
            self.tcp_socket.close()
            self.udp_socket.close()

    def udp_server(self):
        while True:
            #check for new connection on the UDP socket
            self.check_for_new_udp_connections()

    def check_for_new_udp_connections(self):
        try:
            # Check if a new connection is available.
            client = self.udp_socket.recvfrom(Server.RECV_SIZE)

            # Announce that a new connection has been accepted.
            print("\nUDP Connection received from {}.".format(client[1]))

            # Service UDP connection right away
            self.service_udp_client(client)
            
        except socket.error:
            # If an exception occurs, there are no new
            # connections. Continue on.
            pass

    def service_udp_client(self, client):
        try:
            # Check for available incoming data.
            recvd_bytes, address_port = client
            recvd_str = recvd_bytes.decode(MSG_ENCODING)
            print(f"Message received from {address_port}: {recvd_str}")

            if recvd_str == SERVICE_DISCORERY_MSG:
                self.udp_socket.sendto(Server.BYTE_ENCODED_SERVICE_NAME, address_port)
                
        except socket.error:
            # If no bytes are available, catch the
            # exception. Continue on so that we can check
            # other connections.
            pass

    def check_for_new_tcp_connections(self):
        try:
            # Check if a new connection is available.
            new_client = self.tcp_socket.accept()
            new_connection, new_address_port = new_client

            # Announce that a new connection has been accepted.
            print("\nConnection received from {} on port {}.".format(new_address_port[0], new_address_port[1]))

            # Set the new socket to non-blocking. 
            new_connection.setblocking(False)

            # Add the new connection to our connected_clients
            # list.
            self.tcp_connected_clients.append(new_client)
            
        except socket.error:
            # If an exception occurs, there are no new
            # connections. Continue on.
            pass

    def service_tcp_clients(self):
        # Iterate through the list of connected clients, servicing
        # them one by one. Since we may delete from the list, make a
        # copy of it first.
        current_client_list = self.tcp_connected_clients.copy()

        for client in current_client_list:
            connection, address_port = client
            try:
                cmd_field = connection.recv(CMD_FIELD_LEN)
                # If the read fails, give up.
                if len(cmd_field) == 0:
                    print(f"Received nothing. Passing on {address_port} ...")
                    # self.remove_client(client)
                    continue
                # Execute clients command.
                self.handle_client_command(connection, cmd_field)
                
            except socket.error:
                # If no bytes are available, catch the
                # exception. Continue on so that we can check
                # other connections.
                pass
    
    def handle_client_command(self, connection, cmd_field):
        # Convert the command to our native byte order.
        cmd = int.from_bytes(cmd_field, byteorder='big')
        # Give up if we don't get a valid command.
        if cmd not in self.CODE_TO_CMD_HANDLER:
            print("No valid command received.")
            return
        
        self.CODE_TO_CMD_HANDLER[cmd](connection)

    def send_messages_forever(self):
        try:
            beacon_sequence_number = 1
            while True:
                print("Sending multicast beacon {} {}".format(beacon_sequence_number, MULTICAST_ADDRESS_PORT))
                beacon_bytes = Sender.MESSAGE_ENCODED + str(beacon_sequence_number).encode('utf-8')

                ########################################################
                # Send the multicast packet
                self.socket.sendto(beacon_bytes, MULTICAST_ADDRESS_PORT)

                # Sleep for a while, then send another.
                time.sleep(Sender.TIMEOUT)
                beacon_sequence_number += 1
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

########################################################################
# Multicast Receiver 
########################################################################
#
# There are two things that we need to do:
#
# 1. Signal to the os that we want a multicast group membership, so
# that it will capture multicast packets arriving on the designated
# interface. This will also ensure that multicast routers will forward
# packets to us. Note that multicast is at layer 3, so ports do not
# come into the picture at this point.
#
# 2. Bind to the appopriate address/port (L3/L4) so that packets
# arriving on that interface will be properly filtered so that we
# receive packets to the designated address and port.
#
#########################################
# IP add multicast group membership setup
#########################################
#
# Signal to the os that you want to join a particular multicast group
# address on specified interface. Done via setsockopt function call.
# The multicast address and interface (address) are part of the add
# membership request that is passed to the lower layers.
#
# This is done via MULTICAST_ADDRESS from above and RX_IFACE_ADDRESS
# defined below.
#
# If you choose "0.0.0.0" for the Rx interface, the system will select
# the interface, which will probably work ok. In more complex
# situations, where, for example, you may have multiple network
# interfaces, you may have to specify the interface explicitly by
# using its address, as shown in the examples below.

# RX_IFACE_ADDRESS = "0.0.0.0"
# RX_IFACE_ADDRESS = "127.0.0.1"
RX_IFACE_ADDRESS = IFACE_ADDRESS 

##############################################
# Multicast receiver bind (i.e., filter) setup
##############################################
#
# The receiver socket bind address. This is used at the IP/UDP level to
# filter incoming multicast receptions. Using "0.0.0.0" should work
# ok. Binding using the unicast address, e.g., RX_BIND_ADDRESS =
# "192.168.1.22", fails (Linux) since arriving packets don't carry this
# destination address.
# 

# RX_BIND_ADDRESS = MULTICAST_ADDRESS # Ok for Linux/MacOS, not for Windows 10.
RX_BIND_ADDRESS = "0.0.0.0"

# Receiver socket will bind to the following.
# RX_BIND_ADDRESS_PORT = (RX_BIND_ADDRESS, MULTICAST_PORT)

########################################################################

class Client:

    RECV_SIZE = 256

    def __init__(self):
        print("Bind address/port = ", RX_BIND_ADDRESS_PORT)
        
        # create tcp socket
        self.create_tcp_socket()

        # handle commands
        self.CMD_TO_HANDLER = {
            "connect": self.handle_connect_cmd,
            "bye": self.handle_bye_cmd,
            "name": self.handle_name_cmd,
            "chat": self.handle_chat_cmd,
            "getdir": self.handle_getdir_cmd,
            "makeroom": self.handle_makeroom_cmd,
            "deleteroom": self.handle_deleteroom_cmd
        }
        
        while True:
            self.get_console_input()
            self.handle_cmd()
        
        # todo: change to only make udp socket upon joining chat
        #self.get_socket()
    def get_socket(self):

        try:
            if  not self.input_queue.empty():
                self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Arrange to send a broadcast service discovery packet.
                self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except Exception as msg:
            print(msg)
            exit()

        # todo: move this to only when client joins chat room
        # self.receive_forever()

    def create_tcp_socket(self):
        try:
            # Create server listen socket
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        except Exception as msg:
            print(msg)
            exit()

    def get_console_input(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered, i.e., ignore blank lines.
        input_text = input("client > ")
        if input_text == "":
            # throw exception
            raise Exception("Empty command")
        print(f"Command entered: {input_text}")
        # print message explaining command verbosely

        # split command for parsing
        self.parsed_cmd = input_text.split()

    def handle_cmd(self):
        try:
            self.CMD_TO_HANDLER[self.parsed_cmd[0]]()
        except KeyError:
            print(
                "Invalid command. Commands available: \n \
                connect <ip address> <port> \n \
                getdir\
                makeroom\
                deleteroom\
                name\
                chat\
                bye \
                "
            )

        except socket.error:
            print("Server socket closed. Can't execute command")
    
    def handle_connect_cmd(self):
        # scan for service
        crds_addr, crds_port = self.scan_for_crds()
        # connect to client
        self.tcp_socket.connect((crds_addr, crds_port))
        return
    
    def scan_for_crds(self):
        try:
            # broadcast 'SERVICE DISCOVERY' message
            self.udp_socket.sendto(Client.BYTE_ENCODED_DISCOVERY_MSG, Client.BROADCAST_ADDR_PORT)
            self.udp_socket.settimeout(Client.RECV_TIMEOUT)
            msg_bytes, i = self.udp_socket.recvfrom(Client.RECV_SIZE)
            parsed_msg = msg_bytes.decode(MSG_ENCODING).split('/')

            print(f"Found {parsed_msg[0]} at IP address/port: {parsed_msg[1]}/{parsed_msg[2]}")
            return parsed_msg[1], int(parsed_msg[2])

        except socket.timeout:
            print("No services discovered")
        
    def handle_bye_cmd(self):
        # Create the packet cmd field
        cmd_field = CMD["bye"].to_bytes(CMD_FIELD_LEN, byteorder='big')
        # Send the request packet to the server
        self.tcp_socket.sendall(cmd_field)
        return
    
    def handle_name_cmd(self):
        self.chat_name = self.parsed_cmd[1]
        return
    
    def handle_chat_cmd(self):
        try:
            # Create the packet cmd field.
            addr_port_list = self.send_only_cmd_field("chat").split("/")
            self.get_multicast_socket(addr_port_list[0], int(addr_port_list[1]))
            self.chat()
            #self.send_forever()

        
        except Exception as msg:
            print(msg)
    
    def chat(self):
        # Create the input and output queues
        self.input_queue = queue.Queue()
        self.output_queue = queue.Queue()

        # Start the input thread
        input_thread = threading.Thread(target=self.send_forever)
        input_thread.start()

        # Start the output thread
        output_thread = threading.Thread(target=self.receive_forever)
        output_thread.start()

        while True:
            # Check if there's any user input
            if not self.input_queue.empty():
                user_input = self.input_queue.get()
                self.output_queue.put(user_input)

            # Wait for a short amount of time before checking the queues again
            time.sleep(0.1)
            pass
    def get_input(input_queue):
        while True:
            user_input = input("Console:> ")
            input_queue.put(user_input)
            # Clear the console after reading the user input
            print("\033[H\033[J", end='')
    
    def send_forever(self):
        self.beacon_sequence_number = 1
        input = self.get_input()
        self.send_messages(input)

    def send_messages(self):
        try:
            beacon_bytes = Client.MESSAGE_ENCODED + str(self.beacon_sequence_number).encode('utf-8')

            ########################################################
            # Send the multicast packet
            socket.sendto(beacon_bytes, MULTICAST_ADDRESS_PORT)

            # Sleep for a while, then send another.
            time.sleep(Client.TIMEOUT)
            self.beacon_sequence_number += 1
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            socket.close()
            sys.exit(1)

    def receive_forever(self):
        while True:
            try:
                data, address_port = self.multicast_socket.recvfrom(Client.RECV_SIZE)
                self.display_messages(data.decode(MSG_ENCODING))
            except KeyboardInterrupt:
                print(); exit()
            except Exception as msg:
                print(msg)
                sys.exit(1)

    def display_messages(self, message):
        while True:
            # Check if there's any message to display
            if not self.output_queue.empty():
                message = self.output_queue.get()
                print(message)

            # Display status message
            print(message)

            # Clear the console
            print("\033[H\033[J", end='')

            # Move cursor to the bottom of the screen
            print("\033[{};0H".format(25))

    def handle_getdir_cmd(self):
        try:
            # Create the packet cmd field.
            recvd_msg = self.send_only_cmd_field("getdir")
            
            print(f"CRDS directory: {recvd_msg}")
        
        except Exception as msg:
            print(msg)

    def send_only_cmd_field(self, cmd):
        # Create the packet cmd field.
        cmd_field = CMD[cmd].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Send the request packet to the server
        self.tcp_socket.sendall(cmd_field)
        self.tcp_socket.settimeout(Client.RECV_TIMEOUT)

        recvd_bytes = self.tcp_socket.recv(Client.RECV_SIZE)
        recvd_msg = recvd_bytes.decode(MSG_ENCODING)
        return recvd_msg

    def handle_makeroom_cmd(self):
        try:
            chatroom_name_size_field = len(self.parsed_cmd[1]).to_bytes(CHATROOM_NAME_SIZE_FIELD_LEN, byteorder='big')
            chatroom_name_field = self.parsed_cmd[1].encode(MSG_ENCODING)
            addr_port_field = f"{self.parsed_cmd[2]}/{self.parsed_cmd[3]}".encode(MSG_ENCODING)

            self.tcp_socket.sendall(CMD["makeroom"] 
                + chatroom_name_size_field 
                + chatroom_name_field
                + addr_port_field)
            
        except socket.error as err:
            print(f"Caught socket error: {err}")
        except Exception as err:
            print("Couldn't handle `makeroom`", err)
    
    def handle_deleteroom_cmd(self):
        try:
            chatroom_name_size_field = len(self.parsed_cmd[1]).to_bytes(CHATROOM_NAME_SIZE_FIELD_LEN, byteorder='big')
            chatroom_name_field = self.parsed_cmd[1].encode(MSG_ENCODING)
            self.tcp_socket.sendall(CMD["deleteroom"] 
                                        + chatroom_name_size_field 
                                        + chatroom_name_field
                                        )
        except socket.error as err:
            print(f"Caught socket error: {err}")
        except Exception as err:
            print("Couldn't handle `deleteroom`", err)
    
        return
    def get_multicast_socket(self, addr_port):
        try:
            self.multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.multicast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

            ############################################################            
            # Bind to an address/port. In multicast, this is viewed as
            # a "filter" that deterimines what packets make it to the
            # UDP app.
            ############################################################            
            self.multicast_socket.bind(RX_BIND_ADDRESS, addr_port[1])

            ############################################################
            # The multicast_request must contain a bytes object
            # consisting of 8 bytes. The first 4 bytes are the
            # multicast group address. The second 4 bytes are the
            # interface address to be used. An all zeros I/F address
            # means all network interfaces. They must be in network
            # byte order.
            ############################################################
            multicast_group_bytes = socket.inet_aton(addr_port)
            # or
            # multicast_group_int = int(ipaddress.IPv4Address(MULTICAST_ADDRESS))
            # multicast_group_bytes = multicast_group_int.to_bytes(4, byteorder='big')
            # or
            # multicast_group_bytes = ipaddress.IPv4Address(MULTICAST_ADDRESS).packed
            print("Multicast Group: ", addr_port)

            # Set up the interface to be used.
            multicast_iface_bytes = socket.inet_aton(RX_IFACE_ADDRESS)

            # Form the multicast request.
            multicast_request = multicast_group_bytes + multicast_iface_bytes
            print("multicast_request = ", multicast_request)

            # You can use struct.pack to create the request, but it is more complicated, e.g.,
            # 'struct.pack("<4sl", multicast_group_bytes,
            # int.from_bytes(multicast_iface_bytes, byteorder='little'))'
            # or 'struct.pack("<4sl", multicast_group_bytes, socket.INADDR_ANY)'

            # Issue the Multicast IP Add Membership request.
            print("Adding membership (address/interface): ", addr_port[0],"/", RX_IFACE_ADDRESS)
            self.multicast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def receive_forever(self):
        while True:
            try:
                data, address_port = self.multicast_socket.recvfrom(Receiver.RECV_SIZE)
                address, port = address_port
                print("Received: {} {}".format(data.decode('utf-8'), address_port))
            except KeyboardInterrupt:
                print(); exit()
            except Exception as msg:
                print(msg)
                sys.exit(1)

########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'server': Server,'client': Client}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='sender or receiver role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################