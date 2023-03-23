#!/usr/bin/env python3

########################################################################
#
# Simple File Request/Download Protocol
#
########################################################################
#
# When the client connects to the server and wants to request a file
# download, it sends the following message: 1-byte GET command + 1-byte
# filename size field + requested filename, e.g., 

# ------------------------------------------------------------------
# | 1 byte GET command  | 1 byte filename size | ... file name ... |
# ------------------------------------------------------------------

# The server checks for the GET and then transmits the requested file.
# The file transfer data from the server is prepended by an 8 byte
# file size field as follows:

# -----------------------------------
# | 8 byte file size | ... file ... |
# -----------------------------------

# The server needs to have REMOTE_FILE_NAME defined as a text file
# that the client can request. The client will store the downloaded
# file using the filename LOCAL_FILE_NAME. This is so that you can run
# a server and client from the same directory without overwriting
# files.

########################################################################

##
import os
import socket
import argparse
import threading
import time

########################################################################

# Define all of the packet protocol field lengths.

CMD_FIELD_LEN            = 1 # 1 byte commands sent from the client.
FILENAME_SIZE_FIELD_LEN  = 1 # 1 byte file name size field.
FILESIZE_FIELD_LEN       = 8 # 8 byte file size field.
    
# Define a dictionary of commands. The actual command field value must
# be a 1-byte integer. For now, we only define the "GET" command,
# which tells the server to send a file.

CMD = {"get" : 1, "put": 2, "list": 3, "bye": 4}

MSG_ENCODING = "utf-8"
SOCKET_TIMEOUT = 240

UNIVERSAL_UDP_PORT = 50001

SERVICE_DISCORERY_MSG = 'SERVICE DISCOVERY'

########################################################################
# recv_bytes frontend to recv
########################################################################

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
    
######################################################################
# UTILS
########################################################################

def send_file_contents(connection, dir_path, filename, header = b''):
    # See if we can open the requested file. If so, send it.
    
    # If we can't find the requested file, shutdown the connection
    # and wait for someone else.
    try:
        file = open(os.path.join(dir_path, filename), 'r').read()
    except FileNotFoundError:
        print(Server.FILE_NOT_FOUND_MSG)
        connection.close()                   
        return

    # Encode the file contents into bytes, record its size and
    # generate the file size field used for transmission.
    file_bytes = file.encode(MSG_ENCODING)
    file_size_bytes = len(file_bytes)
    file_size_field = file_size_bytes.to_bytes(FILESIZE_FIELD_LEN, byteorder='big')

    # Create the packet to be sent with the header field.
    pkt = header + file_size_field + file_bytes
    
    try:
        # Send the packet to the connected client.
        connection.sendall(pkt)
        print("Sending file: ", filename)
        print("file size field: ", file_size_field.hex(), "\n")
        # time.sleep(20)
    except socket.error:
        # If the client has closed the connection, close the
        # socket on this end.
        print("Closing client connection ...")
        connection.close()
        return

def recv_file(socket, dir_path, filename):
    # Process the file transfer repsonse from the server
        
    # Read the file size field returned by the server.
    status, file_size_bytes = recv_bytes(socket, FILESIZE_FIELD_LEN)
    if not status:
        print("File size not received. Closing connection ...")            
        socket.close()
        return

    print("File size bytes = ", file_size_bytes.hex())
    if len(file_size_bytes) == 0:
        socket.close()
        return

    # Make sure that you interpret it in host byte order.
    file_size = int.from_bytes(file_size_bytes, byteorder='big')
    print("File size = ", file_size)

    socket.settimeout(4)                                  
    status, recvd_bytes_total = recv_bytes(socket, file_size)
    if not status:
        print("No bytes received. Closing connection ...")            
        socket.close()
        return
    print("recvd_bytes_total = ", recvd_bytes_total)
    # Receive the file itself.
    try:
        # Create a file using the received filename and store the
        # data.
        print("Received {} bytes. Creating file: {}" \
                .format(len(recvd_bytes_total), filename))

        with open(os.path.join(dir_path, filename), 'w') as f:
            recvd_file = recvd_bytes_total.decode(MSG_ENCODING)
            f.write(recvd_file)
        print(recvd_file)
    except KeyboardInterrupt:
        print()
        exit(1)

######################################################################
# SERVER
########################################################################

class Server:

    # HOSTNAME = "127.0.0.1"
    HOSTNAME = "0.0.0.0"

    # Specifies a TCP socket port and UDP socket port
    TCP_PORT = 50000

    # File sharing service name
    BYTE_ENCODED_SERVICE_NAME = f"Group 54's File Sharing Service (PORT {TCP_PORT})".encode(MSG_ENCODING)

    RECV_SIZE = 1024
    BACKLOG = 5

    FILE_NOT_FOUND_MSG = "Error: Requested file is not available!"

    # Config constant that names the file sharing directory
    FILE_DIRECTORY = 'server_files'

    def __init__(self):
        self.CODE_TO_CMD_HANDLER = {
            1: self.handle_get_command,
            2: self.handle_put_command,
            3: self.handle_list_command,
            4: self.handle_bye_command
        }

        print(f"Files available for sharing: {os.listdir(Server.FILE_DIRECTORY)}")

        self.tcp_socket = self.create_listen_socket(
            socket.SOCK_STREAM,
            Server.TCP_PORT,
            'file sharing connections'
        )
        self.tcp_socket.setblocking(False)
        self.tcp_socket.listen(Server.BACKLOG)

        self.udp_socket = self.create_listen_socket(
            socket.SOCK_DGRAM,
            UNIVERSAL_UDP_PORT,
            'service discovery messages'
        )
        self.process_connections_forever()

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
    
    def remove_client(self, client):
        self.tcp_connected_clients.remove(client)
        client[0].close()

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
        
    def handle_get_command(self, connection):
        print(f"Handling get command")
        try:
            size = self.get_filename_size(connection)
            filename = self.read_filename(connection, size)
            send_file_contents(connection, Server.FILE_DIRECTORY, filename)
        except Exception as err:
            print(err)

    def get_filename_size(self, connection):
        # GET command is good. Read the filename size (bytes).
        status, filename_size_field = recv_bytes(connection, FILENAME_SIZE_FIELD_LEN)
        if not status:
            raise Exception("Didn't receive filename size.")
        filename_size_bytes = int.from_bytes(filename_size_field, byteorder='big')
        if not filename_size_bytes:
            raise Exception("Filename size empty.")
        print('Filename size (bytes) = ', filename_size_bytes)

        return filename_size_bytes

    def read_filename(self, connection, filename_size_bytes):
        # Now read and decode the requested filename.
        status, filename_bytes = recv_bytes(connection, filename_size_bytes)
        if not status or not filename_bytes:
            raise Exception("Status or filename_bytes empty")

        filename = filename_bytes.decode(MSG_ENCODING)
        print('Requested filename = ', filename)

        return filename

    def handle_list_command(self, connection):
        print(f"Handling `list` command")
        dir_list = os.listdir(Server.FILE_DIRECTORY)
        try:
            connection.sendall('\t'.join(dir_list).encode(MSG_ENCODING))
        except socket.error:
            # If the client has closed the connection, close the
            # socket on this end.
            print("Closing client connection ...")
            connection.close()
            return
        except Exception as msg:
            print(msg)

    def handle_put_command(self, connection):
        print(f"Handling `put` command")
        size = self.get_filename_size(connection)
        filename = self.read_filename(connection, size)
        recv_file(connection, Server.FILE_DIRECTORY, filename)

    def handle_bye_command(self, connection):
        print(f"Handling `bye` command")
        print("Closing client connection ...")
        connection.close()

    

########################################################################
# CLIENT
########################################################################

class Client:

    RECV_SIZE = 1024
    RECV_TIMEOUT = 1

    # Define the local file name where the downloaded file will be
    # saved.
    # DOWNLOADED_FILE_NAME = "filedownload.txt"

    FILE_DIRECTORY = 'client_files'

    BROADCAST_ADDR_PORT = ('255.255.255.255', UNIVERSAL_UDP_PORT)
    BYTE_ENCODED_DISCOVERY_MSG = SERVICE_DISCORERY_MSG.encode(MSG_ENCODING)

    
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

    def __init__(self):
        self.CMD_TO_HANDLER = {
            "scan": self.handle_scan_cmd,
            "connect": self.handle_connect_cmd,
            "llist": self.handle_llist_cmd,
            "rlist": self.handle_rlist_cmd,
            "put": self.handle_put_cmd,
            "get": self.handle_get_cmd,
            "bye": self.handle_bye_cmd
        }
        
        self.get_socket()
        while True:
            self.get_console_input()
            self.handle_cmd()

    def get_socket(self):

        try:
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Arrange to send a broadcast service discovery packet.
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except Exception as msg:
            print(msg)
            exit()

    def handle_cmd(self):
        try:
            self.CMD_TO_HANDLER[self.parsed_cmd[0]]()
        except KeyError:
            print(
                "Invalid command. Commands available: \n \
                scan \n \
                connect <ip address> <port> \n \
                llist \n \
                rlist \n \
                put <filename> \n \
                get <filename> \n \
                bye \
                "
            )

        except socket.error:
            print("Server socket closed. Can't execute command")

    def handle_scan_cmd(self):
        try:
            # broadcast 'SERVICE DISCOVERY' message
            self.udp_socket.sendto(Client.BYTE_ENCODED_DISCOVERY_MSG, Client.BROADCAST_ADDR_PORT)
            self.udp_socket.settimeout(Client.RECV_TIMEOUT)
            msg_bytes, (addr, port) = self.udp_socket.recvfrom(Client.RECV_SIZE)
            msg = msg_bytes.decode(MSG_ENCODING)

            print(f"{msg} found at IP address/port: {addr}/{port}")

        except socket.timeout:
            print("No services discovered")

    def handle_connect_cmd(self):
        # make connection to requested destination
        try:
            self.tcp_socket.connect((self.parsed_cmd[1], int(self.parsed_cmd[2])))
        except IndexError:
            print(f"Expected 2 arguments. Received {len(self.parsed_cmd[1:])}")
        # except Exception as msg:
        #     print(msg)

    def construct_ft_header_pkt(self):
        cmd = self.parsed_cmd[0]
        filename = self.parsed_cmd[1]
        # Create the packet cmd field.
        cmd_field = CMD[cmd].to_bytes(CMD_FIELD_LEN, byteorder='big')

        # Create the packet filename field.
        filename_field_bytes = filename.encode(MSG_ENCODING)

        # Create the packet filename size field.
        filename_size_field = len(filename_field_bytes).to_bytes(FILENAME_SIZE_FIELD_LEN, byteorder='big')

        # Create the packet.
        print("CMD field: ", cmd_field.hex())
        print("Filename_size_field: ", filename_size_field.hex())
        print("Filename field: ", filename_field_bytes.hex())
        
        return cmd_field + filename_size_field + filename_field_bytes

    def handle_get_cmd(self):
        # Generate a file transfer request to the server
        pkt = self.construct_ft_header_pkt()

        # Send the request packet to the server.
        self.tcp_socket.sendall(pkt)

        # receive file function
        try:
            self.tcp_socket.settimeout(SOCKET_TIMEOUT)
            recv_file(self.tcp_socket, Client.FILE_DIRECTORY, self.parsed_cmd[1])
        except socket.timeout:
            print("Socket connection timed out")

    def handle_llist_cmd(self):
        print(f"local files: {os.listdir(Client.FILE_DIRECTORY)}")

    def handle_rlist_cmd(self): #Q is this working to connect to server?
        try:
            # Create the packet cmd field.
            cmd_field = CMD["list"].to_bytes(CMD_FIELD_LEN, byteorder='big')

            # Send the request packet to the server
            self.tcp_socket.sendall(cmd_field)
            self.tcp_socket.settimeout(Client.RECV_TIMEOUT)

            recvd_bytes = self.tcp_socket.recv(Client.RECV_SIZE)
            recvd_msg = recvd_bytes.decode(MSG_ENCODING)
            
            print(f"Server directory: {recvd_msg}")
        
        except Exception as msg:
            print(msg)
        
    def handle_put_cmd(self):
        pkt = self.construct_ft_header_pkt()
        send_file_contents(self.tcp_socket, Client.FILE_DIRECTORY, self.parsed_cmd[1], pkt)

    def handle_bye_cmd(self):
        # Create the packet cmd field
        cmd_field = CMD["bye"].to_bytes(CMD_FIELD_LEN, byteorder='big')
        # Send the request packet to the server
        self.tcp_socket.sendall(cmd_field)


            
########################################################################

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################






