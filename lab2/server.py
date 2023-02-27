import socket
import sys
import csv
import json
from cryptography.fernet import Fernet
########################################################################
# Echo Server class
########################################################################

class Server:

    # Set the server hostname used to define the server socket address
    # binding. Note that "0.0.0.0" or "" serves as INADDR_ANY. i.e.,
    # bind to all local network interfaces.
    HOSTNAME = "0.0.0.0"      # All interfaces.
    # HOSTNAME = "192.168.1.22" # single interface
    # HOSTNAME = "hornet"       # valid hostname (mapped to address/IF)
    # HOSTNAME = "localhost"    # local host (mapped to local address/IF)
    # HOSTNAME = "127.0.0.1"    # same as localhost
    
    # Server port to bind the listen socket.
    PORT = 50000
    
    RECV_BUFFER_SIZE = 1024 # Used for recv.
    MAX_CONNECTION_BACKLOG = 10

    # We are sending text strings and the encoding to bytes must be
    # specified.
    # MSG_ENCODING = "ascii" # ASCII text encoding.
    MSG_ENCODING = "utf-8" # Unicode text encoding.

    # Create server socket address. It is a tuple containing
    # address/hostname and port.
    SOCKET_ADDRESS = (HOSTNAME, PORT)

    # Command operations to database column mapping
    _OPS_TO_COLUMN_NAME = {
        "GMA": ["Midterm"],
        "GL1A": ["Lab 1"],
        "GL2A": ["Lab 2"],
        "GL3A": ["Lab 3"],
        "GL4A": ["Lab 4"],
        "GEA": ["Exam 1", "Exam 2", "Exam 3", "Exam 4"]
    }

    def __init__(self):
        self.load_grades()
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set socket layer socket options. This one allows us to
            # reuse the socket without waiting for any timeouts.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind(Server.SOCKET_ADDRESS)

            # Set socket to listen state.
            self.socket.listen(Server.MAX_CONNECTION_BACKLOG)
            print("Listening on port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            while True:
                # Block while waiting for accepting incoming TCP
                # connections. When one is accepted, pass the new
                # (cloned) socket info to the connection handler
                # function. Accept returns a tuple consisting of a
                # connection reference and the remote socket address.
                self.connection_handler(self.socket.accept())
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            # If something bad happens, make sure that we close the
            # socket.
            self.socket.close()
            sys.exit(1)

    def load_grades(self):
        reader = csv.DictReader('course_grades_2023.csv')
        self.grades_data = dict()
        self.student_count = 0

        for row in reader:
            self.grades_data[row['ID Number']] = row
            self.student_count += 1

    def connection_handler(self, client):
        # Unpack the client socket address tuple.
        connection, address_port = client
        print("-" * 72)
        print("Connection received from {}.".format(address_port))
        # Output the socket address.
        print(client)

        while True:
            try:
                # Receive bytes over the TCP connection. This will block
                # until "at least 1 byte or more" is available.
                recvd_bytes = connection.recv(Server.RECV_BUFFER_SIZE)
            
                # If recv returns with zero bytes, the other end of the
                # TCP connection has closed (The other end is probably in
                # FIN WAIT 2 and we are in CLOSE WAIT.). If so, close the
                # server end of the connection and get the next client
                # connection.
                if len(recvd_bytes) == 0:
                    print("Closing client connection ... ")
                    connection.close()
                    break
                
                # Decode the received bytes back into strings. Then output
                # them.
                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)

                data_entry, encryption_key = self.service(recvd_str)

                # Done_todo: encrypt data_entry
                fernet = Fernet(encryption_key.encode('utf-8'))
                Encrypted_data_entry= fernet.encrypt(data_entry.encode(Server.MSG_ENCODING))
                
                # Send the received bytes back to the client. We are
                # sending back the raw data.
                connection.sendall(Encrypted_data_entry)
                print("Sent: ", data_entry)

            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break

            except UserNotFoundError as err:
                print(err)
                print("Closing client connection ...")
                connection.close()
                break

    # Processes command and returns requested data
    def service(self, cmd):
        # parse command
        # parsed_cmd format: [STUDENT_ID, OPERATION]
        parsed_cmd = cmd.split()

        print(f"Received {parsed_cmd[1]} command from client")

        # check if student is authorized
        if not (parsed_cmd[0] in self.grades_data):
            raise UserNotFoundError("User not found")
        print("User found")

        # retrieve needed data
        if parsed_cmd[1] == "GG":
            return json.dumps(self.grades_data[parsed_cmd[0]]), self.grades_data[parsed_cmd[0]]['Key']
        
        # process data as needed
        return str(self.get_grade_average(parsed_cmd[1])), self.grades_data[parsed_cmd[0]]['Key']
    
    def get_grade_average(self, cmd_op):
        grade_tally = 0
        columns = Server._OPS_TO_COLUMN_NAME[cmd_op]

        for student_entry in self.grades_data:
            for col in columns:
                grade_tally += student_entry[col]

        return grade_tally/(self.student_count * len(columns))
    
class UserNotFoundError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message