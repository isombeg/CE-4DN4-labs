import socket
import struct
import threading

# Define multicast group and port number
MULTICAST_GROUP = '224.3.29.71'
PORT = 5001

# Create a UDP socket and bind it to a local address and port
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('localhost', PORT))

# Set the time-to-live (TTL) for multicast packets to 1
ttl = struct.pack('b', 1)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

# Join the multicast group
membership = socket.inet_aton(MULTICAST_GROUP) + socket.inet_aton('0.0.0.0')
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)

# Function to send messages to the multicast group
def send_message():
    while True:
        message = input('Enter a message to send: ')
        sock.sendto(message.encode(), (MULTICAST_GROUP, PORT))

# Function to receive messages from the multicast group
def receive_message():
    while True:
        data, address = sock.recvfrom(1024)
        print(f'Received message from {address}: {data.decode()}')

# Start two threads for sending and receiving messages
send_thread = threading.Thread(target=send_message)
receive_thread = threading.Thread(target=receive_message)
send_thread.start()
receive_thread.start()
