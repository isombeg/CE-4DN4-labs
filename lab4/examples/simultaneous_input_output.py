import threading
import queue
import time

def get_input(input_queue):
    while True:
        user_input = input("Console:> ")
        input_queue.put(user_input)
        # Clear the console after reading the user input
        print("\033[H\033[J", end='')

def display_messages(output_queue):
    while True:
        # Check if there's any message to display
        if not output_queue.empty():
            message = output_queue.get()
            print(message)

        # Display status message
        print("Status message {}".format(time.time()))

        # Clear the console
        print("\033[H\033[J", end='')

        # Move cursor to the bottom of the screen
        print("\033[{};0H".format(25))

        # Wait for a short amount of time before displaying the next message
        time.sleep(1)

if __name__ == '__main__':
    # Create the input and output queues
    input_queue = queue.Queue()
    output_queue = queue.Queue()

    # Start the input thread
    input_thread = threading.Thread(target=get_input, args=(input_queue,))
    input_thread.start()

    # Start the output thread
    output_thread = threading.Thread(target=display_messages, args=(output_queue,))
    output_thread.start()

    while True:
        # Check if there's any user input
        if not input_queue.empty():
            user_input = input_queue.get()
            output_queue.put(user_input)

        # Wait for a short amount of time before checking the queues again
        time.sleep(0.1)
