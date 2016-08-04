import socket
import sys
import struct
import errno
import os
import hashlib
import signal
import time
from time import sleep

PORT        = 8080
BUFF_SIZE   = 4096

eintr = False

def sigterm_handler(*args):
    global eintr
    sys.stderr.write("Got SIGTERM, exiting...\n")
    eintr = True


def recv_payload(conn):
    """
    Receive checksum and payload from a socket
    """
    data = ""
    try:
        expected_checksum = conn.recv(16)
        while True:
            chunk =  conn.recv(BUFF_SIZE)
            if len(chunk) == 0:
                # Connection closed, recv does raise EOF
                break
            data += chunk
    except Exception, e:
        raise 

    return expected_checksum, data

def write_payload(data, expected_checksum):
    """
    Write corrupted payload on disk
    """
    filename = "expected-%s-%s" % (expected_checksum.encode("hex"), time.strftime("%s"))
    try:
        f = open(os.path.join("/tmp", "samples", filename), "wb")
        f.write(data)
        f.close()
    except Exception, e:
        raise


def run():
    """
    Main function which listens for incoming connections
    """

    global eintr
    if(len(sys.argv) < 2):
        sys.stderr.write("Please pass the IP to bind to")
        sys.exit(1)

    signal.signal(signal.SIGINT, sigterm_handler)
    
    if not os.path.exists("/tmp/samples"):
        os.mkdir("/tmp/samples", 755)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((sys.argv[1], PORT))
    except Exception, e:
        sys.stderr.write("Error while binding socket: %s\n" % str(e));
        sys.exit(1)
    
    s.listen(1)
    received = 0
    corrupted = 0
    while not eintr:
	    try:
                conn, addr = s.accept()
            except Exception, e:
                if not (type(e) == socket.error and e.errno == errno.EINTR):
                    sys.stderr.write("Error while listening on socket %s\n" % str(e))
                run = False
                continue

            try:
                expected_checksum, data = recv_payload(conn)
            except Exception, e:
                if not (type(e) == socket.error and e.errno == errno.EINTR):
                    sys.stderr.write("Error while receiving payload from socket: %s\n" % str(e))
                run = False
                continue
            
            # Checking md5sum, if it does not match, write the payload on disk
            checksum = hashlib.md5(data)
            if(checksum.digest() != expected_checksum):
                corrupted += 1 
                try:
                    write_payload(data, expected_checksum)
                except Exception, e:
                    sys.stderr.write("Could not write payload to disk: %s\n", str(e))
            else:
                received +=1
            
            sys.stderr.write("\rPacket received: %s, corrupted %s" % 
                             (received, corrupted))
    try: 
        conn.close()       
    except Exception, e:
        pass

if __name__ == '__main__':
    run()
