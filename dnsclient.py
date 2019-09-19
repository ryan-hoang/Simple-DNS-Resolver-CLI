from socket import *
from struct import *
import sys


def create_header():
    return ""


def create_question(addr):
    return addr


if __name__ == "__main__":
    address = ""
    try:
        address = sys.argv[1]
    except IndexError:
        print("No address specified. Usage: dnsclient <hostname>")
        sys.exit(0)

    header = create_header()
    question = create_question(address)
    datagram = header + question

    serverName = '8.8.8.8' # Google's public DNS server
    serverPort = 53 # The standard port for DNS requests

    socket = socket(AF_INET, SOCK_DGRAM)
    socket.settimeout(5.0)

    response = ""
    for i in range(0,3):
        try:
            print("Sending query, attempt {0}".format(i+1))
            socket.sendto(datagram, serverName, serverPort)
            socket.recvfrom()
            break
        except timeout:
            if i == 2:
                print("Timeout Error, no response after 3 attempts")
            continue




