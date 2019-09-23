from socket import *
from struct import *
import sys


def create_header():
    return ""


def create_question(addr):
    return addr


def parse_header(dns_response):
    return dns_response


def parse_question(dns_response):
    return dns_response


if __name__ == "__main__":
    address = ""
    try:
        address = sys.argv[1]
    except IndexError:
        print("No address specified. Usage: dnsclient <hostname>")
        sys.exit(0)

    print("Preparing DNS query..")
    header = create_header()
    question = create_question(address)
    datagram = header + question

    serverName = '8.8.8.8'  # Google's public DNS server
    serverPort = 53  # The standard port for DNS requests

    socket = socket(AF_INET, SOCK_DGRAM)
    socket.settimeout(5.0)

    response = ""
    print("Contacting DNS server..")
    for i in range(0, 3):
        try:
            print("Sending DNS query (attempt {0})..".format(i + 1))
            socket.sendto(bytes(123), (serverName, serverPort))
            response = socket.recvfrom(2048)
            print("DNS response received (attempt {0} of 3)".format(i + 1))
            break
        except timeout:
            if i == 2:  # this is the third attempt failed, exit
                print("Timeout Error, no response after 3 attempts")
                sys.exit(0)
            continue

    #print(response)
    print("Processing DNS response..")
