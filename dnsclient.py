from socket import *
import sys
from struct import *
from query import *
import ctypes


def create_query(params):
    qr = Query()
    qr.ID = params["id"]
    qr.QR = params["qr"]
    qr.OPCODE = params["opcode"]
    qr.AA = params["aa"]
    qr.TC = params["tc"]
    qr.RD = params["rd"]
    qr.RA = params["ra"]
    qr.Z = params["z"]
    qr.RCODE = params["rcode"]
    qr.QDCOUNT = params["qdcount"]
    qr.ANCOUNT = params["ancount"]
    qr.NSCOUNT = params["nscount"]
    qr.ARCOUNT = params["arcount"]

    labels = params["address"].split(".")

    size = 0
    for label in labels:
        size += len(label)  # there will be one byte for each character

    size += len(labels)  # there will be a length byte for each label
    size += 1  # one byte to null terminate the qname section
    size += 2  # 2 bytes for qtype
    size += 2  # 2 bytes for qclass

    question = ctypes.create_string_buffer(size)
    offset = 0

    for label in labels:
        pack_into('>b', question, offset, len(label))
        offset += 1
        for character in label:
            pack_into('>c', question, offset, bytes(character, 'utf-8'))
            offset += 1

    pack_into('>b', question, offset, 0)  # terminate the qname section
    offset += 1
    pack_into('>h', question, offset, 1)  # qtype set to 1
    offset += 2
    pack_into('>h', question, offset, 1)  # qclass set to 1
    offset += 2

    #print(bytes(qr))
    #print(bytes(question))
    return bytes(qr) + bytes(question)


def parse_response(dns_response, length):
    print(dns_response[0 : length])
    print(dns_response)

    print("--------------------------------------")
    print(hex(dns_response[0]), hex(dns_response[1]))
    #print("ID: {0}".format(int(hex(dns_response[0:2]).strip('x'), 16)))

    return 1


if __name__ == "__main__":
    address = ""
    try:
        address = sys.argv[1]
    except IndexError:
        print("No address specified. Usage: dnsclient <hostname>")
        sys.exit(0)

    print("Preparing DNS query..")

    dns_params = {
        "id": 1234,
        "qr": 0,
        "opcode": 0,
        "aa": 0,
        "tc": 0,
        "rd": 1,
        "ra": 0,
        "z": 0,
        "rcode": 0,
        "qdcount": 1,
        "ancount": 0,
        "nscount": 0,
        "arcount": 0,
        "address": address
    }

    datagram = create_query(dns_params)
    query_length = len(datagram)  # length in bytes, used later determine offsets

    #print(bin(int.from_bytes(datagram, byteorder='big')))
    #print(datagram)

    serverName = '8.8.8.8'  # Google's public DNS server
    serverPort = 53  # The standard port for DNS requests

    socket = socket(AF_INET, SOCK_DGRAM)
    socket.settimeout(5.0)

    response = ""
    print("Contacting DNS server..")
    for i in range(0, 3):
        try:
            print("Sending DNS query (attempt {0})..".format(i + 1))
            socket.sendto(datagram, (serverName, serverPort))
            response, addr = socket.recvfrom(2048)
            print("DNS response received (attempt {0} of 3)".format(i + 1))
            break
        except timeout:
            if i == 2:  # this is the third attempt failed, exit
                print("Timeout Error, no response after 3 attempts")
                sys.exit(0)
            continue

    print("Processing DNS response..")
    parse_response(response, query_length)

    #print(bin(int.from_bytes(response, byteorder='big')))
    #print(response)
    #print(hex(response[0]), hex(response[1]))


