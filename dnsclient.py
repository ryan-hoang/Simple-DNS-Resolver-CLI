from socket import *
import sys
from struct import *
from header import *
import ctypes

# Ryan Hoang
# CS555
# Fall 2019


def create_query(params):
    head = Header()
    head.ID = params["id"]
    head.QR = params["qr"]
    head.OPCODE = params["opcode"]
    head.AA = params["aa"]
    head.TC = params["tc"]
    head.RD = params["rd"]
    head.RA = params["ra"]
    head.Z = params["z"]
    head.RCODE = params["rcode"]
    head.QDCOUNT = params["qdcount"]
    head.ANCOUNT = params["ancount"]
    head.NSCOUNT = params["nscount"]
    head.ARCOUNT = params["arcount"]

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

    return bytes(head) + bytes(question)


def parse_response(dns_response):
    print("--------------------------------------")
    print("HEADER.ID: {0}".format(int.from_bytes(dns_response[0:2], byteorder='big', signed=False)))

    qr = (dns_response[2] & 0b10000000) >> 7
    print("HEADER.QR: {0}".format(qr))

    opcode = (dns_response[2] & 0b01111000) >> 3
    print("HEADER.OPCODE: {0}".format(opcode))

    aa = (dns_response[2] & 0b00000100) >> 2
    print("HEADER.AA: {0}".format(aa))

    tc = (dns_response[2] & 0b00000010) >> 1
    print("HEADER.TC: {0}".format(tc))

    rd = (dns_response[2] & 0b00000001)
    print("HEADER.RD: {0}".format(rd))

    ra = (dns_response[3] & 0b10000000) >> 7
    print("HEADER.RA: {0}".format(ra))

    z = (dns_response[3] & 0b01110000) >> 4
    print("HEADER.Z: {0}".format(z))

    rcode = (dns_response[3] & 0b00001111)
    print("HEADER.RCODE: {0}".format(rcode))

    print("HEADER.QCOUNT: {0}".format(int.from_bytes(dns_response[4:6], byteorder='big', signed=False)))

    answer_count = int.from_bytes(dns_response[6:8], byteorder='big', signed=False)
    print("HEADER.ANCOUNT: {0}".format(answer_count))

    print("HEADER.NSCOUNT: {0}".format(int.from_bytes(dns_response[8:10], byteorder='big', signed=False)))

    print("HEADER.ARCOUNT: {0}".format(int.from_bytes(dns_response[10:12], byteorder='big', signed=False)))

    # parse QNAME section and convert back to human readable format.
    current_offset = 12
    hostname, current_offset = read_name_from_offset(current_offset, dns_response)

    print("QUESTION.QNAME: {0}".format(hostname))
    current_offset += 1  # move one byte past the null terminator for the qname section

    print("QUESTION.QTYPE: {0}".format(int.from_bytes(dns_response[current_offset:current_offset+2], byteorder='big', signed=False)))
    current_offset += 2  # Increment by 2 bytes to get to qclass section

    print("QUESTION.QCLASS: {0}".format(int.from_bytes(dns_response[current_offset:current_offset+2], byteorder='big', signed=False)))
    current_offset += 2  # Increment by 2 bytes to get to answer.name section

    for i in range(answer_count):

        print("------------------------------------------------")
        print("RR #{0}".format(i+1))

        name_offset = int.from_bytes(dns_response[current_offset:current_offset+2], byteorder='big', signed=False) & 0b0011111111111111
        name, bla = read_name_from_offset(name_offset, dns_response)
        print("ANSWER.NAME: {0}".format(name))

        current_offset += 2  # Increment by 2 bytes to get to answer.type section

        type = int.from_bytes(dns_response[current_offset:current_offset+2], byteorder='big', signed=False)
        # print("Type: {0}".format(type))
        t = ""
        if type == 1:
            t = "A"
        elif type == 5:
            t = "CNAME"
        elif type == 2:
            t = "NS"
        else:
            t = "OTHER"
        print("ANSWER.TYPE: {0}".format(t))
        current_offset += 2  # Increment by 2 bytes to get to answer.class section

        print("ANSWER.CLASS: {0}".format(int.from_bytes(dns_response[current_offset:current_offset+2], byteorder='big', signed=False)))
        current_offset += 2  # Increment by 2 bytes to get to answer.ttl section

        print("ANSWER.TTL: {0}".format(int.from_bytes(dns_response[current_offset:current_offset+4], byteorder='big', signed=False)))
        current_offset += 4  # Increment by 2 bytes to get to answer.rdlength section

        rdlength = int.from_bytes(dns_response[current_offset:current_offset+2], byteorder='big', signed=False)
        print("ANSWER.RDLENGTH: {0}".format(rdlength))

        current_offset += 2  # Increment by 2 bytes to get to answer.rdata section

        next_record_offset = current_offset + rdlength  # location of the next record

        ip_address = ""

        if type == 1:  # A-record
            flag = 0
            for i in range(0, rdlength):
                if flag == 0:
                    ip_address += str(dns_response[current_offset+i])
                    flag = 1
                else:
                    ip_address += "." + str(dns_response[current_offset+i])
            current_offset = next_record_offset
        elif type == 2:  # NS record
            current_offset = next_record_offset
        elif type == 5:  # CNAME record
            count = 0
            ad = []
            while count != rdlength:

                if dns_response[current_offset] == 192:
                    offset = int.from_bytes(dns_response[current_offset : current_offset + 2], byteorder='big', signed=False) & 0b0011111111111111
                    temp, current_offset = read_name_from_offset(offset, dns_response)
                    ad.append(temp)
                    current_offset += 2
                    count += 2
                else:
                    length = dns_response[current_offset]
                    current_offset += 1 # move offset past length byte
                    count += 1
                    tmp = ""
                    for x in range(length):
                        tmp += chr(dns_response[current_offset + x])
                    ad.append(tmp)

                    current_offset += length
                    count += length

            ip_address = ".".join(ad)
            current_offset = next_record_offset

        print("ANSWER.RDATA: {0}".format(ip_address))


def read_name_from_offset(offset, dns_response):
    hostname = []
    while dns_response[offset] != 0:
        if dns_response[offset] == 192:
            off = int.from_bytes(dns_response[offset : offset + 2], byteorder='big', signed=False) & 0b0011111111111111
            temp, offset = read_name_from_offset(off, dns_response)
            hostname.append(temp)
            offset += 3
        else:
            label_length = dns_response[offset]
            label = ""
            offset += 1  # move past length byte
            for i in range(0, label_length):
                label += chr(dns_response[offset + i])
            offset += label_length
            hostname.append(label)
    host = ".".join(hostname)
    return host, offset



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

    serverName = '8.8.8.8'  # Google's public DNS server
    serverPort = 53  # The standard port for DNS requests

    socket = socket(AF_INET, SOCK_DGRAM)  # Get UDP socket
    socket.settimeout(5.0)

    response = ""
    print("Contacting DNS server..")
    for i in range(0, 3):
        try:
            print("Sending DNS query (attempt {0})..".format(i + 1))
            socket.sendto(datagram, (serverName, serverPort))
            response, addr = socket.recvfrom(4096)
            print("DNS response received (attempt {0} of 3)".format(i + 1))
            break
        except timeout:
            if i == 2:  # this is the third attempt failed, exit
                print("Timeout Error, no response after 3 attempts")
                sys.exit(0)
            continue

    print("Processing DNS response..")
    print(bytearray(response)[40:])
    parse_response(bytearray(response))