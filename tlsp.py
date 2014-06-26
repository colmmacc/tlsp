
import urllib2
import socket
import struct
import copy
import csv
import sys

def parseServerHello(message):

    # Skip the first 4 bytes
    message = message[4:]
    
    # Grab the protocol version
    (major, minor) = struct.unpack("!BB", message[:2])

    # Skip the random data 
    message = message[34:]

    # Get the session id length
    (session_id_len,) = struct.unpack("!B", message[:1])

    # Skip the session_id
    message = message[1 + session_id_len:]

    # Get the negotiated cipher suite
    (cipher_suite,) = struct.unpack("!H", message[:2])

    # Ignore the compression suite
    message = message[4:]
    
    return cipher_suite
    

def sendClientHello(cipherSuites, namedCurves, major, minor):
    # Start with the client version number
    message = struct.pack("!BB", major, minor)

    # TLS client hello has 32 bytes of random data. Use 7;
    # that's a random number (I promise, I rolled a D20). 
    message += "\7" * 32

    # Zero length session ID
    message += struct.pack("!B", 0)

    # The cipher suites
    message += struct.pack("!H", len(cipherSuites) * 2) 
    for suite in cipherSuites:
        message += struct.pack("!H", suite) 
    
    # One compression method, but it's zero (the null compressor)
    message += struct.pack("!B", 1)
    message += struct.pack("!B", 0)

    if len(namedCurves) > 0:
        curve_list  = struct.pack("!H", len(namedCurves) * 2) 
        for curve in namedCurves.keys():
            curve_list += struct.pack("!H", int(curve))
        
        extension  = struct.pack("!HHH", 10, len(curve_list) + 2, len(curve_list))
        extension += curve_list

        # Add the point format extension too
        extension += struct.pack("!HHBB", 11, 2, 1, 0)
        
        extension_data = struct.pack("!H", len(extension))
        extension_data += extension

        message += extension_data
    
    fragment = struct.pack("!BBH", 1, 0, len(message))
    fragment += message
    
    return fragment

def hello(ip, port, cipherSuites, namedCurves, major, minor):

    clientHelloMessage = sendClientHello(cipherSuites, namedCurves, major, minor)

    # Create a handshake (type 22) record using TLS
    header = struct.pack("!BBBH", 22, major, minor, len(clientHelloMessage)); 

    s = socket.socket()
    s.connect((ip, port))
    s.sendall(header)
    s.sendall(clientHelloMessage)

    # Recieve two bytes so that we know the length
    header = s.recv(5)

    if len(header) < 5:
        raise Exception("Connection closed")

    (rectype, major, minor, length) = struct.unpack("!BBBH", header)

    if rectype != 22:
        raise Exception('Invalid record type from server: %d' % rectype)

    # Get the rest of the server hello message
    message = s.recv(length)
    s.close()

    return parseServerHello(message)


def getIANAcsv(url):
    response = urllib2.urlopen(url) 
    reader = csv.reader(response)

    # Skip the fields line
    next(reader)

    ret = { } 

    for line in reader:
        # Ignore values that are ranges
        if "-" in line[0]:
            continue
    
        # Ignore unassigned 
        if line[1] == "Unassigned":
            continue

        # and arbitrary values
        if line[1].startswith("arbitrary"):
            continue

        ret[ line[0] ] = line[1]

    return ret

def getIANACipherSuites():
    suites = getIANAcsv("http://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv")
    new_suites = { }
    for suite in suites.keys():    
        old_key = suite
        (msb, lsb) = old_key.split(",")
        new_key = int(msb, 16) << 8 | int(lsb, 16) 
        new_suites[ new_key ] = suites[ old_key ]
    return new_suites

def getIANANamedCurves():
    return getIANAcsv("http://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv")

if __name__ == "__main__":
    suites = getIANACipherSuites()
    curves = getIANANamedCurves()

    port = 443
    if len(sys.argv) > 2:
        port = int(sys.argv[2]) 
    
    endpoint = sys.argv[1]

    major = 3
    for minor in range(0, 4):
    
        all_suites = suites.keys()
        negotiated_suites = [ ] 
        while len(suites):
            try:
                negotiated = hello(endpoint, port, all_suites, curves, major, minor) 
                negotiated_suites.append(negotiated)
                all_suites.remove(negotiated)
            except:
                break

        # Reverse the list
        negotiated_suites.reverse()

        order = "server"
        if hello(endpoint, port, negotiated_suites, curves, major, minor) is negotiated_suites[0]:
            order = "client"

        negotiated_suites.reverse()

        print "TLS %d.%d Server uses %s ordering for cipher suites" % (major, minor, order)
        print "Supported suites:"
        for suite in negotiated_suites:
            print "    " + suites[ suite ]

