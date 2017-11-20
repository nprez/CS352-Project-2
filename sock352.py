
# CS 352 project part 2
# this is the initial socket library for project 2
# You wil need to fill in the various methods in this
# library

# main libraries
import binascii
import socket as syssock
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
import struct
import sys
import random

# encryption libraries
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

# if you want to debug and print the current stack frame
from inspect import currentframe, getframeinfo

# these are globals to the sock352 class and
# define the UDP ports all messages are sent
# and received from

# the ports to use for the sock352 messages
global sock352portTx
global sock352portRx
# the public and private keychains in hex format
global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format
global publicKeys
global privateKeys

# the encryption flag
global ENCRYPT

publicKeysHex = {}
privateKeysHex = {}
publicKeys = {}
privateKeys = {}

# this is 0xEC
ENCRYPT = 236

# this is the structure of the sock352 packet
sock352HdrStructStr = '!BBBBHHLLQQLL'

##8 version; /* version number */                               0x1
##8 flags; /* for connection set up, tear-down, control */      see below
##8 opt_ptr; /* option type between the header and payload */    1 = encrypted
#8 protocol; /* higher-level protocol */                        0
##16 header_len; /* length of the header */                     40
#16 checksum; /* checksum of the packet */                      calculate this
#32 source_port; /* source port */                              0
#32 dest_port; /* destination port */                           0
##64 sequence_no; /* sequence number */                         start random, ++
##64 ack_no; /* acknowledgement number */                       start x+1, ++
#32 window; /* receiver advertised window in bytes*/            0
##32 payload_len; /* length of the payload */                   up to 64K

#SOCK352_SYN 0x01 Connection initiation
#SOCK352_FIN 0x02 Connection end
#SOCK352_ACK 0x04 Acknowledgement #
#SOCK352_RESET 0x08 Reset the connection
#SOCK352_HAS_OPT 0x10 Option field is valid

# this init function is global to the class and
# defines the UDP ports all messages are sent
# and received from.
def init(UDPportTx,UDPportRx): # initialize your UDP socket here
    # create a UDP/datagram socket
    # bind the port to the Rx (receive) port number
    global sock352portTx
    global sock352portRx

    if(UDPportTx is None or UDPportTx == 0):
        sock352portTx = 27182
    else:
        sock352portTx = int(UDPportTx)

    if(UDPportRx is None or UDPportRx == 0):
        sock352portRx = 27182
    else:
        sock352portRx = int(UDPportRx)

    # create the sockets to send and receive UDP packets on
    # if the ports are not equal, create two sockets, one for Tx and one for Rx


# read the keyfile. The result should be a private key and a keychain of
# public keys
def readKeyChain(filename):
    global publicKeysHex
    global privateKeysHex
    global publicKeys
    global privateKeys

    if (filename):
        try:
            keyfile_fd = open(filename,"r")
            for line in keyfile_fd:
                words = line.split()
                # check if a comment
                # more than 2 words, and the first word does not have a
                # hash, we may have a valid host/key pair in the keychain
                if ( (len(words) >= 4) and (words[0].find("#") == -1)):
                    host = words[1]
                    port = words[2]
                    keyInHex = words[3]
                    if (words[0] == "private"):
                        privateKeysHex[(host,port)] = keyInHex
                        privateKeys[(host,port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                    elif (words[0] == "public"):
                        publicKeysHex[(host,port)] = keyInHex
                        publicKeys[(host,port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
        except Exception,e:
            print ( "error: opening keychain file: %s %s" % (filename,repr(e)))
    else:
            print ("error: No filename presented")

    return (publicKeys,privateKeys)

class socket:

    def __init__(self):  # fill in your code here
        # create any lists/arrays/hashes you need
        self.sPort = sock352portTx
        self.rPort = sock352portRx
        self.addr = None
        self.seq = 0
        self.ack = 0
        self.socket = syssock.socket(AF_INET, SOCK_DGRAM)
        self.encrypt = False
        self.myPrivateKey = None
        self.theirPublicKey = None
        self.box = None

        self.packetList = []    # for part 1 we dont need a buffer to be stored,
        # so we're only using this list to store the current packet
        self.PLindex = 0
        return

    def bind(self,address):
        # bind is not used in this assignment
        self.socket.bind(("", int(address[1])))
        return

    def connect(self,*args):

        # example code to parse an argument list
        global sock352portTx
        global ENCRYPT
        if (len(args) >= 1):
            (host,port) = args[0]
        if (len(args) >= 2):
            if (args[1] == ENCRYPT):
                self.encrypt = True


        # your code goes here
        #  create a new sequence number
        #  create a new packet header with the SYN bit set in the flags (use the Struct.pack method)
        #  also set the other fields (e.g sequence #)
        #   add the packet to the send buffer
        #   set the timeout
        #      wait for the return SYN
        #        if there was a timeout, retransmit the SYN packet
        #   set the send and recv packets sequence numbers

        self.addr = (syssock.gethostbyname(syssock.getfqdn(host)), (int)(port))

        #search for correct keys
        if(self.encrypt):
            for k, v in publicKeys.items():
                if((k[0] == self.addr or k[0] == host or k[0] == '*') and (k[1] == self.sPort or k[1] == port or k[1] == '*')):
                    self.theirPublicKey = v
                    break
            for k, v in privateKeys.items():
                if((k[0] == self.addr or k[0] == host or k[0] == '*') and (k[1] == self.rPort or k[1] == '*')):
                    self.myPrivateKey = v
                    break
            #make a box
            self.box = Box(self.myPrivateKey, self.theirPublicKey)

        self.seq = random.randint(0, 1000)
        self.socket.bind(("", sock352portRx))

        udpPkt_hdr_data = struct.Struct(sock352HdrStructStr)
        header = udpPkt_hdr_data.pack(1, 1, 0, 0, 40, 0, 0, 0, self.seq, self.ack, 0, 0)
        #first part
        self.socket.sendto(header, self.addr)

        waiting = True
        while(waiting):
            try:
                #second part
                self.socket.settimeout(0.2)
                ret, ad = self.socket.recvfrom(40)
                retStruct = struct.unpack('!BBBBHHLLQQLL', ret)
                synCheck = retStruct[1]
                incSeqNum = retStruct[8]
                incAckNum = retStruct[9]
                #invalid
                if(synCheck != 5 or incAckNum != self.seq+1 or (incSeqNum != self.ack and self.ack != 0)):
                    print("Error 1")
                    continue
                self.ack = incSeqNum+1
            except:
                #first part failed
                self.socket.sendto(header, self.addr)
                print("Error 2")
                continue
            waiting = False
        #third part
        self.seq+=1
        udpPkt_hdr_data2 = struct.Struct(sock352HdrStructStr)
        header2 = udpPkt_hdr_data2.pack(1, 5, 0, 0, 40, 0, 0, 0, self.seq, self.ack, 0, 0)
        self.socket.sendto(header2, self.addr)
        self.seq+=1
        return

    def listen(self,backlog):
        # listen is not used in this assignments
        return

    def accept(self,*args):
        # example code to parse an argument list
        global ENCRYPT
        if (len(args) >= 1):
            if (args[0] == ENCRYPT):
                self.encrypt = True
        # your code goes here

        # call  __sock352_get_packet() until we get a new conection
        # check the the incoming packet - did we see a new SYN packet?
        self.socket.settimeout(None)
        temp = self.socket.recvfrom(40)
        self.packetList.append(temp[0])
        ad = temp[1]
        self.addr = (syssock.gethostbyname(syssock.getfqdn(ad[0])), (int)(ad[1]))

        #search for correct keys
        if(self.encrypt):
            for k, v in publicKeys.items():
                if((k[0] == self.addr or k[0] == ad[0] or k[0] == '*') and (k[1] == self.sPort or k[1] == ad[1] or k[1] == '*')):
                    self.theirPublicKey = v
                    break
            for k, v in privateKeys.items():
                if((k[0] == self.addr or k[0] == ad[0] or k[0] == '*') and (k[1] == self.rPort or k[1] == '*')):
                    self.myPrivateKey = v
                    break
            #make a box
            self.box = Box(self.myPrivateKey, self.theirPublicKey)

        self.__sock352_get_packet()
        self.packetList[0] = None
        self.socket.settimeout(0.2)
        return(self, self.addr)

    def close(self):   # fill in your code here
        self.socket.close()
        return

    def send(self,buffer):
        bytessent = 0     # fill in your code here
        # make sure the correct fields are set in the flags
        # make sure the sequence and acknowlegement numbers are correct
        # create a new sock352 header using the struct.pack
        # create a new UDP packet with the header and buffer
        # send the UDP packet to the destination and transmit port
        # set the timeout
        # wait or check for the ACK or a timeout

        udpPkt_hdr_data = struct.Struct(sock352HdrStructStr)
        header = None
        packet = None
        if (self.encrypt):
            header = udpPkt_hdr_data.pack(1, 16, 1, 0, 40, 0, 0, 0, self.seq, self.ack, 0, len(buffer)+40)
            packet = header + self.box.encrypt(buffer, nacl.utils.random(Box.NONCE_SIZE))
        else:
            header = udpPkt_hdr_data.pack(1, 0, 0, 0, 40, 0, 0, 0, self.seq, self.ack, 0, len(buffer))
            packet = header + buffer

        bytessent = self.socket.sendto(packet, self.addr)

        waiting = True
        while(waiting):
            try:
                #second part
                ret, ad = self.socket.recvfrom(40)
                retStruct = struct.unpack(sock352HdrStructStr, ret)
                ackCheck = retStruct[1]
                incSeqNum = retStruct[8]
                incAckNum = retStruct[9]
                #invalid
                if(ackCheck != 4 or incAckNum != self.seq+1 or incSeqNum != self.ack):
                    print("Error 3")
                    continue
                self.ack = incSeqNum+1
            except:
                #first part failed
                bytessent = self.socket.sendto(packet, self.addr)
                print("Error 4")
                continue
            waiting = False
        self.seq += 1

        return len(buffer)

    def recv(self,nbytes):
        # fill in your code here
        if(self.encrypt):
            nbytes += 40
        self.packetList[0], ad = self.socket.recvfrom(nbytes+40)
        self.__sock352_get_packet()
        bytesreceived = self.packetList[0][40:]
        self.packetList[0] = None

        # call __sock352_get_packet() to get packets (polling)
        # check the list of received fragements
        # copy up to bytes_to_receive into a buffer
        # return the buffer if there is some data
        return bytesreceived

    # this is an internal function that demultiplexes all incomming packets
    # it update lists and data structures used by other methods
    def __sock352_get_packet(self):
        # There is a differenct action for each packet type, based on the flags:
        #  First check if it's a connection set up (SYN bit set in flags)
        #    Create a new fragment list
        #    Send a SYN packet back with the correct sequence number
        #    Wake up any readers wating for a connection via accept() or return
        #  else
        #      if it is a connection tear down (FIN)
        #        send a FIN packet, remove fragment list
        #      else if it is a data packet
        #           check the sequence numbers, add to the list of received fragments
        #           send an ACK packet back with the correct sequence number
        #          else if it's nothing it's a malformed packet.
        #              send a reset (RST) packet with the sequence number
        header = self.packetList[self.PLindex][:40]
        msg = self.packetList[self.PLindex][40:]
        headerData = struct.unpack(sock352HdrStructStr, header)

        if (headerData[1] == 1):            #syn
            udpPkt_hdr_data = struct.Struct(sock352HdrStructStr)
            self.seq = self.seq = random.randint(0, 1000)
            self.ack = headerData[8]+1
            syn = udpPkt_hdr_data.pack(1, 5, 0, 0, 40, 0, 0, 0, self.seq, self.ack, 0, 0)
            self.socket.sendto(syn, self.addr)
            self.socket.settimeout(0.2)

            waiting = True
            while(waiting):
                try:
                    #wait for third part
                    ret, ad = self.socket.recvfrom(40)
                    retStruct = struct.unpack(sock352HdrStructStr, ret)
                    ackCheck = retStruct[1]
                    incSeqNum = retStruct[8]
                    incAckNum = retStruct[9]
                    #invalid
                    if(ackCheck != 5 or incAckNum != self.seq+1 or incSeqNum != self.ack):
                        print("Error 5")
                        continue
                    self.ack+=1;
                except:
                    #our ack failed; resend
                    self.socket.settimeout(0.2)
                    self.socket.sendto(syn, self.addr)
                    print("Error 6")
                    continue
                waiting = False
            self.seq+=1

        elif (headerData[1] == 2):       #fin
            udpPkt_hdr_data = struct.Struct(sock352HdrStructStr)
            self.ack+=1
            fin = udpPkt_hdr_data.pack(1, 6, 0, 0, 40, 0, 0, 0, self.seq, self.ack, 0, 0)
            self.socket.sendto(fin, self.addr)

        elif (headerData[1] == 0 or headerData[1] == 16):      #data
            if(self.encrypt):
                msg = self.box.decrypt(msg)
                self.packetList[self.PLindex][40:] = msg
            udpPkt_hdr_data = struct.Struct(sock352HdrStructStr)
            self.ack+=1
            ack = udpPkt_hdr_data.pack(1, 4, 0, 0, 40, 0, 0, 0, self.seq, self.ack, 0, 0)
            self.socket.sendto(ack, self.addr)
            self.seq+=1

        else:       #malformed packet
            udpPkt_hdr_data = struct.Struct(sock352HdrStructStr)
            res = udpPkt_hdr_data.pack(1, 8, 0, 0, 40, 0, 0, 0, self.seq, self.ack, 0, 0)
            self.socket.sendto(res, self.addr)

        return
