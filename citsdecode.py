import os
import struct
from io import BytesIO
import argparse
 
 
# Initialize parser
parser = argparse.ArgumentParser()
 
# Adding optional argument
parser.add_argument("-i", "--input", help = "input as hexstring e.g. 'FEEDBEEF'. A dummy input can be used for testing with the -v option")
parser.add_argument("-f", "--filter", help = "filter output on package type. More than one can be added using a space between. Not used if -ot is 'hexdump' or 'pcap' (default is 'its')")
parser.add_argument("-ot", "--outputtype", help = "Selects output type. values can be 'hexdump','pcap', 'json', or any output type tshark supports (default is 'json')")
parser.add_argument("-o", "--outputfile", help = "name of output file (defaults to printing to stdout unless using -ot 'pcap')")
parser.add_argument("-d", "--dummy", help = "use dummy input data",action='store_true')
parser.add_argument("-V", "--verbose", help = "add output of packet tree (Packet Details) when -ot is not 'hexdump' or 'pcap'",action='store_true')

# Read arguments from command line
args = parser.parse_args()

if args.filter:
    filterv = args.filter
else:
    filterv = "its"
 
if args.input:
    hexGN = args.input
elif not args.dummy:
    print("No input defined, use --help for instructions")
    exit()
else:
    hexGN = '1200500A038100400380652040018000310A00C9730000000000020337424DAF680F3223B67970066424BC8000000023FD94C00331B18000C800000000000007D2000002012E5BF27181172DF938B2DC124C95D860049CAFED1AAD9A27DC06E7B8380FFFFFFE11DBBA10003C07800304500125000240E530B53E5B23B67970066424BC5A3C8101018003008009707265A61774E81083000000000025CEA28C8400C8010F00030840818002404281060501FFFFFFFF800308408381060501FFFFFFFF80012481040301FFFC80012581050401FFFFFF80018981030201E080018A81030201C080018B8107060130C001FFF880018C81050402FFFFE000018D80013581060501FFFFFFFF80013681060501FFFFFFFF8002027D810201018002027E81050401FFFFFF8002027F81050401FFFFFF808083561CDB2E3B1BA4ABC27EE140DC715544F7A1B15B9C3AFB1618C4A3988FB5187481809F8C60479879F4FC5CC0F56E4FBEA1A42094C2CAB88BFF9E4D35F545A6ED91DF07A56CE11E309280C9B0FE4F382478D45A324642E3C43292C0002964CECA6727808089F79A20EE722E5D6E3684103059D0DF2F5CF4B1488F5DD9E17AB98E6109B428C6F62D54F2193266A5CF877ED4D24C1289B9C9D20C0B8228DB5C9B2C3159C3E3'#+"00"
hexEth = 'ffffffffffff04e54820d9018947'

## helper functions for setting up pcap format
def align32bitPadding(hexstring):
    hlen = int(len(hexstring.replace(' ',''))/2)
    padd = ""
    if (hlen % 4) != 0:
        padd = "00 "*(4-(hlen % 4))
    return padd

def sizeInHex(hexval):
    return valInHex(int(len(hexval.replace(' ',''))/2))

def valInHex(val):
    return struct.pack("<I",int(val)).hex()

def shortValInHex(val):
    return struct.pack("<H",int(val)).hex()

import sys
import binascii

## BASIC PCAP GENERATOR BY: RPGillespie (https://www.codeproject.com/Tips/612847/Generate-a-quick-and-easy-custom-pcap-file-using-P)

#Global header for pcap 2.4
pcap_global_header =   ('D4 C3 B2 A1'   
                        '02 00'         #File format major revision (i.e. pcap <2>.4)  
                        '04 00'         #File format minor revision (i.e. pcap 2.<4>)   
                        '00 00 00 00'     
                        '00 00 00 00'     
                        'FF FF 00 00'     
                        '01 00 00 00')

#pcap packet header that must preface every packet
pcap_packet_header =   ('AA 77 9F 47'     
                        '90 A2 04 00'     
                        'XX XX XX XX'   #Frame Size (little endian) 
                        'YY YY YY YY')  #Frame Size (little endian)

eth_header =   ('00 00 00 00 00 00'     #Source Mac    
                '00 00 00 00 00 00'     #Dest Mac  
                '89 47')                #Protocol (0x0800 = IP)

ip_header =    ('45'                    #IP version and header length (multiples of 4 bytes)   
                '00'                      
                'XX XX'                 #Length - will be calculated and replaced later
                '00 00'                   
                '40 00 40'                
                '11'                    #Protocol (0x11 = UDP)          
                'YY YY'                 #Checksum - will be calculated and replaced later      
                '7F 00 00 01'           #Source IP (Default: 127.0.0.1)         
                '7F 00 00 01')          #Dest IP (Default: 127.0.0.1) 

udp_header =   ('80 01'                   
                'XX XX'                 #Port - will be replaced later                   
                'YY YY'                 #Length - will be calculated and replaced later        
                '00 00')
                
def getByteLength(str1):
    return len(''.join(str1.split())) / 2

def writeByteStringToFile(bytestring, filename):
    bytelist = bytestring.split()  
    bytes = binascii.a2b_hex(''.join(bytelist))
    bitout = open(filename, 'wb')
    bitout.write(bytes)

def generatePCAP(message,port): 

    pcap_len = int(getByteLength(message) + getByteLength(eth_header))
    
    hex_str = "%08x"%pcap_len
    reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
    pcaph = pcap_packet_header.replace('XX XX XX XX',reverse_hex_str)
    pcaph = pcaph.replace('YY YY YY YY',reverse_hex_str)

    bytestring = pcap_global_header + pcaph + eth_header + message
    return bytestring

#Splits the string into a list of tokens every n characters
def splitN(str1,n):
    return [str1[start:start+n] for start in range(0, len(str1), n)]

#Calculates and returns the IP checksum based on the given IP Header
def ip_checksum(iph):

    #split into bytes    
    words = splitN(''.join(iph.split()),4)

    csum = 0;
    for word in words:
        csum += int(word, base=16)

    csum += (csum >> 16)
    csum = csum & 0xFFFF ^ 0xFFFF

    return csum

hexr = generatePCAP(hexGN, 1234).replace(' ','')

#print("inlen(Bytes): ",len(hexGN)/2)
#print(hexr)
bindata = bytearray.fromhex(hexr)#binascii.a2b_hex(hexr)
#print(bindata)
thebytes = BytesIO(bindata)
#print(bytes)

## set filenames for -ot hexdump and pcap
if args.outputtype:
    if args.outputtype == "hexdump":
        if args.outputfile:
            file_path = os.path.join(os.path.dirname(__file__),args.outputfile)
    elif args.outputtype == "pcap":
        if not args.outputfile:
            file_path = os.path.join(os.path.dirname(__file__),"out.pcap")
        else:
            file_path = os.path.join(os.path.dirname(__file__),args.outputfile)

## prints a hexdump to the console
def printHexdump(inbytes):
    for line in hexdump(inbytes):
        print(line)

## writes a hexdump to file
def writeHexdump(inbytes):
    with open(file_path, "w") as file:
        for line in hexdump(inbytes):
            file.write(line+'\n')

def hexdump(src: bytes, bytesPerLine: int = 16, bytesPerGroup: int = 2, sep: str = '.', ascii: bool = False) -> list:
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    lines = []
    maxAddrLen = len(hex(len(src)))
    if 8 > maxAddrLen:
        maxAddrLen = 8

    for addr in range(0, len(src), bytesPerLine):
        hexString = ""
        printable = ""

        # The chars we need to process for this line
        chars = src[addr : addr + bytesPerLine]

        # Create hex string
        tmp = ''.join(['{:02X}'.format(x) for x in chars])
        idx = 0
        for c in tmp:
            hexString += c
            idx += 1
            # 2 hex digits per byte.
            if idx % bytesPerGroup * 2 == 0 and idx < bytesPerLine * 2:
                hexString += " "
        # Pad out the line to fill up the line to take up the right amount of space to line up with a full line.
        hexString = hexString.ljust(bytesPerLine * 2 + int(bytesPerLine * 2 / bytesPerGroup) - 1)

        # create printable string
        tmp = ''.join(['{}'.format((x <= 127 and FILTER[x]) or sep) for x in chars])
        # insert space every bytesPerGroup
        idx = 0
        for c in tmp:
            printable += c
            idx += 1
            # Need to check idx because strip() would also delete genuine spaces that are in the data.
            if idx % bytesPerGroup == 0 and idx < len(chars):
                printable += " "
        if(ascii):
            lines.append(f'{addr:0{maxAddrLen}X}  {hexString}  |{printable}|')
        else:
            lines.append(f'{addr:0{maxAddrLen}X}  {hexString}')
    return lines



## writes a binary file
def writeHexBin(write_byte):
    with open(file_path, "wb") as file:
        file.write(write_byte.getbuffer())
        #for i in range(0,len(hexr)):
        #    file.write(hexr[i])

import subprocess
out = 'json'

runargs = ["tshark"]
if args.verbose:
    runargs.append("-V")

if args.outputtype:
    if args.outputtype == "hexdump":
        if args.outputfile:
            writeHexdump(bindata)
        else:
            printHexdump(bindata)
    elif args.outputtype == 'pcap':
        writeHexBin(thebytes)
    else:
        out = args.outputtype
        runargs.extend(['-r', '-', '-T', out, '-J', filterv])
        result = subprocess.run(runargs, stdout=subprocess.PIPE, input=thebytes.getbuffer())
        print(result.stdout.decode('utf-8'))
else:
    runargs.extend(['-r', '-', '-T', 'json', '-J', filterv])
    result = subprocess.run(runargs, stdout=subprocess.PIPE, input=thebytes.getbuffer())
    print(result.stdout.decode('utf-8'))


#import time
#start = time.perf_counter_ns()
#result = subprocess.run(['tshark', '-r', '-', '-T', 'json', '-J', 'its'], stdout=subprocess.PIPE, input=bytes.getbuffer()).stdout.decode('utf-8')
#duration = time.perf_counter_ns() - start
#print(f"Your duration was {duration // 1000000}ms.")

