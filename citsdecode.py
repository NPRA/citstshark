import os
import struct
from io import BytesIO
import argparse
 
 
# Initialize parser
parser = argparse.ArgumentParser()
 
# Adding optional argument
parser.add_argument("-i", "--input", help = "input as hexstring e.g. 'FEEDBEEF'. A dummy input can be used for testing with the -d option")
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

hexPadding = align32bitPadding(hexEth+hexGN)

headType = "0A0D0D0A"
headlen = "20000000"
headMagic = "4D3C2B1A"
headVersion = "0100 0000"
headSecLen = "FF FF FF FF FF FF FF FF"
headOpt = "00 00 00 00"
IDBtype = "01 00 00 00"
IDBlen = "43 00 00 00" #0x44
IDBlinkType = "01 00" + "00 00" # eth + reserved
IDBsnaplen = "00 00 00 00" # 0=no limit
IFname = "Dummy interchange IF"
IFnameHex = IFname.encode("utf-8").hex()
IDBopt = "02 00"+shortValInHex(int(len(IFnameHex.replace(' ',''))/2))+IFnameHex+align32bitPadding(IFnameHex)     #"02 00"+"1D 00"+"46616B652049462C20496D706F72742066726F6D204865782044756D70 00 00 00" # if_name + nameLen(29) + name(Fake IF, Import from Hex Dump) + padding to 32bits
IDBif_tsresol = "090001000900000000000000"
IDBlen = sizeInHex(IDBtype+IDBlen+IDBlinkType+IDBsnaplen+IDBopt+IDBif_tsresol+IDBlen)
pcapblocktype = "06 00 00 00" # EPB
pcapBlockLen = valInHex(int(len((hexEth+hexGN).replace(' ',''))/2)+33) #"08 02 00 00" #33(0x21)+payloadlen
pcapIfaceId = "00 00 00 00"
pcapTime = "00 00 00 00 00 00 00 00"
pcaplen = sizeInHex(hexEth+hexGN)#"E7 01 00 00" #487

test = IFname.encode("utf-8").hex()

head = headType+headlen+headMagic+headVersion+headSecLen+headOpt+headlen
IDB = IDBtype+IDBlen+IDBlinkType+IDBsnaplen+IDBopt+IDBif_tsresol+IDBlen
EPB = pcapblocktype+pcapBlockLen+pcapIfaceId+pcapTime+pcaplen+pcaplen+hexEth+hexGN+hexPadding+pcapBlockLen
hexr = head+IDB+EPB
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

