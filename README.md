# citstshark
Helper program to decode cits messages using tshark.
It can also be used to turn hex-encoded c-its messags (with Geonetworking headers) in to pcap-files that can be opened in wireshark.

## Requires:
- Python 3
- tshark (for decoding the c-its payload) or wireshark if only used for pcap generation

## Usage:
```
usage: citsdecode.py [-h] [-i INPUT] [-f FILTER] [-ot OUTPUTTYPE] [-o OUTPUTFILE] [-d] [-V]

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        input as hexstring e.g. 'FEEDBEEF'. A dummy input can be used for testing with the -d option
  -f FILTER, --filter FILTER
                        filter output on package type. More than one can be added using a space between. Not used if -ot is
                        'hexdump' or 'pcap' (default is 'its')
  -ot OUTPUTTYPE, --outputtype OUTPUTTYPE
                        Selects output type. values can be 'hexdump','pcap', 'json', or any output type tshark supports (default is
                        'json')
  -o OUTPUTFILE, --outputfile OUTPUTFILE
                        name of output file (defaults to printing to stdout unless using -ot 'pcap')
  -d, --dummy           use dummy input data
  -V, --verbose         add output of packet tree (Packet Details) when -ot is not 'hexdump' or 'pcap'
```

## Examples:
### Decode an included dummy payload
```
python3 citsdecode.py -d
```
### Decode a hex-encoded payload
```
python3 citsdecode.py -i 1200500A038100400380652040018000310A00C9730000000000020337424DAF680F3223B67970066424BC8000000023FD94C00331B18000C800000000000007D2000002012E5BF27181172DF938B2DC124C95D860049CAFED1AAD9A27DC06E7B8380FFFFFFE11DBBA10003C07800304500125000240E530B53E5B23B67970066424BC5A3C8101018003008009707265A61774E81083000000000025CEA28C8400C8010F00030840818002404281060501FFFFFFFF800308408381060501FFFFFFFF80012481040301FFFC80012581050401FFFFFF80018981030201E080018A81030201C080018B8107060130C001FFF880018C81050402FFFFE000018D80013581060501FFFFFFFF80013681060501FFFFFFFF8002027D810201018002027E81050401FFFFFF8002027F81050401FFFFFF808083561CDB2E3B1BA4ABC27EE140DC715544F7A1B15B9C3AFB1618C4A3988FB5187481809F8C60479879F4FC5CC0F56E4FBEA1A42094C2CAB88BFF9E4D35F545A6ED91DF07A56CE11E309280C9B0FE4F382478D45A324642E3C43292C0002964CECA6727808089F79A20EE722E5D6E3684103059D0DF2F5CF4B1488F5DD9E17AB98E6109B428C6F62D54F2193266A5CF877ED4D24C1289B9C9D20C0B8228DB5C9B2C3159C3E3
```
### Create pcap from hex-encoded payload (that can be opened in wireshark)
```
python3 citsdecode.py -i 1200500A038100400380652040018000310A00C9730000000000020337424DAF680F3223B67970066424BC8000000023FD94C00331B18000C800000000000007D2000002012E5BF27181172DF938B2DC124C95D860049CAFED1AAD9A27DC06E7B8380FFFFFFE11DBBA10003C07800304500125000240E530B53E5B23B67970066424BC5A3C8101018003008009707265A61774E81083000000000025CEA28C8400C8010F00030840818002404281060501FFFFFFFF800308408381060501FFFFFFFF80012481040301FFFC80012581050401FFFFFF80018981030201E080018A81030201C080018B8107060130C001FFF880018C81050402FFFFE000018D80013581060501FFFFFFFF80013681060501FFFFFFFF8002027D810201018002027E81050401FFFFFF8002027F81050401FFFFFF808083561CDB2E3B1BA4ABC27EE140DC715544F7A1B15B9C3AFB1618C4A3988FB5187481809F8C60479879F4FC5CC0F56E4FBEA1A42094C2CAB88BFF9E4D35F545A6ED91DF07A56CE11E309280C9B0FE4F382478D45A324642E3C43292C0002964CECA6727808089F79A20EE722E5D6E3684103059D0DF2F5CF4B1488F5DD9E17AB98E6109B428C6F62D54F2193266A5CF877ED4D24C1289B9C9D20C0B8228DB5C9B2C3159C3E3 -ot pcap -o output.pcap
```
## FAQ
- If you get a "FileNotFoundError: [WinError 2] The system cannot find the file specified" error, you need to install tshark. 
