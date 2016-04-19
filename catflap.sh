#!/bin/bash

# Extracts NTLMv2 parts from capture file for Hashcat cracking
# Creates test case using suppplied password from capture file or hash file
# Author: Jerome Smith @exploresecurity
# www.exploresecurity.com
# www.nccgroup.com
# Version: 0.1

if [ $# -eq 0 ] || [ $# -gt 2 ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
	echo "Extracts NTLMv2 parts from capture file for Hashcat cracking:"
	echo "  `basename $0` <capture_file>"
	echo "Creates test case using suppplied password from capture file or hash file:"
	echo "  `basename $0` <capture_file | hash_file> <test_password>"
	exit 1
fi

if [ ! -e "$1" ]; then
	echo "Input file $1 does not exist"
	exit 1
fi

# function to deal with capture files
cap_file() {
	hash tshark 2>/dev/null || { echo "This script requires tshark"; exit 1; }
	
	NUM_NTLMSSP=$(tshark -r $1 -Y "ntlmssp.identifier == NTLMSSP" 2>/dev/null | wc -l)
	if [[ -z $NUM_NTLMSSP ]]; then
		echo "Error"
		echo "- check the input file is a valid packet capture"
		echo "- check the input file contains NTLMSSP packets"
		exit 1
	fi
	
	CHALLENGE=$(tshark -r $1 -Y "ntlmssp.messagetype == 0x00000002" -T fields -e ntlmssp.ntlmserverchallenge 2>/dev/null | sed 's/://g')
	if [[ -z $CHALLENGE ]]; then
		echo "Error"
		echo "- no Type 2 packet found with challenge"
		exit 1
	fi
	if [[ $(echo $CHALLENGE | wc -w) -ne 1 ]]; then
		echo "The capture file looks to have more than 1 NTLM exchange"
		echo "- using the first exchange"
		echo "- otherwise export the packets of interest to a separate file"
		EXTRACT=1
		CHALLENGE=$(echo $CHALLENGE|awk '{print $1}')
	fi
	
	DOMAIN=$(tshark -r $1 -Y "ntlmssp.messagetype == 0x00000003" -T fields -e ntlmssp.auth.domain 2>/dev/null)
	if [[ -z $DOMAIN ]]; then
		echo "Error"
		echo "- no Type 3 packet found with domain"
		exit 1
	fi
	if [[ $(echo $DOMAIN | wc -w) -ne 1 && -z $EXTRACT ]]; then
		echo "The capture file looks to have more than one Type 3 message but only one Type 2 message"
		echo "- it's probably best to review the capture file"
		exit 1
	fi
	if [[ $EXTRACT ]]; then
		DOMAIN=$(echo $DOMAIN|awk '{print $1}')
	fi
	
	USERNAME=$(tshark -r $1 -Y "ntlmssp.messagetype == 0x00000003" -T fields -e ntlmssp.auth.username 2>/dev/null)
	if [[ -z $USERNAME ]]; then
		echo "Error"
		echo "- no Type 3 packet found with username"
		exit 1
	fi
	if [[ $EXTRACT ]]; then
		USERNAME=$(echo $USERNAME|awk '{print $1}')
	fi
	
	HMAC=$(tshark -r $1 -Y "ntlmssp.messagetype == 0x00000003" -T fields -e ntlmssp.ntlmv2_response 2>/dev/null | sed 's/://g' | cut -c 1-32) 
	if [[ -z $HMAC ]]; then
		echo "Error"
		echo "- no Type 3 packet found with HMAC"
		echo "- maybe this is a LM or NTLMv1 exchange"
		exit 1
	fi
	if [[ $EXTRACT ]]; then
		HMAC=$(echo $HMAC|awk '{print $1}')
	fi
	
	BLOB=$(tshark -r $1 -Y "ntlmssp.messagetype == 0x00000003" -T fields -e ntlmssp.ntlmv2_response 2>/dev/null | sed 's/://g' | cut -c 33-) 
	if [[ -z $BLOB ]]; then
		echo "Error"
		echo "- no Type 3 packet found with blob"
		exit 1
	fi
	if [[ $EXTRACT ]]; then
		BLOB=$(echo $BLOB|awk '{print $1}')
	fi
	
	echo ">> Hash format for cracking"
	echo $USERNAME::$DOMAIN:$CHALLENGE:$HMAC:$BLOB
}

# see if there's a hash in the input file
HASH=$(grep -E ".*::.*:[0-9a-f]{16}:[0-9a-f]{32}:[0-9a-f]+" "$1")
if [[ -z $HASH ]]; then
	cap_file "$1"
	if [ $# -eq 1 ]; then
		exit 0
	fi
else
	echo "Input file looks to contain a hash"
	if [ $# -eq 1 ]; then
		echo "Add a password parameter to create a test case"
		exit 1
	fi
	if [[ $(echo $HASH | wc -w) -ne 1 ]]; then
		echo "The hash file looks to have more than 1 NTLMv2 hash"
		echo "- using the first hash"
		HASH=$(echo $HASH|awk '{print $1}')
	fi
	USERNAME=$(echo $HASH|awk -F : '{print $1}')
	DOMAIN=$(echo $HASH|awk -F : '{print $3}')
	CHALLENGE=$(echo $HASH|awk -F : '{print $4}')
	BLOB=$(echo $HASH|awk -F : '{print $6}')
fi

#NT hash of supplied password converted to little endian unicode, removing first 2 BOM bytes
NTHASH=$(echo -n $2|iconv -f ascii -t utf16|tail -c +3|openssl dgst -md4 -binary|xxd -p)
#convert USERNAME to uppercase and concatenate with DOMAIN
	
INTHASH=$(echo -n ${USERNAME^^}$DOMAIN|iconv -f ascii -t utf16|tail -c +3|openssl dgst -md5 -mac HMAC -macopt hexkey:$NTHASH -binary|xxd -p)
HMAC=$(echo -n $CHALLENGE$BLOB|xxd -r -p|openssl dgst -md5 -mac HMAC -macopt hexkey:$INTHASH -binary|xxd -p)

echo
echo -e ">> Hash format for cracking with password set to \033[1;31m$2\e[00m"
echo $USERNAME::$DOMAIN:$CHALLENGE:$HMAC:$BLOB

exit 0