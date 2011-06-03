#!/usr/bin/env python
import sys, getopt, os, random, threading, re
try:
  import pylorcon
except:
  print "Error! pylorcon missing (http://code.google.com/p/pylorcon/)"

try:
  import scapy.packet
  import scapy.fields
  from scapy.sendrecv import send,sendp,sniff
  from scapy.layers import dot11, l2

except:
  print "Error! scapy missing (http://www.secdev.org/projects/scapy/)"

__author__ = "Arturo Filasto'"
__copyright__ = "Copyright 2010, Arturo Filasto'"
__credits__ = ["Arturo Filasto'"]
__version__ = "0.1"
__email__ = "art@baculo.org"

unique = {}

def usage():
  """
  """
  print "VX v.0.1 - pwn the pwner"
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
 

def wepKey(WEPKEY):
  """
  Match and parse WEP key
  """ 
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
  """
  Generate a random mac address
  """
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

  print mac
  return mac


def getBeacon(bssid, ssid, channel):
  """
  Generate a beacon frame, src=ff:ff:ff:ff:ff:ff,dst=bssid
  """
  beacon_pckt = dot11.Dot11(addr1='ff:ff:ff:ff:ff:ff',addr2=bssid,addr3=bssid)
  beacon_pckt /= dot11.Dot11Beacon(cap='privacy+ESS')    \
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
  """
  Generate a WEP encrypted data packet
  """
  
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
    """
    Send wep packets encrypted with the selected WEP key into
    the air.
    """
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


def sniffBeacon(p):
    """
    Detect unique beacon packets and print them out
    """
    global unique
    if p.haslayer(dot11.Dot11Beacon):
        if unique.count([p.addr2, p.info]) == 0:
          unique.append([p.addr2,p.info]) 
          string = "[" + str(len(unique)) + "]" + " ESSID: %Dot11Elt.info%"
          string += "\nBSSID: %Dot11.addr2%\nMode: %Dot11Beacon.cap%"
          print p.sprintf(string)
          print "-"*15

 
def demon(p):
    """
    """
    global unique

    if p.haslayer(dot11.Dot11Beacon):
        if unique.count([p.addr2, p.info]) == 0:
          unique.append([p.addr2,p.info])
          if re.search(match, p.info):
            print "Success!\n\n"
            unique[0][0] = len(unique)


def main():
  global unique
  # Keyword used for demon mode, to autoinject once a
  # specified beacon ssid is detected
  global match 
  match = ".*"
  try:
    opts, args = getopt.getopt(sys.argv[1:], "hsdi:e:b:m:k:c:")
  except getopt.GetoptError, err:
    usage()
    sys.exit(2)

  channel = ""
  essid   = ""
  bssid   = ""
  mac     = "00:23:33:56:88:99"
  key     = ""
  logfile = "./output.log"

  iface = "mon0"
  mode = "default"
  l = 99

  unique = []
 
  n = 0

  flog = open(logfile, "w+")

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


  if not channel:
    print "Error! Non channel supplied."
    usage()
    sys.exit(1)

  if not key:
    print "Error! No key supplied."
    usage()
    sys.exit(1)

  if(mode == "default" and n >= 3):
    print "Default mode"
    print "BSSID: %s MAC: %s ESSID: %s Channel: %s iface: %s" % (bssid, mac, essid, channel, iface)
    infect(iface, channel, bssid, essid, mac, key, l, 0)
 
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
    while unique[0][0] == "none":
      sniff(iface=iface,prn=demon,timeout=2)
    x = int(unique[0][0]) - 1 
    infect(iface, channel, unique[x][0], unique[x][1], mac, key, l, 0) 

  flog.close()
if __name__ == "__main__":
    main()


