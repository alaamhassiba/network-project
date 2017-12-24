import socket
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP
import time
from PyQt4 import QtGui, QtCore
import sys
   

from design2 import Ui_Dialog
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

class mydialog(QtGui.QDialog ,Ui_Dialog  ):
   
   def __init__(self):
     QtGui.QDialog.__init__(self)
     #self.Dialog = QtGui.QDialog(self)
     self.setupUi(self)
     self.pushButton.clicked.connect(self.start)
     # self.label = QtGui.QLabel()
     #self.table=QtGui.QTableWidget(self)
     #self.tableWidget.setItem(1,1,  QtGui.QTableWidgetItem("55555"))
     #self.label.setGeometry(QtCore.QRect(10, 10, 201, 31))   #run (start) function when clicked
     #self.pushButton_2.clicked.connect(self.stop)
     #self.radioButton.clicked.connect(self.loopback)
     #self.radioButton_2.clicked.connect(self.wifi)
     #self.radioButton_3.clicked.connect(self.ethernet)
     #self.radioButton_4.clicked.connect(self.bluetooth)
     #self.radioButton_5.clicked.connect(self.any)
     
    
   #def start(self):
   # for i in range(0, 70 ):
       
    #     self.tableWidget.setItem(i,0,  QtGui.QTableWidgetItem(str(i+1)))
     #    self.tableWidget.setItem=M
   def print_to(self,l, j,  x):
         #m=self.tableWidget.setItem
         self.tableWidget.setItem(l,0,  QtGui.QTableWidgetItem(x))  
   row = 0
   column =0      
   def print_to_tabl(self ,l, j,  x):
       self.tableWidget.setItem(l, j, QtGui.QTableWidgetItem(x))

       return l
   #def stop(self):
    #  snif.stop()

  # def loopback(self):
  # def wifi(self):
  # def ethernet(self):
  # def bluetooth(self):
  # def any(self):

   #tableWidget.setItem(0,0,  QtGui.QTableWidgetItem("55555"))
#QtGui.table.setItem(0,0,  QtGui.QTableWidgetItem("55555"))

   def start(self):

     pcap = Pcap('capture.pcap')
     conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

     for i in range(0, 70):
        x=time.clock()
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        eth = Ethernet(raw_data)

        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))
        mydialog.print_to_tabl(self, i, 0, str(i+1))
        mydialog.print_to_tabl(self, i, 1, str(x))

        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))
            mydialog.print_to_tabl(self, i, 2, ipv4.src)
            mydialog.print_to_tabl(self, i, 3, ipv4.target)
            mydialog.print_to_tabl(self, i, 5,str(ipv4.header_length))

            # ICMP
            if ipv4.proto == 1:

                icmp = ICMP(ipv4.data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                print(TAB_2 + 'ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp.data))
                mydialog.print_to_tabl(self,i, 4, "ICMP")

            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))
                mydialog.print_to_tabl(self,i, 4, "tcp")
                mydialog.print_to_tabl(self, i, 6,'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment) )

                if len(tcp.data) > 0:

                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp.data))

            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port,
                                                                                         udp.size))
                mydialog.print_to_tabl(self,i, 4, "UDP")

            # Other IPv4
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_multi_line(self,DATA_TAB_2, ipv4.data))
                mydialog.print_to_tabl(self, i, 4, "ICMP")

       # else:
            #print('Ethernet Data:')
            #print(format_multi_line(DATA_TAB_1, eth.data))
            #mydialog.print_to_tabl(self, i, 6, str(eth.data))

        # if pushButton_2.clicked :
        #  break

     pcap.close()

app = QtGui.QApplication(sys.argv)
window = mydialog()
window.show()
app.exec_()


# QtGui.QTableWidgetItem()

#QtGui.table.setItem(0,0,  QtGui.QTableWidgetItem("55555")
