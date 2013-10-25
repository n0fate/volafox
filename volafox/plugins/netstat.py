# reference
# http://opensource.apple.com/source/xnu/xnu-2422.1.72/bsd/netinet/in_pcb.h

import sys
import struct

from tableprint import columnprint

DATA_PTR_SIZE = [[4, '=I'], [8, '=Q']]

# Lion/SN 32bit, ML/Lion/SN 64bit, Mavericks
DATA_NETWORK_STRUCTURE = [[40, '=IIIIII12xI', 16, 112, '>HH48xI36xI12xI'],
    [72, '=Q8xQQQQ16xQ', 24, 156, '>HH80xQ36xI20xI'],
    [120, '=104xQQ', 140, 104, '>HH15xb48xI28xI']]


NETWORK_STATES = {
    0:        'CLOSED',
    1:        'LISTEN',
    2:        'SYN_SENT',
    3:        'SYN_RCVD',
    4:        'ESTABLISHED',
    5:        'CLOSE_WAIT',
    6:        'FIN_WAIT_1',
    7:        'CLOSING',
    8:        'LAST_ACK',
    9:        'FIN_WAIT_2',
    10:        'TIME_WAIT'
}


class network_manager():
    def __init__(self, net_pae, arch, os_version, base_address):
        self.net_pae = net_pae
        self.arch = arch
        self.os_version = os_version
        self.base_address = base_address

    # http://snipplr.com/view.php?codeview&id=14807
    def IntToDottedIP(self, intip):
        octet = ''
        for exp in [3,2,1,0]:
                octet = octet + str(intip / ( 256 ** exp )) + "."
                intip = intip % ( 256 ** exp )
        return(octet.rstrip('.'))

    def network_status_hash(self, sym_addr):
        network_list = []
        if sym_addr == 0:
            return
        if not(self.net_pae.is_valid_address(sym_addr + self.base_address)):
            return
        
        if self.arch == 32:
            PTR_SIZE = DATA_PTR_SIZE[0]
            NETWORK_STRUCTURE = DATA_NETWORK_STRUCTURE[0]
        else:
          if self.os_version == 13:
            PTR_SIZE = DATA_PTR_SIZE[1]
            NETWORK_STRUCTURE = DATA_NETWORK_STRUCTURE[2]
          else:
            PTR_SIZE = DATA_PTR_SIZE[1]
            NETWORK_STRUCTURE = DATA_NETWORK_STRUCTURE[1]
        
        #print 'Real Address (inpcbinfo): %x'%self.net_pae.vtop(sym_addr+self.base_address)
        inpcbinfo_t = self.net_pae.read(sym_addr + self.base_address, NETWORK_STRUCTURE[0])
        inpcbinfo = struct.unpack(NETWORK_STRUCTURE[1], inpcbinfo_t)

        if not(self.net_pae.is_valid_address(inpcbinfo[0])):
            return

        # print 'ipi_count: %d'%inpcbinfo[6]
        
        loop_count = inpcbinfo[1]

        for offset_hashbase in range(0, loop_count):
            inpcb_t = self.net_pae.read(inpcbinfo[0]+(offset_hashbase*PTR_SIZE[0]), PTR_SIZE[0])
            inpcb = struct.unpack(PTR_SIZE[1], inpcb_t)
            loop_addr = inpcb[0]

            if loop_addr == 0:
                continue
            
            if not(self.net_pae.is_valid_address(loop_addr)):
                break
            
            #print 'Real Address (inpcb): %x'%self.net_pae.vtop(inpcb[0])
            inpcb = self.net_pae.read(loop_addr+NETWORK_STRUCTURE[2], NETWORK_STRUCTURE[3])
            in_network = struct.unpack(NETWORK_STRUCTURE[4], inpcb) # fport, lport, flag, fhost, lhost
            
            #print self.net_pae.vtop(loop_addr+NETWORK_STRUCTURE[2])
      #123 struct inpcb {
      #124         LIST_ENTRY(inpcb) inp_hash;     /* hash list */
      #125         int             inp_wantcnt;            /* pcb wanted count. protected by pcb list lock */
      #126         int             inp_state;              /* state of this pcb, in use, recycled, ready for recycling... */
      #127         u_short inp_fport;              /* foreign port */
      #128         u_short inp_lport;              /* local port */
      #129         LIST_ENTRY(inpcb) inp_list;     /* list for all PCBs of this proto */
      #130         caddr_t inp_ppcb;               /* pointer to per-protocol pcb */
      #131         struct  inpcbinfo *inp_pcbinfo; /* PCB list info */
      #132         struct  socket *inp_socket;     /* back pointer to socket */
      #133         u_char  nat_owner;              /* Used to NAT TCP/UDP traffic */
      #134         u_int32_t nat_cookie;           /* Cookie stored and returned to NAT */
      #135         LIST_ENTRY(inpcb) inp_portlist; /* list for this PCB's local port */
      #136         struct  inpcbport *inp_phd;     /* head of this list */
      #137         inp_gen_t inp_gencnt;           /* generation count of this instance */
      #138         int     inp_flags;              /* generic IP/datagram flags */
      #139         u_int32_t inp_flow;
      #140 
      #141         u_char  inp_vflag;      /* INP_IPV4 or INP_IPV6 */
      #142 
      #143         u_char inp_ip_ttl;              /* time to live proto */
      #144         u_char inp_ip_p;                /* protocol proto */
      #145         /* protocol dependent part */
      #146         union {
      #147                 /* foreign host table entry */
      #148                 struct  in_addr_4in6 inp46_foreign;
      #149                 struct  in6_addr inp6_foreign;
      #150         } inp_dependfaddr;
      #151         union {
      #152                 /* local host table entry */
      #153                 struct  in_addr_4in6 inp46_local;
      #154                 struct  in6_addr inp6_local;
      #155         } inp_dependladdr;
    
            network = []
            network.append(in_network[2]) # state
            network.append(self.IntToDottedIP(in_network[3])) # local address
            network.append(self.IntToDottedIP(in_network[4])) # remote address
            network.append(in_network[1]) # local port
            network.append(in_network[0]) # remote port
        
            #print 'Local Address: %s:%d, Foreign Address: %s:%d, flag:%x'%(self.IntToDottedIP(in_network[3]), in_network[1], self.IntToDottedIP(in_network[4]), in_network[0], in_network[2])
            network_list.append(network)

        return network_list
    
    
    def network_status_list(self, sym_addr):
        network_list = []

        if sym_addr == 0:
            return
        if not(self.net_pae.is_valid_address(sym_addr+self.base_address)):
            return

        if self.arch == 32:
            PTR_SIZE = DATA_PTR_SIZE[0]
            NETWORK_STRUCTURE = DATA_NETWORK_STRUCTURE[0]
        else:
            PTR_SIZE = DATA_PTR_SIZE[1]
            NETWORK_STRUCTURE = DATA_NETWORK_STRUCTURE[1]

        inpcbinfo_t = self.net_pae.read(sym_addr+self.base_address, NETWORK_STRUCTURE[0])
        inpcbinfo = struct.unpack(NETWORK_STRUCTURE[1], inpcbinfo_t)

        if not(self.net_pae.is_valid_address(inpcbinfo[4])):
            return

        #print 'Real Address (inpcbinfo): %x'%net_pae.vtop(inpcbinfo[5])

        temp_ptr = inpcbinfo[4] # base address
        #list_t = net_pae.read(inpcbinfo[5], 4)
        #temp_ptr = struct.unpack('=I', list_t)

        #print 'Real Address (inpcbinfo): %x'%net_pae.vtop(temp_ptr)
        
        while self.net_pae.is_valid_address(temp_ptr):
            
            #print 'Real Address (inpcb): %x'%net_pae.vtop(inpcb[0])
            inpcb = self.net_pae.read(temp_ptr+NETWORK_STRUCTURE[3], NETWORK_STRUCTURE[4])
            in_network = struct.unpack(NETWORK_STRUCTURE[5], inpcb) # fport, lport, flag, fhost, lhost
            
            network = []
            network.append(in_network[3])
            network.append(self.IntToDottedIP(in_network[4]))
            network.append(self.IntToDottedIP(in_network[5]))
            network.append(in_network[1])
            network.append(in_network[0])
        
            #print 'Local Address: %s:%d, Foreign Address: %s:%d, flag:%x'%(self.IntToDottedIP(in_network[3]), in_network[1], self.IntToDottedIP(in_network[4]), in_network[0], in_network[2])
            network_list.append(network)

            temp_ptr = in_network[2]
            
        return network_list
#################################### PUBLIC FUNCTIONS ####################################

def get_network_hash(net_pae, tcb_symbol_addr, udb_symbol_addr, arch, os_version, build, base_address):
    NetMan = network_manager(net_pae, arch, os_version, base_address)
    tcp_network_list = NetMan.network_status_hash(tcb_symbol_addr)
    udp_network_list = NetMan.network_status_hash(udb_symbol_addr)
    return tcp_network_list, udp_network_list

def get_network_list(net_pae, tcb_symbol_addr, udb_symbol_addr, arch, os_version, build, base_address):
    NetMan = network_manager(net_pae, arch, os_version, base_address)
    tcp_network_list = NetMan.network_status_list(tcb_symbol_addr)
    udp_network_list = NetMan.network_status_list(udb_symbol_addr)
    return tcp_network_list, udp_network_list

def print_network_list(tcp_network_list, udp_network_list):
    print '[+] NETWORK INFORMATION (hashbase)'
    headerlist = ["Proto", "Local Address", "Foreign Address", "(state)"]
    contentlist = []
    for network in tcp_network_list:
        data = ['tcp']
        data.append('%s:%d'%(network[1], network[3]))
        data.append('%s:%d'%(network[2], network[4]))
        data.append('')
        #data.append('%s'%NETWORK_STATES[network[0]])
        #print '[TCP] Local Address: %s:%d, Foreign Address: %s:%d, flag: %x'%(network[1], network[3], network[2], network[4], network[0])
        
        contentlist.append(data)

    for network in udp_network_list:
        data = ['udp']
        data.append('%s:%d'%(network[1], network[3]))
        data.append('%s:%d'%(network[2], network[4]))
        data.append('')
        #print '[UDP] Local Address: %s:%d, Foreign Address: %s:%d, flag: %x'%(network[1], network[3], network[2], network[4], network[0])
        contentlist.append(data)
        
    mszlist = [-1, -1, -1, -1]
    columnprint(headerlist, contentlist, mszlist)
    
