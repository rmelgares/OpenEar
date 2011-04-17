#!/usr/bin/env python
# ZBScanner
# rmelgares 2011
# Promiscious capture on multiple channels at once

import threading, time, os, signal, sys, operator
import string, socket, struct, bitstring
from datetime import datetime

from killerbee import *
import Queue

# Globals
active_queues = []
arg_verbose = False

def broadcast_event(data):
    ''' Send broadcast data to all active threads '''
    print "\nShutting down threads." 
    for q in active_queues:
        q.put(data)

class ThreadClass(threading.Thread):
    ''' Thread to capture on a given channel, using a given device, to a given pcap file, exits when it receives a broadcast shutdown message via Queue.Queue'''
    def __init__(self, dev, channel, pd):
        global active_queues
        threading.Thread.__init__(self)
        self.mesg = Queue.Queue()
        active_queues.append(self.mesg)
        self.channel = channel
        self.dev = dev
        self.pd = pd
        self.packetcount = 0

    def run(self):
        global running, active_queues
        
        self.kb = KillerBee(device=self.dev, datasource="Wardrive Live")
        self.kb.set_channel(self.channel)
        self.kb.sniffer_on()
        print "Capturing on \'%s\' at channel %d." % (self.kb.get_dev_info()[0], self.channel)
        
        # loop capturing packets to dblog and file
        message = ""
        while (True):
            try:
                message = self.mesg.get(timeout=.00001)
            except Queue.Empty:
                pass
            if message == "shutdown":
                break
            packet = self.kb.pnext()
            if packet != None:
                self.packetcount+=1
                self.kb.dblog.add_packet(full=packet)
                self.pd.pcap_dump(packet[0])
                if arg_verbose:
                    print "Packet %d on %d" % (self.packetcount, self.channel)
        # trigger threading.Event set to false, so shutdown thread
        if arg_verbose:
            print "%s on channel %d shutting down..." % (threading.currentThread().getName(), self.channel)
        self.kb.sniffer_off()
        self.kb.close()
        self.pd.close()
        print "%d packets captured on channel %d" % (self.packetcount, self.channel)

def signal_handler(signal, frame):
    ''' Signal handler called on keyboard interrupt to exit threads and exit scanner script'''
    broadcast_event("shutdown")
    time.sleep(1)
    sys.exit(0)

def main(args):
    global arg_verbose
    # parse command line options
    while len(args) > 1:
        op = args.pop(1)
        if op == '-v':
            arg_verbose = True
    if arg_verbose:
        print "Verbose on."

    signal.signal(signal.SIGINT, signal_handler)

    kbdev_info = kb_dev_list()
    channel = 11
    print "Found %d devices." % len(kbdev_info)
    for i in range(0, len(kbdev_info)):
            print 'Device at %s: \'%s\'' % (kbdev_info[i][0], kbdev_info[i][1])
            if channel <= 26:
                print '\tAssigning to channel %d.' % channel
            timeLabel = datetime.now().strftime('%Y%m%d-%H%M')
            fname = 'zb_c%s_%s.pcap' % (channel, timeLabel) #fname is -w equiv
            pcap = PcapDumper(DLT_IEEE802_15_4, fname)
            t = ThreadClass(kbdev_info[i][0], channel, pcap)
            t.start()
            channel += 1

    while True: pass

if __name__ == '__main__':
  main(sys.argv)
