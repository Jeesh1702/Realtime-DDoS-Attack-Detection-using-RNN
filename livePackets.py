import pyshark
import csv


pcap_file = 'packets.pcap'
csv_output_file = 'packets.csv'



fields = [
    'frame.len', 'frame.protocols', 'ip.hdr_len', 'ip.len', 'ip.flags.rb', 'ip.flags.df', 'ip.flags.mf', 'ip.frag_offset',
    'ip.ttl', 'ip.proto', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'tcp.len', 'tcp.ack',
    'tcp.flags.res', 'tcp.flags.ns', 'tcp.flags.cwr', 'tcp.flags.ecn', 'tcp.flags.urg', 'tcp.flags.ack',
    'tcp.flags.push', 'tcp.flags.reset', 'tcp.flags.syn', 'tcp.flags.fin', 'tcp.window_size', 'tcp.time_delta', 'class'
]

with open(csv_output_file, mode='w', newline='') as csv_file:
    writer = csv.DictWriter(csv_file, fieldnames=fields)
    writer.writeheader()

    cap = pyshark.FileCapture(pcap_file)
    for packet in cap:
        packet_data = {}
        
        packet_data['class'] = 'normal'
        packet_data['frame.len'] = 1
        packet_data['frame.protocols'] = ''

        try:
            ip = packet.ip
        except:
            continue
        
        packet_data['ip.hdr_len'] = packet.ip.hdr_len
        packet_data['ip.len'] = packet.ip.len
        flag = bin(int(packet.ip.flags[3]))[2:].zfill(3)
        packet_data['ip.flags.rb'] = int(flag[0])
        packet_data['ip.flags.df'] = int(flag[1])
        packet_data['ip.flags.mf'] = int(flag[2])
        packet_data['ip.frag_offset'] = 0
        packet_data['ip.ttl'] = packet.ip.ttl
        packet_data['ip.proto'] = packet.ip.proto
        packet_data['ip.src'] = packet.ip.src
        packet_data['ip.dst'] = packet.ip.dst
        
        
        try:
            tcp = packet.tcp
        except:
            continue
        
        packet_data['tcp.srcport'] = packet.tcp.srcport
        packet_data['tcp.dstport'] = packet.tcp.dstport
        packet_data['tcp.len'] = packet.tcp.len
        packet_data['tcp.ack'] = packet.tcp.ack
        flag = packet.tcp.flags[3:]
        flag = bin(int(flag, 16))[2:].zfill(12)
        # print(int(flag[0:3],2))
        packet_data['tcp.flags.res'] = int(flag[0:3],2)
        packet_data['tcp.flags.ns'] = int(flag[10])
        packet_data['tcp.flags.cwr'] = int(flag[4])
        packet_data['tcp.flags.ecn'] = int(flag[3])
        packet_data['tcp.flags.urg'] = int(flag[6])
        packet_data['tcp.flags.ack'] = int(flag[7])
        packet_data['tcp.flags.push'] = int(flag[8])
        packet_data['tcp.flags.reset'] = int(flag[9])
        packet_data['tcp.flags.syn'] = int(flag[10])
        packet_data['tcp.flags.fin'] = int(flag[11])
        packet_data['tcp.window_size'] = packet.tcp.window_size
        packet_data['tcp.time_delta'] = packet.tcp.time_delta

        writer.writerow(packet_data)