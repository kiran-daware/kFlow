import os, pyshark, json
from kflow_main import getSrcDstMsg

# Get the directory of the current Python file, base dir of flask and kflow_data dir
current_dir = os.path.abspath(os.path.dirname(__file__))
base_dir = os.path.abspath(os.path.join(current_dir, '..'))
data_path = os.path.abspath(os.path.join(base_dir, 'kflow_data'))
tmp_data = os.path.abspath(os.path.join(data_path, 'tmp'))


# pcap_file_path=os.path.join(data_path, 'SIPmsg_2020_12_10_11_36_57.pcap')

pcap_file_path=os.path.join(data_path, 'basic-call.pcapng')

p = pyshark.FileCapture(pcap_file_path,
                        only_summaries=False)
p.load_packets()
k = p[3]
# print(str(k.frame_info) + str(k) )
# print("======================================")
# print(k.pretty_print())

# print(dir(k.sip))
# print(k.sip.get_field_value('status-code'))

# print(k.sip)

# if hasattr(sip, 'sdp_media'):
#     print(sip.sdp_media)
# print(sip.from_addr)
# print(sip.to_addr)
# if hasattr(p.frame_info, 'time'):
#     print(p.frame_info.time)
# call_id = sip.call_id

# call = pyshark.FileCapture(pcap_file_path, display_filter=f'sip.Call-ID =="{call_id}"')
# for packet in call:
#     if hasattr(packet.sip, 'status_code') and packet.sip.status_code == '200' and packet.sip.cseq_method == 'INVITE':
#         print(packet.sip.cseq_method)

# print(sip.field_names)
# if hasattr(sip, 'status_code'):
#     print(sip.status_code)
# # if 'Method' in p:
# if hasattr(sip, 'method'):
#     print(sip.method)

# print(sip.sent_by_address)
# print(p.layers)
# print(dir(p))
# print(p.frame_info)
# print(p.udp.srcport)


# packet_str = ""

# # Add frame_info
# packet_str += p.frame_info.__str__()

# # Add other layers
# packet_str += p.__str__()
# print(packet_str)
