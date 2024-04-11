import os, pyshark

# Get the directory of the current Python file, base dir of flask and kflow_data dir
current_dir = os.path.abspath(os.path.dirname(__file__))
base_dir = os.path.abspath(os.path.join(current_dir, '..'))
data_path = os.path.abspath(os.path.join(base_dir, 'kflow_data'))
tmp_data = os.path.abspath(os.path.join(data_path, 'tmp'))


pcap_file_path=os.path.join(data_path, 'basic-call.pcapng')

cap = pyshark.FileCapture(pcap_file_path)
p=cap[0]
print(p.SIP.field_names)