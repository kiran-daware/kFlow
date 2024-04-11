from flask import request, jsonify
import pyshark
import json, re
import os

# Get the directory of the current Python file, base dir of flask and kflow_data dir
current_dir = os.path.abspath(os.path.dirname(__file__))
base_dir = os.path.abspath(os.path.join(current_dir, '..'))
data_path = os.path.abspath(os.path.join(base_dir, 'kflow_data'))
tmp_data = os.path.abspath(os.path.join(data_path, 'tmp'))


def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file:
        filename = clean_filename(file.filename)
        # Save the file to the desired location
        fileSavePath = pcap_file_path=os.path.join(data_path, filename)
        file.save(fileSavePath)

        generate_call_flow_diagram(filename)

        return jsonify({'message': 'File uploaded successfully'}), 200
    
def clean_filename(filename):
    # Replace spaces with underscores
    cleaned_filename = filename.replace(' ', '_')
    # Remove any characters that are not alphanumeric, underscores, hyphens, or periods
    cleaned_filename = re.sub(r'[^\w\-\.]', '', cleaned_filename)
    return cleaned_filename


def list_files():
    files = []
    for filename in os.listdir(data_path):
        if os.path.isfile(os.path.join(data_path, filename)):
            files.append(filename)
    return files


def generate_call_flow_diagram(pcap_filename):

    flowTxtPath = os.path.join(tmp_data, pcap_filename + '.txt')
    sipJsonPath = os.path.join(tmp_data, pcap_filename + '.json')

    # Open pcap file
    pcap_file_path=os.path.join(data_path, pcap_filename)
    cap = pyshark.FileCapture(pcap_file_path)
    
    # p=cap[0]
    # if 'IP' in p:
    #     print(p.ip.field_names)
    # if 'UDP' in p:
    #     print(p.udp.field_names)
    # if 'SIP' in p:
    #     print(p.sip.field_names)

    # Initialize a dictionary to store call flows
    call_flows = {}
    sip_msgs = {}
    msgSr = 1

    with open(flowTxtPath, 'w') as file:
        file.write("")

    # Iterate over each packet
    for packet in cap:
        if 'SIP' in packet:
            # Extract SIP information
            sip = packet.sip
            # print(sip.field_names)
            # print(str(sip))
            sip_msgs.update({msgSr: str(packet)})
            msgSr+=1

            call_id = sip.get_field_value('Call-ID')
            src_ip = f'"{packet.ip.src}:{packet.udp.srcport}"'
            dst_ip = f'"{packet.ip.dst}:{packet.udp.dstport}"'

            if hasattr(sip, 'request_line'):
                # This is a SIP request
                request_line = sip.request_line
                message = request_line.split()[0]
                
                # print(f"\n{src_ip} =========> {message} =========> {dst_ip} \n")
                   
            elif hasattr(sip, 'status_line'):
                # This is a SIP response
                status_line = sip.status_line
                message = status_line.split()[1]

                # print(f"\n{dst_ip} <========= {message} <========= {src_ip} \n")
            

            # Add call flow to the dictionary
            if call_id not in call_flows:
                call_flows[call_id] = [{'src': src_ip, 'dst': dst_ip, 'msg': message}]

            else:
                call_flows[call_id].append({'src': src_ip, 'dst': dst_ip, 'msg': message})


            with open(flowTxtPath, 'a') as file:
                file.write(f"\n{src_ip}->{dst_ip} : {message}")


    # Convert dictionary to JSON string
    sip_json = json.dumps(sip_msgs)
    # Write JSON string to a file    
    with open(sipJsonPath, 'w') as json_file:
        json_file.write(sip_json)

    
def getJsonFile(fileName):
    jsonPath = os.path.join(tmp_data, fileName + '.json')
    with open(jsonPath, 'r') as f:
        return f.read()
    
def getFlowText(fileName):
    flowTxtPath = os.path.join(tmp_data, fileName + '.txt')
    with open(flowTxtPath, 'r') as f:
            return f.read()
        