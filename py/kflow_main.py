from flask import request, jsonify
import pyshark
import pickle
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
    
    # Initialize a dictionary to store call flows
    call_flows = {}
    sip_packets = {}
    packetNo = 1
    call_ids = []

    with open(flowTxtPath, 'w') as file:
        file.write("")

    # Iterate over each packet
    for packet in cap:
        if 'SIP' in packet:

            fullPacket=""
            fullPacket += packet.frame_info.__str__()
            fullPacket += packet.__str__()
            sip = packet.sip

            sip_packets.update({packetNo: str(fullPacket)})
            

            call_id = sip.get_field_value('Call-ID')

            src_ip = f'"{packet.ip.src}:{packet[packet.transport_layer].srcport}"'
            dst_ip = f'"{packet.ip.dst}:{packet[packet.transport_layer].dstport}"'


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
            

            if call_id not in call_ids:
                call_ids.append(call_id)


            # Add call flow to the dictionary
            if call_id not in call_flows:
                # call_flows[call_id] = [{'src': src_ip, 'dst': dst_ip, 'msg': message}]
                call_flows[call_id] = [{packetNo: f"\n{src_ip}->{dst_ip} : {message}"}]
                # tmpName = clean_filename(call_id)
                # tmpPath = os.path.join(tmp_data, tmpName + '.txt')
                # with open(tmpPath, 'a') as file:
                #     file.write(f"\n{src_ip}->{dst_ip} : {message}")
                
                

            else:
                # call_flows[call_id].append({'src': src_ip, 'dst': dst_ip, 'msg': message})
                call_flows[call_id].append({packetNo: f"\n{src_ip}->{dst_ip} : {message}"})
                # tmpName = clean_filename(call_id)
                # tmpPath = os.path.join(tmp_data, tmpName + '.txt')
                # with open(tmpPath, 'w') as file:
                #     file.write(f"\n{src_ip}->{dst_ip} : {message}")

            
            packetNo+=1


            with open(flowTxtPath, 'a') as file:
                file.write(f"\n{src_ip}->{dst_ip} : {message}")
    
    print(call_ids)
    #save call_ids to pkl
    save_list_to_pkl(call_ids, pcap_filename+'.cid.pkl')


    # Convert dictionary to JSON string
    sip_json = json.dumps(sip_packets)
    # Write JSON string to a file    
    with open(sipJsonPath, 'w') as json_file:
        json_file.write(sip_json)


def save_list_to_pkl(my_list, filename):
    pklPath = os.path.join(tmp_data, filename)
    with open(pklPath, 'wb') as file:
        pickle.dump(my_list, file)


def load_list_from_pkl(filename):
    pklPath = os.path.join(tmp_data, filename)
    with open(pklPath, 'rb') as file:
        return pickle.load(file)


def getJsonFile(fileName):
    jsonPath = os.path.join(tmp_data, fileName + '.json')
    if not os.path.exists(jsonPath):
        generate_call_flow_diagram(fileName)

    with open(jsonPath, 'r') as f:
        return f.read()
    
def getFlowText(fileName):
    flowTxtPath = os.path.join(tmp_data, fileName + '.txt')
    if not os.path.exists(flowTxtPath):
        generate_call_flow_diagram(fileName)

    with open(flowTxtPath, 'r') as f:
            return f.read()



def generateFilterredCallIdFlow(pcapname, cid, cidSr):

    flowTxtPath = os.path.join(tmp_data, pcapname +'.'+ str(cidSr) +'.txt')
    pcap_file_path=os.path.join(data_path, pcapname)
    fPcap = pyshark.FileCapture(pcap_file_path, display_filter=f'sip.Call-ID == "{cid}"')

    sip_packets = {}
    packetNo = 1

    with open(flowTxtPath, 'w') as file:
        file.write("")

    for packet in fPcap:

        fullPacket=""
        fullPacket += packet.frame_info.__str__()
        fullPacket += packet.__str__()

        sip_packets.update({packetNo: str(fullPacket)})

        packetNo+=1

        src_ip = f'"{packet.ip.src}:{packet[packet.transport_layer].srcport}"'
        dst_ip = f'"{packet.ip.dst}:{packet[packet.transport_layer].dstport}"'
        if hasattr(packet.sip, 'request_line'):
            # This is a SIP request
            request_line = packet.sip.request_line
            message = request_line.split()[0]
        elif hasattr(packet.sip, 'status_line'):
            # This is a SIP response
            status_line = packet.sip.status_line
            message = status_line.split()[1]

        with open(flowTxtPath, 'a') as file:
            file.write(f"\n{src_ip}->{dst_ip} : {message}")

    with open(flowTxtPath, 'r') as f:
        return f.read()
