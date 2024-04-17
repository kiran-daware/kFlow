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


def uploadFile():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file:
        filename = cleanFilename(file.filename)
        # Save the file to the desired location
        fileSavePath=os.path.join(data_path, filename)
        file.save(fileSavePath)

        return jsonify({'message': 'File uploaded successfully'}), 200
    
def cleanFilename(filename):
    # Replace spaces with underscores
    cleaned_filename = filename.replace(' ', '_')
    # Remove any characters that are not alphanumeric, underscores, hyphens, or periods
    cleaned_filename = re.sub(r'[^\w\-\.]', '', cleaned_filename)
    return cleaned_filename


def listFiles():
    files = []
    for filename in os.listdir(data_path):
        if os.path.isfile(os.path.join(data_path, filename)):
            files.append(filename)
    return files


def saveToPickle(my_obj, pklPath):
    with open(pklPath, 'wb') as file:
        pickle.dump(my_obj, file)


def loadPickle(pklPath):
    with open(pklPath, 'rb') as file:
        return pickle.load(file)


def getJsonFile(jsonName):
    jsonPath = os.path.join(tmp_data, jsonName)
    with open(jsonPath, 'r') as f:
        return f.read()


def extractCalls(pcap_filename):
    pklPath = os.path.join(tmp_data, pcap_filename+'.calls.pkl')
    if not os.path.exists(pklPath):
        limitCalls = 500
        # Open pcap file
        pcap_file_path=os.path.join(data_path, pcap_filename)
        allCalls = pyshark.FileCapture(pcap_file_path, display_filter='sip.Method==INVITE')

        succeessCallIdSet = set()
        successCalls = pyshark.FileCapture(pcap_file_path, display_filter='sip.Status-Code == 200 && sip.CSeq.method == INVITE')
        limitCnt=0
        for p in successCalls:
            if limitCnt > limitCalls:
                break
            succeessCallIdSet.add(p.sip.call_id)
            limitCnt+=1
        successCalls.close()

        call_flows = {}
        noOfCalls = 0
        # list_sc=['404','488','486','408','480','403','603','410','301','404','502','584','501','503','606','404','504','500']

        for pkt in allCalls:
            if noOfCalls > limitCalls:
                print(f'Too Many Calls! More than {limitCalls}')
                break
            invite = pkt.sip
            call_id = invite.get_field_value('Call-ID')
            fromAddr = invite.from_addr
            toAddr = invite.to_addr

            if call_id not in call_flows:
                noOfCalls +=1 
                startTime = pkt.frame_info.time
                src_ip = f'{pkt.ip.src}:{pkt[pkt.transport_layer].srcport}'
                dst_ip = f'{pkt.ip.dst}:{pkt[pkt.transport_layer].dstport}'

                if call_id in succeessCallIdSet:
                    callStatus = 'Successful Call'
                else: callStatus = 'Failed Call'            

                call_flows[call_id] = {'time': startTime, 'from': fromAddr, 'to': toAddr, 'status': callStatus, 'src': src_ip, 'dst': dst_ip}
        
        allCalls.close()
        saveToPickle(call_flows, pklPath)

    else: call_flows=loadPickle(pklPath)

    return call_flows




def generateCallFlowFilter(pcapFilename, displayFilter):

    trackFilterPkl = os.path.join(tmp_data, pcapFilename+'.f.pkl')
    if os.path.exists(trackFilterPkl):
        trackFilter = loadPickle(trackFilterPkl)
    else: trackFilter = {}
    
    if displayFilter not in trackFilter:
        trackFilter[displayFilter] = len(trackFilter) + 1
        saveToPickle(trackFilter, trackFilterPkl)
    
    fNo = trackFilter[displayFilter]

    flowTxtPath = os.path.join(tmp_data, pcapFilename + f'.f{fNo}.txt')
    jsonName = pcapFilename+f'.f{fNo}.json'
    sipJsonPath = os.path.join(tmp_data, jsonName)

    if not os.path.exists(flowTxtPath) or not os.path.exists(sipJsonPath):
        sip_packets = {}
        pktNo = 1
        # Open pcap file
        pcap_file_path=os.path.join(data_path, pcapFilename)
        fCap = pyshark.FileCapture(pcap_file_path, display_filter=displayFilter)

        with open(flowTxtPath, 'w') as file:
            file.write("")

        for p in fCap:
            fullP=""
            fullP += p.frame_info.__str__()
            fullP += p.__str__()
            # save all sip packets in sip_packets dictionary with a serial number to match with ID later in diagram
            sip_packets.update({pktNo: str(fullP)})
            pktNo +=1
            src_ip, dst_ip, sip_msg = getSrcDstMsg(p)

            with open(flowTxtPath, 'a') as file:
                file.write(f"\n{src_ip}->{dst_ip} : {sip_msg}")

        # Convert dictionary to JSON string
        sip_json = json.dumps(sip_packets)
        # Write JSON string to a file    
        with open(sipJsonPath, 'w') as json_file:
            json_file.write(sip_json)

    return flowTxtPath, jsonName



def getSrcDstMsg(packet):
    src_ip = f'"{packet.ip.src}:{packet[packet.transport_layer].srcport}"'
    dst_ip = f'"{packet.ip.dst}:{packet[packet.transport_layer].dstport}"'
    sip = packet.sip
    if hasattr(sip, 'request_line'):
        request_line = sip.request_line
        sip_msg = request_line.split()[0]
    elif hasattr(sip, 'status_line'):
        status_line = sip.status_line
        status_code, reason_phrase = status_line.split(maxsplit=2)[1:]
        sip_msg = status_code +" "+ reason_phrase

    return src_ip, dst_ip, sip_msg







# def generate_call_flow_diagram(pcap_filename):

#     flowTxtPath = os.path.join(tmp_data, pcap_filename + '.txt')
#     sipJsonPath = os.path.join(tmp_data, pcap_filename + '.json')

#     # Open pcap file
#     pcap_file_path=os.path.join(data_path, pcap_filename)
#     cap = pyshark.FileCapture(pcap_file_path, display_filter='sip')
    
    
#     # Initialize a dictionary to store call flows
#     call_flows = {}
#     sip_packets = {}
#     packetNo = 1
#     call_ids = []

#     with open(flowTxtPath, 'w') as file:
#         file.write("")

#     # Iterate over each packet
#     for packet in cap:
#         sip = packet.sip
#         fullPacket=""
#         fullPacket += packet.frame_info.__str__()
#         fullPacket += packet.__str__()
#         sip = packet.sip
#         # save all sip packets in sip_packets dictionary with a serial number to match with ID later in diagram
#         sip_packets.update({packetNo: str(fullPacket)})
        
#         call_id = sip.get_field_value('Call-ID')

#         src_ip = f'"{packet.ip.src}:{packet[packet.transport_layer].srcport}"'
#         dst_ip = f'"{packet.ip.dst}:{packet[packet.transport_layer].dstport}"'


#         if hasattr(sip, 'request_line'):
#             # This is a SIP request
#             request_line = sip.request_line
#             message = request_line.split()[0]
            
#             # print(f"\n{src_ip} =========> {message} =========> {dst_ip} \n")
                
#         elif hasattr(sip, 'status_line'):
#             # This is a SIP response
#             status_line = sip.status_line
#             message = status_line.split()[1]

#             # print(f"\n{dst_ip} <========= {message} <========= {src_ip} \n")
        

#         if call_id not in call_ids:
#             call_ids.append(call_id)


#         # Add call flow to the dictionary
#         if call_id not in call_flows:
#             # call_flows[call_id] = [{'src': src_ip, 'dst': dst_ip, 'msg': message}]
#             call_flows[call_id] = [{packetNo: f"\n{src_ip}->{dst_ip} : {message}"}]
#             # tmpName = clean_filename(call_id)
#             # tmpPath = os.path.join(tmp_data, tmpName + '.txt')
#             # with open(tmpPath, 'a') as file:
#             #     file.write(f"\n{src_ip}->{dst_ip} : {message}")
            
            

#         else:
#             # call_flows[call_id].append({'src': src_ip, 'dst': dst_ip, 'msg': message})
#             call_flows[call_id].append({packetNo: f"\n{src_ip}->{dst_ip} : {message}"})
#             # tmpName = clean_filename(call_id)
#             # tmpPath = os.path.join(tmp_data, tmpName + '.txt')
#             # with open(tmpPath, 'w') as file:
#             #     file.write(f"\n{src_ip}->{dst_ip} : {message}")

            
#         packetNo+=1


#         with open(flowTxtPath, 'a') as file:
#             file.write(f"\n{src_ip}->{dst_ip} : {message}")
    
#     print(call_ids)
#     #save call_ids to pkl
#     pklPath = os.path.join(tmp_data, pcap_filename+'.cid.pkl')
#     saveToPickle(call_ids, pklPath)


#     # Convert dictionary to JSON string
#     sip_json = json.dumps(sip_packets)
#     # Write JSON string to a file    
#     with open(sipJsonPath, 'w') as json_file:
#         json_file.write(sip_json)





    
