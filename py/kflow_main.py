from flask import request, jsonify
import pyshark
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


def getJsonFile(jsonName):
    jsonPath = os.path.join(tmp_data, jsonName)
    with open(jsonPath, 'r') as f:
        return f.read()


def saveToJson(data, path):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)  # Set indent=2 only if human-readable; remove for performance

def loadFromJson(path):
    with open(path, 'r') as f:
        return json.load(f)

def extractCalls(pcap_filename):
    jsonPath = os.path.join(tmp_data, pcap_filename + '.calls.json')
    if os.path.exists(jsonPath):
        try:
            return loadFromJson(jsonPath)
        except Exception as e:
            print(f"Failed to load JSON cache: {e}")

    limitCalls = 100
    pcap_file_path = os.path.join(data_path, pcap_filename)

    # Parse all SIP packets at once
    sip_packets = pyshark.FileCapture(
        pcap_file_path,
        display_filter='(sip) && !(sip.CSeq.method == "REGISTER") && !(sip.CSeq.method == "OPTIONS")',
        # display_filter ='sip',
        keep_packets=False
    )

    call_flows = {}
    noOfCalls = 0

    for pkt in sip_packets:
        try:
            sip = pkt.sip
            cSeqMethod = sip.get_field_value('CSeq_method')
            requestMethod = sip.get_field_value('Method')
            statusCode = sip.get_field_value('Status-Code')
            call_id = sip.get_field_value('Call-ID')
            src_ip = f'{pkt.ip.src}:{pkt[pkt.transport_layer].srcport}'

            # Track INVITE calls
            if requestMethod == "INVITE" and call_id not in call_flows:
                if noOfCalls >= limitCalls:
                    print(f'Too Many Calls! More than {limitCalls} !!! some last calls may not have been completely analysed')
                    break

                fromAddr = sip.get_field_value('from.addr')
                toAddr = sip.get_field_value('to.addr')
                startTime = pkt.frame_info.time
                # src_ip = f'{pkt.ip.src}:{pkt[pkt.transport_layer].srcport}'
                dst_ip = f'{pkt.ip.dst}:{pkt[pkt.transport_layer].dstport}'


                call_flows[call_id] = {
                    'time': startTime,
                    'src': src_ip,
                    'dst': dst_ip,
                    'from': fromAddr,
                    'to': toAddr,
                    'status': '',
                    'comments': '-Invite->',
                }
                noOfCalls += 1
                continue

            if call_id in call_flows:
                comment = requestMethod if requestMethod else statusCode if statusCode else ''
                if call_flows[call_id]['src'] == src_ip:
                    comment = "-"+comment+"->"
                elif call_flows[call_id]['dst'] == src_ip:
                    comment = "<-"+comment+"-"
                call_flows[call_id]['comments'] += "  " +comment


            # Track successful calls
            if  statusCode and call_id in call_flows and cSeqMethod == "INVITE":
                call_flows[call_id]['status'] = statusCode
                continue

            if statusCode == "200" and cSeqMethod == "BYE" and call_id in call_flows:
                call_flows[call_id]['status'] = "Completed"
                continue

        except AttributeError:
            continue  # Malformed or irrelevant packet


    sip_packets.close()
    saveToJson(call_flows, jsonPath)

    return call_flows



def generateCallFlowFilter(pcapFilename, displayFilter):
    # Load or initialize trackFilter dictionary
    trackFilterJson = os.path.join(tmp_data, pcapFilename + '.f.json')
    trackFilter = loadFromJson(trackFilterJson) if os.path.exists(trackFilterJson) else {}

    if displayFilter not in trackFilter:
        trackFilter[displayFilter] = len(trackFilter) + 1
        saveToJson(trackFilter, trackFilterJson)

    fNo = trackFilter[displayFilter]
    flowTxtPath = os.path.join(tmp_data, f"{pcapFilename}.f{fNo}.txt")
    jsonName = f"{pcapFilename}.f{fNo}.json"
    sipJsonPath = os.path.join(tmp_data, jsonName)

    # Only process if data isn't already cached
    if not os.path.exists(flowTxtPath) or not os.path.exists(sipJsonPath):
        sip_packets = {}
        
        pcap_file_path = os.path.join(data_path, pcapFilename)
        fCap = pyshark.FileCapture(
            pcap_file_path,
            display_filter=displayFilter,
            keep_packets=False
        )
        fCap.load_packets()

        with open(flowTxtPath, 'w') as txt_file:
            for pktNo, p in enumerate(fCap, start=1):
                sip_packets[pktNo] = str(p)
                src_ip, dst_ip, sip_msg = getSrcDstMsg(p)
                txt_file.write(f"\n{src_ip}->{dst_ip} : {sip_msg}")

        fCap.close()

        with open(sipJsonPath, 'w') as json_file:
            json.dump(sip_packets, json_file, indent=2)

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



def allPacketSummaries(pcapName, displayFilter):
    pcap_file_path=os.path.join(data_path, pcapName)
    fCap = pyshark.FileCapture(pcap_file_path, display_filter=displayFilter,
                               only_summaries=True)
    fCap.load_packets()
    allPackets = []
    for p in fCap:
        pkt_details = {
                "number": p.no,
                "time": p.time,
                "source": p.source,
                "dest": p.destination,
                "protocol": p.protocol,
                "length": p.length,
                "info": p.info
            }
        allPackets.append(pkt_details)
    fCap.close()
    return allPackets


