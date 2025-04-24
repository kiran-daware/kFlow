from flask import request, jsonify
import re
import ujson as json
import os
from datetime import datetime
from .tshark_extract import tshark_extract

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
        return loadFromJson(jsonPath)

    pcap_path = os.path.join(data_path, pcap_filename)
    limitCalls = 10000
    noOfCalls = 0
    call_flows = {}
    status_counter = {}

    # Define tshark fields to extract
    fields = [
        "frame.time", "frame.time_epoch",
        "ip.src", "udp.srcport", "tcp.srcport",
        "ip.dst", "udp.dstport", "tcp.dstport",
        "sip.Call-ID",
        "sip.from.addr","sip.from.user",
        "sip.to.addr",
        "sip.Method",
        "sip.r-uri.user",
        "sip.Status-Code",
        "sip.CSeq.method"
    ]

    # Use your reusable tshark extractor
    packets = tshark_extract(
        pcap_path,
        fields=fields,
        display_filter='sip && !(sip.CSeq.method == "REGISTER") && !(sip.CSeq.method == "OPTIONS")'
    )

    for pkt in packets:
        call_id = pkt.get("sip.Call-ID")
        if not call_id:
            continue

        method = pkt.get("sip.Method")
        status = pkt.get("sip.Status-Code")
        cseq_method = pkt.get("sip.CSeq.method")
        src_ip_port = pkt.get("ip.src") + ":" + pkt.get('udp.srcport') or pkt.get('tcp.srcport')
        dst_ip_port = pkt.get("ip.dst") + ":" + pkt.get('udp.dstport') or pkt.get('tcp.dstport')
        frame_time = pkt.get("frame.time")

        if method == "INVITE" and call_id not in call_flows:
            if noOfCalls >= limitCalls:
                print(f"Too Many Calls! Limit of {limitCalls} exceeded.")
                break

            call_flows[call_id] = {
                'start_time': frame_time.rsplit(' ', 1)[0],
                'start_time_epoch': float(pkt.get("frame.time_epoch")), #internal field
                'src': src_ip_port,
                'dst': dst_ip_port,
                'from': pkt.get("sip.from.addr"),
                'to': pkt.get("sip.to.addr"),
                'from_no': pkt.get("sip.from.user"),
                'dialed_no': pkt.get("sip.r-uri.user"),
                'status': '',
                'answer_time': '',
                'end_time': '',
                'duration': '',
                'events': '(o)INVITE',
                
            }
            noOfCalls += 1
            continue

        if call_id in call_flows:
            event = method or status or ""
            if call_flows[call_id]['src'] == src_ip_port:
                event = f"(o){event}"
            elif call_flows[call_id]['dst'] == src_ip_port:
                event = f"(+){event}"
            call_flows[call_id]['events'] +="_" + event

            if status and cseq_method == "INVITE":
                if status == "200":
                    call_flows[call_id]['status'] = "Answered"
                    status_counter["Answered"] = status_counter.get("Answered", 0) + 1
                    call_flows[call_id]['answer_time'] = frame_time.rsplit(' ', 1)[0]

                elif status.startswith("3"):
                    call_flows[call_id]['status'] = "Redirected" + status
                    status_counter["Redirected"] = status_counter.get("Redirected", 0) + 1

                elif status.startswith("4") or status.startswith("5") or status.startswith("6"):
                    failed_label = "Failed " + status
                    call_flows[call_id]['status'] = failed_label 
                    status_counter[failed_label] = status_counter.get(failed_label, 0) + 1
                    status_counter["Total_Failed"] = status_counter.get("Total_Failed", 0) + 1

                else: 
                    call_flows[call_id]['status'] = status
                    status_counter[status] = status_counter.get(status, 0) + 1
            
                continue

            if status == "200" and cseq_method == "BYE":
                call_flows[call_id]['status'] = "Completed"
                status_counter["Completed"] = status_counter.get("Completed", 0) + 1
                call_flows[call_id]['end_time'] = frame_time.rsplit(' ', 1)[0]
                thisTimeEpoch = float(pkt.get("frame.time_epoch"))
                inviteTimeEpoch = call_flows[call_id]['start_time_epoch']               
                duration = datetime.fromtimestamp(thisTimeEpoch) - datetime.fromtimestamp(inviteTimeEpoch)
                call_flows[call_id]['duration'] = str(duration)
                continue


    # Cache result to json
    saveToJson(call_flows, jsonPath)

    return call_flows






def generateCallFlowFilter(pcapFilename, displayFilter):
    # Track filter usage
    trackFilterJson = os.path.join(tmp_data, pcapFilename + '.f.json')
    trackFilter = loadFromJson(trackFilterJson) if os.path.exists(trackFilterJson) else {}

    if displayFilter not in trackFilter:
        trackFilter[displayFilter] = len(trackFilter) + 1
        saveToJson(trackFilter, trackFilterJson)

    fNo = trackFilter[displayFilter]
    flowTxtPath = os.path.join(tmp_data, f"{pcapFilename}.f{fNo}.txt")
    jsonName = f"{pcapFilename}.f{fNo}.json"
    sipJsonPath = os.path.join(tmp_data, jsonName)

    # Skip if already cached
    if os.path.exists(flowTxtPath) and os.path.exists(sipJsonPath):
        return flowTxtPath, jsonName

    pcap_file_path = os.path.join(data_path, pcapFilename)

    # Run tshark to get essential fields
    fields = [
        # General frame info
        "frame.number",
        "frame.time",
        "frame.len",

        # Network layer
        "ip.src", "ip.dst",

        # Transport layer
        "udp.srcport", "udp.dstport",
        "tcp.srcport", "tcp.dstport",

        # SIP protocol fields
        "sip.Method",
        "sip.Status-Code",
        "sip.CSeq",
        "sip.CSeq.method",
        "sip.Call-ID",
        "sip.from.addr",
        "sip.to.addr",
        "sip.Contact",
        "sip.User-Agent",
        "sip.Via",
        "sip.Request-Line",

        # SDP fields (media/session negotiation)
        "sdp.connection_info",
        "sdp.media",
        "sdp.session_name",
        "sdp.owner",
    ]

    packets = tshark_extract(pcap_file_path, fields, display_filter=displayFilter)
    print("here")
    sip_packets = {}
    with open(flowTxtPath, 'w') as txt_file:
        for i, pkt in enumerate(packets, start=1):

            sip_packets[i] = pkt

            src_ip_port = pkt.get("ip.src") + ":" + pkt.get('udp.srcport') or pkt.get('tcp.srcport')
            dst_ip_port = pkt.get("ip.dst") + ":" + pkt.get('udp.dstport') or pkt.get('tcp.dstport')

            # Reconstruct basic SIP message summary
            method = pkt.get("sip.Method")
            status = pkt.get("sip.Status-Code")
            msg = method if method else status if status else "Unknown"

            txt_file.write(f'\n"{src_ip_port}"->"{dst_ip_port}" : {msg}')

    # Save all packets to JSON
    with open(sipJsonPath, 'w') as json_file:
        json.dump(sip_packets, json_file, indent=2)

    return flowTxtPath, jsonName


def allPacketSummaries(pcapName, displayFilter):
    pcap_file_path = os.path.join(data_path, pcapName)
    
    # These fields match pyshark's summary fields
    fields = [
        "frame.number",
        "frame.time",
        "ip.src",
        "ip.dst",
        "frame.protocols",
        "frame.len",
        "frame"
    ]
    
    # Use your existing tshark_extract function
    raw_packets = tshark_extract(pcap_file_path, fields, display_filter=displayFilter)

    # Map extracted packets into summary-style dicts
    allPackets = []
    for pkt in raw_packets:
        pkt_details = {
            "number": pkt.get("frame.number"),
            "time": pkt.get("frame.time"),
            "source": pkt.get("ip.src"),
            "dest": pkt.get("ip.dst"),
            "protocol": pkt.get("frame.protocols"),
            "length": pkt.get("frame.len"),
            "info": pkt.get("frame.info")
        }
        allPackets.append(pkt_details)

    return allPackets

