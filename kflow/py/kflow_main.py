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
    pcapName = re.sub(r'\.f\d+\.json$', '', jsonName)
    jsonPath = os.path.join(tmp_data, pcapName, jsonName)
    with open(jsonPath, 'r') as f:
        return f.read()


def saveToJson(data, path):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)  # Set indent=2 only if human-readable; remove for performance

def loadFromJson(path):
    with open(path, 'r') as f:
        return json.load(f)



def extractCalls(pcap_filename):

    # jsonPath = os.path.join(tmp_data, pcap_filename + '.calls.json')
    pcap_path = os.path.join(data_path, pcap_filename)
    jsonDirPath = f"{data_path}/tmp/{pcap_filename}/"
    os.makedirs(jsonDirPath, exist_ok=True)
    jsonPath = os.path.join(jsonDirPath, pcap_filename + '.calls.json')

    stat = os.stat(pcap_path)

    if os.path.exists(jsonPath):
        call_flows = loadFromJson(jsonPath)
        if stat.st_size == call_flows["meta"].get("trace_size") or stat.st_mtime == call_flows["meta"].get("trace_mtime"):
            print("Loading from Json Cache")
            return call_flows
        else:
            print("Generating new calls.jason")
    
    
    limitCalls = 10000
    noOfCalls = 0
    call_flows = {}
    call_flows["meta"] = {}
    call_flows["meta"]["trace_file"] = pcap_filename
    call_flows["meta"]["trace_size"] = stat.st_size 
    call_flows["meta"]["trace_mtime"] = stat.st_mtime
    call_flows["summary"] = {}
    call_flows["failed"] = {}
    call_flows["calls"] = {} #Here, can try to use callid and src ip tuple as a key for dictionary

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

        if method == "INVITE" and call_id not in call_flows["calls"]:
            if noOfCalls >= limitCalls:
                print(f"Too Many Calls! Limit of {limitCalls} exceeded.")
                break

            call_flows["calls"][call_id] = {
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
            call_flows["summary"]["Total Call Legs"] = call_flows["summary"].get("Total Call Legs", 0) + 1
            continue

        if call_id in call_flows["calls"]:
            event = method or status or ""
            if call_flows["calls"][call_id]['src'] == src_ip_port:
                event = f"(o){event}"
            elif call_flows["calls"][call_id]['dst'] == src_ip_port:
                event = f"(+){event}"
            call_flows["calls"][call_id]['events'] +="_" + event

            if status and cseq_method == "INVITE":
                if status == "200":
                    call_flows["calls"][call_id]['status'] = "Answered"
                    call_flows["calls"][call_id]['answer_time'] = frame_time.rsplit(' ', 1)[0]

                elif status.startswith("3"):
                    call_flows["calls"][call_id]['status'] = "Redirected" + status

                elif status.startswith("4") or status.startswith("5") or status.startswith("6"):
                    failed_label = "Failed_" + status
                    call_flows["calls"][call_id]['status'] = failed_label 

                else: 
                    call_flows["calls"][call_id]['status'] = status
            
                continue

            if status == "200" and cseq_method == "BYE":
                call_flows["calls"][call_id]['status'] = "Completed"
                call_flows["calls"][call_id]['end_time'] = frame_time.rsplit(' ', 1)[0]
                thisTimeEpoch = float(pkt.get("frame.time_epoch"))
                inviteTimeEpoch = call_flows["calls"][call_id]['start_time_epoch']               
                duration = datetime.fromtimestamp(thisTimeEpoch) - datetime.fromtimestamp(inviteTimeEpoch)
                call_flows["calls"][call_id]['duration'] = str(duration)
                continue
    
    for call_id, call_data in call_flows.get("calls", {}).items():
        status = call_data.get("status")
        if status.startswith("Failed_"):
            call_flows["failed"][status] = call_flows["failed"].get(status, 0) + 1
            call_flows["summary"]["Failed"] = call_flows["summary"].get("Failed", 0) + 1
            continue

        if not status:
            status = "NoResponse"
            call_data["status"] = status

        call_flows["summary"][status] = call_flows["summary"].get(status, 0) + 1

    # Cache result to json
    saveToJson(call_flows, jsonPath)
    return call_flows




def generateCallFlowFilter(pcapFilename, displayFilter):
    # Track filter usage
    trackFilterJson = os.path.join(tmp_data, pcapFilename, pcapFilename + '.f.json')
    trackFilter = loadFromJson(trackFilterJson) if os.path.exists(trackFilterJson) else {}

    if displayFilter not in trackFilter:
        trackFilter[displayFilter] = len(trackFilter) + 1
        saveToJson(trackFilter, trackFilterJson)

    fNo = trackFilter[displayFilter]
    jsonName = f"{pcapFilename}.f{fNo}.json"
    sipJsonPath = os.path.join(tmp_data, pcapFilename, jsonName)

    # Skip processing json if already cached
    if os.path.exists(sipJsonPath):
        return jsonName

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
        "sip.Request-Line",
        "sip.Status-Line",
        "sip.msg_hdr",
        "sip.msg_body",

        # SDP fields (media/session negotiation)
        "sdp.connection_info",
        "sdp.media",
        "sdp.session_name",
        "sdp.owner",
    ]

    packets = tshark_extract(pcap_file_path, fields, display_filter=displayFilter)
    
    sip_packets = {}
    sip_packets["sequence"] = []

    for pkt in packets:
        src_ip = pkt.get("ip.src", "?")
        dst_ip = pkt.get("ip.dst", "?")
        src_port = pkt.get("udp.srcport") or pkt.get("tcp.srcport") or "?"
        dst_port = pkt.get("udp.dstport") or pkt.get("tcp.dstport") or "?"

        src_ip_port = f"{src_ip}:{src_port}"
        dst_ip_port = f"{dst_ip}:{dst_port}"

        # Reconstruct basic SIP message summary
        msg = pkt.get("sip.Method") or pkt.get("sip.Status-Code") or "Unknown"

        sip_headers = [
            pkt.get("sip.Request-Line"),
            pkt.get("sip.Status-Line"),
            pkt.get("sip.msg_hdr")
        ]

        pkt_body = pkt.get("sip.msg_body")

        sip_packet = "\r\n".join(filter(None, sip_headers))
        if pkt_body:
            sip_packet += "\r\n" + pkt_body


        sip_packets["sequence"].append({
            "from": src_ip_port,
            "to": dst_ip_port,
            "message": msg,
            "packet": sip_packet, 
        })

    # Save all packets to JSON
    with open(sipJsonPath, 'w') as json_file:
        json.dump(sip_packets, json_file, indent=2)

    return jsonName


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

