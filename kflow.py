import pyshark
import json

def generate_call_flow_diagram(pcap_file):
    # Open pcap file
    cap = pyshark.FileCapture(pcap_file)
    
    p=cap[0]
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
    with open('flow.txt', 'w') as file:
        file.write("")

    # Iterate over each packet
    for packet in cap:
        if 'SIP' in packet:
            # Extract SIP information
            sip = packet.sip
            # print(sip.field_names)
            # print(str(sip))
            sip_msgs.update({msgSr: str(sip)})
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


            with open('flow.txt', 'a') as file:
                file.write(f"\n{src_ip}->{dst_ip} : {message}")

        # print(sip_msgs)

    # Convert dictionary to JSON string
    sip_json = json.dumps(sip_msgs)
    # Write JSON string to a file
    with open('sip_dict.json', 'w') as json_file:
        json_file.write(sip_json)

    
    # puml = plantuml.PlantUML("http://10.122.24.240:8080/img/")
    # puml.processes_file('flow.txt')





    # for cid, cdata in call_flows.items():
    #     # print(cid)
    #     # print(cdata)

    #     ingress_ip = None
    #     for i in range(len(cdata)):
    #         src_ip = cdata[i]['src']
    #         dst_ip = cdata[i]['dst']
    #         msg_type = cdata[i]['msg']

    #         # If the first message is INVITE, assign its source IP as the ingress IP
    #         if msg_type == 'INVITE' and ingress_ip is None:
    #             ingress_ip = src_ip

            # if src_ip==ingress_ip:
                # print(f"A =========> {msg_type} =========> B ")

                # with open('flow.txt', 'a') as file:
                #     file.write(f"\n{src_ip}->{dst_ip} : {msg_type}")

            # else:
                # print(f"A <========= {msg_type} <========= B ")

                # with open('flow.txt', 'a') as file:
                #     file.write(f"\n{src_ip}->{dst_ip} : {msg_type}")

    # puml = plantuml.PlantUML("http://10.122.24.240:8080/img/")
    # puml.processes_file('flow.txt')



# # Example usage
generate_call_flow_diagram("basic-call2.pcapng")

