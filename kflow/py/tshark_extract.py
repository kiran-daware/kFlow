import subprocess

def tshark_extract(pcap_path, fields, display_filter="sip", limit=None):

    base_cmd = [
        "tshark",
        "-r", pcap_path,
        "-Y", display_filter,
        "-T", "fields",
    ]

    for field in fields:
        base_cmd.extend(["-e", field])

    base_cmd.extend(["-E", "separator=|", "-E", "occurrence=a"])

    if limit:
        base_cmd.extend(["-c", str(limit)])

    parsed_data = []
    try:
        with subprocess.Popen(
            base_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as proc:
            for line in proc.stdout:
                values = line.strip().split('|')
                if len(values) == len(fields):
                    entry = dict(zip(fields, values))
                    parsed_data.append(entry)

            # Check for errors after the process has finished
            stderr_output = proc.stderr.read()
            if proc.returncode != 0:
                print(f"[tshark_extract_stream] TShark process failed with error:\n{stderr_output}")


    except FileNotFoundError:
        print("Error: TShark not found. Make sure it's installed and in your system's PATH.")
        return []
    except Exception as e:
        print(f"[tshark_extract_stream] An unexpected error occurred: {e}")
        return []

    return parsed_data







    #     result = subprocess.run(
    #         base_cmd,
    #         stdout=subprocess.PIPE,
    #         stderr=subprocess.PIPE,
    #         text=True,
    #         check=True
    #     )

    #     parsed_data = []
    #     for line in result.stdout.splitlines():
    #         values = line.strip().split('|')
    #         entry = dict(zip(fields, values))
    #         parsed_data.append(entry)

    #     return parsed_data

    # except subprocess.CalledProcessError as e:
    #     print(f"[tshark_extract] Error running tshark: {e.stderr}")
    #     return []



# fields = [
#     "frame.time",
#     "ip.src", "udp.srcport", "tcp.srcport",
#     "ip.dst", "udp.dstport", "tcp.dstport",
#     "sip.Call-ID",
#     "sip.from.addr",
#     "sip.to.addr",
#     "sip.Method",
#     "sip.r-uri",
#     "sip.Status-Code",
#     "sip.CSeq.method"
# ]


# # Use your reusable tshark extractor
# packets = tshark_extract(
#     "/home/kiran/kgit/kFlow/kflow/kflow_data/basic-call.pcapng",
#     fields=fields,
#     display_filter='sip && !(sip.CSeq.method == "REGISTER") && !(sip.CSeq.method == "OPTIONS")'
# )

# # print(packets[0])





