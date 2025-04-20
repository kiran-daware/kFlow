import subprocess

def tshark_extract(pcap_path, fields, display_filter="sip", limit=None):
    """
    Extract specific fields from a pcap file using tshark.

    :param pcap_path: Path to the .pcap file
    :param fields: List of tshark fields to extract (e.g. ['frame.time', 'ip.src', 'sip.Call-ID'])
    :param display_filter: Tshark display filter (e.g. 'sip', 'sip.Method=="INVITE"')
    :param limit: Optional limit to the number of packets
    :return: List of dictionaries, each with keys matching the field names
    """
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

    try:
        result = subprocess.run(
            base_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )

        parsed_data = []
        for line in result.stdout.splitlines():
            values = line.strip().split('|')
            entry = dict(zip(fields, values))
            parsed_data.append(entry)

        return parsed_data

    except subprocess.CalledProcessError as e:
        print(f"[tshark_extract] Error running tshark: {e.stderr}")
        return []

