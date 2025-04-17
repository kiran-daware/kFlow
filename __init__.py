from flask import Flask, request, Response, render_template, jsonify
from py.kflow_main import uploadFile, listFiles, getJsonFile
from py.kflow_main import generateCallFlowFilter, extractCalls, allPacketSummaries
from py.kflow_main import allPacketSummaries

app = Flask(__name__)

@app.route('/')
def index():
    files = listFiles()
    return render_template('index.html', files=files)

@app.route('/pcapupload', methods=['POST'])
def upload():
    uploadResponse = uploadFile()
    return uploadResponse


@app.route('/all-packets')
def allPackets():
    pcapName = 'SIPmsg_2020_12_10_11_36_57.pcap'
    allPackets = allPacketSummaries(pcapName, 'sip')
    return render_template('all-packets.html', allPackets = allPackets)



@app.route('/stream_packets')
def stream_packets():
    def generate():
        packet_stream = allPacketSummaries("SIPmsg_2020_12_10_11_36_57.pcap", 'sip')
        for packet_summary in packet_stream:
            yield "data: " + packet_summary + "\n\n"
    return Response(generate(), mimetype='text/event-stream')


@app.route('/packets')
def packets():
    return render_template('packets.html')


@app.route('/calls')
def kflow():
    pcapName = request.args.get('pcapname')
    if pcapName is not None:
        callFlows = extractCalls(pcapName)
        if len(callFlows) < 5:
            display_filter = 'sip'
            flowTxtPath, jsonName = generateCallFlowFilter(pcapName, display_filter)
            with open(flowTxtPath, 'r') as f:
                flowText = f.read()
            return render_template('kflow.html', flowText = flowText, pcapName = pcapName, jsonName = jsonName)

    else:
        return "Error: 'filename' parameter is missing from the URL"
    
    return render_template('calls.html', pcapName = pcapName, callFlows = callFlows)



@app.route('/filtered-calls', methods=['POST'])
def submit():
    # Access form data from the request object
    pcapName = request.form['pcap_name']
    call_ids = request.form.getlist('call_ids')  # Get the list of selected call IDs
    display_filter = f'sip.Call-ID == "{call_ids[0]}"'  # Initialize with the first call ID
    for call_id in call_ids[1:]:
        display_filter += f' || sip.Call-ID == "{call_id}"'  # Add OR conditions for each subsequent call ID

    flowTxtPath, jsonName = generateCallFlowFilter(pcapName, display_filter) 
    with open(flowTxtPath, 'r') as f:
        flowText = f.read()

    return render_template('kflow.html', flowText = flowText, pcapName = pcapName, jsonName = jsonName)


@app.route('/get_json')
def get_json():
    jsonName = request.args.get('json')
    if jsonName is None:
        return "Error: 'filename' parameter is missing from the URL"
    
    flowJson = getJsonFile(jsonName)
    return jsonify(flowJson)




if __name__ == '__main__':
    app.run(debug=True)
