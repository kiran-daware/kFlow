from flask import Flask, request, render_template, jsonify
from py.kflow_main import uploadFile, listFiles, getJsonFile
from py.kflow_main import generateCallFlowFilter, extractCalls

app = Flask(__name__)

@app.route('/')
def index():
    files = listFiles()
    return render_template('index.html', files=files)

@app.route('/pcapupload', methods=['POST'])
def upload():
    uploadResponse = uploadFile()
    return uploadResponse


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


# @kFlow.route('/kflow')
# def kflow():
#     pcapName = request.args.get('pcapname')
#     cidNo = request.args.get('cid-no')

#     if pcapName is not None: 
#         flowText = getFlowText(pcapName)
#         loadCidList = load_list_from_pkl(pcapName+'.cid.pkl')
#     else:
#         return "Error: 'filename' parameter is missing from the URL"
    
#     if cidNo is not None:
#         cidSr = int(cidNo) - 1
#         flowText = generateFilterredCallIdFlow(pcapName, loadCidList[cidSr], cidSr)


#     return render_template('kflow.html', flowText = flowText, pcapName = pcapName, loadCidList = loadCidList)


# @kFlow.route('/get_json')
# def get_json():
#     pcapName = request.args.get('pcapname')
#     if pcapName is None:
#         return "Error: 'filename' parameter is missing from the URL"
    
#     flowJson = getJsonFile(pcapName)
#     return jsonify(flowJson)



if __name__ == '__main__':
    app.run(debug=True)
