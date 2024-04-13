from flask import Flask, render_template, request, jsonify
from py.kflow_main import getFlowText, upload_file, list_files, getJsonFile, load_list_from_pkl
from py.kflow_main import generateFilterredCallIdFlow

kFlow = Flask(__name__)

@kFlow.route('/')
def index():
    files = list_files()
    return render_template('index.html', files=files)

@kFlow.route('/pcapupload', methods=['POST'])
def upload():
    uploadResponse = upload_file()
    return uploadResponse


@kFlow.route('/kflow')
def kflow():
    pcapName = request.args.get('pcapname')
    cidNo = request.args.get('cid-no')

    if pcapName is not None: 
        flowText = getFlowText(pcapName)
        loadCidList = load_list_from_pkl(pcapName+'.cid.pkl')
    else:
        return "Error: 'filename' parameter is missing from the URL"
    
    if cidNo is not None:
        cidSr = int(cidNo) - 1
        flowText = generateFilterredCallIdFlow(pcapName, loadCidList[cidSr], cidSr)


    return render_template('kflow.html', flowText = flowText, pcapName = pcapName, loadCidList = loadCidList)


@kFlow.route('/get_json')
def get_json():
    pcapName = request.args.get('pcapname')
    if pcapName is None:
        return "Error: 'filename' parameter is missing from the URL"
    
    flowJson = getJsonFile(pcapName)
    return jsonify(flowJson)



if __name__ == '__main__':
    kFlow.run(debug=True)
