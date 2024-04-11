from flask import Flask, render_template, request, jsonify
from py.kflow_main import getFlowText, upload_file, list_files, getJsonFile

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
    if pcapName is None:
        return "Error: 'filename' parameter is missing from the URL"
    
    flowText = getFlowText(pcapName)
    return render_template('kflow.html', flowText = flowText, pcapName = pcapName)


@kFlow.route('/get_json')
def get_json():
    pcapName = request.args.get('pcapname')
    if pcapName is None:
        return "Error: 'filename' parameter is missing from the URL"
    
    flowJson = getJsonFile(pcapName)
    return jsonify(flowJson)



if __name__ == '__main__':
    kFlow.run(debug=True)
