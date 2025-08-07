from flask import Flask, request, render_template, flash, redirect, url_for
from kflow.py.kflow_main import upload_file, list_files, get_json_file
from kflow.py.kflow_main import generate_call_flow_filter, extract_calls, all_packet_summaries
from kflow.py.kflow_main import delete_file

app = Flask(__name__)
app.secret_key = 'dev'

@app.route('/')
def index():
    files = list_files()
    return render_template('index.html', files=files)

@app.route('/pcapupload', methods=['POST'])
def upload():
    uploadResponse = upload_file()
    return uploadResponse


@app.route('/all-packets')
def allPackets():
    pcapName = 'basic-call.pcapng'
    allPackets = all_packet_summaries(pcapName, 'sip')
    return render_template('all-packets.html', allPackets = allPackets)


@app.route('/delete-file', methods=['POST'])
def delete():
    filename = request.form.get('filename')
    if filename:
        success = delete_file(filename)
        if success is True:
            flash(f"File '{filename}' deleted successfully.", 'success')
        else:
            flash(success[0], 'error')
    else:
        flash("No filename provided.", 'error')

    return redirect(url_for('index'))


@app.route('/calls')
def kflow():
    pcapName = request.args.get('pcapname')
    if pcapName is not None:
        callFlows = extract_calls(pcapName)
        if len(callFlows) < 2:
            display_filter = 'sip'
            flowTxtPath, jsonName = generate_call_flow_filter(pcapName, display_filter)
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

    jsonName = generate_call_flow_filter(pcapName, display_filter) 

    return render_template('kflow.html', pcapName = pcapName, jsonName = jsonName)


@app.route('/get_json')
def get_json():
    jsonName = request.args.get('json')
    if jsonName is None:
        return "Error: 'filename' parameter is missing from the URL"
    
    flowJson = get_json_file(jsonName)
    return flowJson




# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000)
