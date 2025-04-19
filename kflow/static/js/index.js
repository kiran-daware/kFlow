const dropArea = document.getElementById('drop-area');
const fileInput = document.getElementById('file-input');
const uploadBtn = document.getElementById('upload-btn');

['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropArea.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

['dragenter', 'dragover'].forEach(eventName => {
    dropArea.addEventListener(eventName, highlight, false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropArea.addEventListener(eventName, unhighlight, false);
});

function highlight() {
    dropArea.classList.add('dragging');
}

function unhighlight() {
    dropArea.classList.remove('dragging');
}

dropArea.addEventListener('drop', handleDrop, false);

function handleDrop(e) {
    let dt = e.dataTransfer;
    let files = dt.files;

    handleFiles(files);
}

fileInput.addEventListener('change', handleFileInput, false);

function handleFileInput(e) {
    let files = e.target.files;
    handleFiles(files);
}

function handleFiles(files) {
    if (files.length > 0) {
        const file = files[0];
        if (isWiresharkFile(file.name)) {
            console.log('File:', file.name);
            const formData = new FormData();
            formData.append('file', file);
            // Send the file to the server
            fetch('/pcapupload', {
                method: 'POST',
                body: formData
            }).then(response => {
                if (response.ok) {
                    alert('File uploaded successfully');
                } else {
                    alert('Failed to upload file');
                }
            }).catch(error => {
                console.error('Error uploading file:', error);
            });
        } else {
            alert('Please select a valid Wireshark pcap file.');
        }
    }
}

function isWiresharkFile(filename) {
    return filename.endsWith('.pcap') || filename.endsWith('.pcapng');
}
uploadBtn.addEventListener('click', () => {
    fileInput.click();
});


// function to call python flow function or delete files function
// function callPyKflow(filename) {
//     if(action === 'kflow') {
//         fetch('/kflow?filename=' + filename)
//     }
// }