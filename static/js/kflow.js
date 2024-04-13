let sipDictData = null
fetch('/get_json?pcapname='+ pcapName)
.then(response => response.json())
.then(data => {
    sipDictData = JSON.parse(data)
    // Use the data as needed
});


// Function to extract numbers from a string using regex
function extractNumbers(str) {
    const match = str.match(/\d+/); // Match one or more digits using regex
    return match ? parseInt(match[0]) : null; // Parse the matched digits to integer
}
// show more function used in kmod.js file for signal elements to be clickable for more data
function showMore(id) {
    kpacketId=5
    nid=extractNumbers(id)
    // console.log(sipDictData[nid])
    var xmlContent=convertAnsiToHtml(sipDictData[nid]);
    document.getElementById("popup-content").innerHTML = xmlContent;
    document.getElementById("popup-modal").style.display = "block";
    collapseSipLayers();
}
function closePopup() {
    // Hide the modal
    document.getElementById("popup-modal").style.display = "none";
}



// Conver ANSI to HTML

function convertAnsiToHtml(text) {

    var escapedText = text.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    // Regular expression to match ANSI escape codes and text between them
    var ansiEscapeRegex = /\x1B\[1m(\x1B\[\d{1,2}m)([\s\S]*?)(\x1B\[0m)/g
    var ktext = escapedText.replace(ansiEscapeRegex, '$1$2$3')
    
    var ansiRegex = /\x1B\[(\d{1,2})m([\s\S]*?)\x1B\[0m/g;
    
    // Replace ANSI escape codes and text between them with HTML/CSS styling
    ansidecoded = ktext.replace(ansiRegex, function(match, code, text) {
        // Determine CSS styling based on ANSI escape codes
        code = parseInt(code);
        var kClass = '';
        switch (code) {
            // case 1: // Bold
            //     style = 'font-weight: bold;';
            //     break;
            case 33: // Yellow
                kClass = 'k-layers';
                break;
            case 32: // green
                kClass = 'k-headers';
                break;
            // Add more cases for other ANSI escape codes as needed
            default:
                kClass = 'k-values'
                break;
        }
    
        // Wrap matched text with span and apply style
        return '<span class="' + kClass + '">' + text + '</span>';
    });
    
    ansidecoded=ansidecoded.replace(/\n:/g, " :\n");
    var reForSipHeader = /(\t*)(Message Header|Message Body)/g;

    return ansidecoded.replace(reForSipHeader, '<span class="k-sip">$2</span>');
};



// to make collapsible sip layers
function collapseSipLayers(){
    let layers = document.getElementsByClassName("k-layers");

    // Initially hide all content except for the last one
    for (let i = 0; i < layers.length -1; i++) {
        let nextElement = layers[i].nextElementSibling;
        while (nextElement && !nextElement.classList.contains("k-layers")) {
            nextElement.style.display = 'none';
            nextElement = nextElement.nextElementSibling;
        }
    }

    for (let i = 0; i < layers.length; i++) {
        layers[i].addEventListener("click", function() {
          this.classList.toggle("active");
          let content = this.nextElementSibling;
          while (content && !content.classList.contains("k-layers")) {
            if (content.style.display === "inline") {
              content.style.display = "none";
            } else {
              content.style.display = "inline";
            }
            content = content.nextElementSibling;
          }
        });
    };
};