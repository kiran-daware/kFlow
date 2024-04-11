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
    nid=extractNumbers(id)
    // console.log(sipDictData[nid])
    var xmlContent=convertAnsiToHtml(sipDictData[nid])
    document.getElementById("popup-content").innerHTML = xmlContent;
    document.getElementById("popup-modal").style.display = "block";
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
        var style = '';
        switch (code) {
            // case 1: // Bold
            //     style = 'font-weight: bold;';
            //     break;
            case 33: // Yellow
                style = 'color: orange;';
                break;
            case 32: // green
                style = 'color: green;';
                break;
            // Add more cases for other ANSI escape codes as needed
            default:
                // Handle unsupported codes or other cases
                break;
        }
    
        // Wrap matched text with span and apply style
        return '<span style="' + style + '">' + text + '</span>';
    });
    
    
    var reForBoldHeader = /(\t*)(Message Header|Message Body)/g;
    
    return ansidecoded.replace(reForBoldHeader, '<span style="font-weight:bold;color:orange;">$2</span>');
    };
