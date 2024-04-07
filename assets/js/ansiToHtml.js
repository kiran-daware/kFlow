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