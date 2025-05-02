let sipDictData = null
let umlData = null
let participants_orig = [];
let participants = [];
let k=0;

fetch('/get_json?json='+ jsonName)
.then(response => response.json())
.then(data => {
    sipDictData = data.sequence
    const umlLines = sipDictData.map(entry => {
        return `"${entry.from}"->"${entry.to}" : ${entry.message}`;
      });
    umlData = umlLines.join('\n');      
    // Draw the diagram
    const diagram = Diagram.parse(umlData);
    diagram.drawSVG('diagram', { theme: 'simple' });

    // Use MutationObserver to watch for changes in the SVG container
    const observer = new MutationObserver(() => {
        // Call functions after the diagram has been rendered
        colorForEachCallId();
        participants=participantsArrows();
        observer.disconnect();  // Stop observing once the function has been called
        });

    // Start observing changes in the 'diagram' container
    const diagramElement = document.getElementById('diagram');
    observer.observe(diagramElement, { childList: true, subtree: true });

    });


// Function to extract numbers kid (line element id)
function extractNumbers(str) {
    const match = str.match(/\d+/);
    return match ? parseInt(match[0]) : null;
}


// function to escape html and hex to text for SIP packet data
function escapeHtml(text) {
    return text
      .replace(/&/g, '&amp;')   // Must come first
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }  
function formatSipPacket(raw) {
let unescaped = raw
    .replace(/\\r\\n/g, '\r\n')
    .replace(/\\\\/g, '\\');

const [headers, hexBody] = unescaped.split('\r\n\r\n\r\n');
let decodedBody = '';
if (hexBody) {
    decodedBody = hexBody.match(/.{1,2}/g)
    .map(b => String.fromCharCode(parseInt(b, 16)))
    .join('');
}

const fullText = `${headers}\n\n${decodedBody}`;
return escapeHtml(fullText);
}


// show more function used in kmod.js file for signal elements to be clickable for more data
function showMore(id) {
    const nid=extractNumbers(id)
    packet_data = sipDictData[nid].packet
    const rawPacket = sipDictData[nid].packet;
    const formatted = formatSipPacket(rawPacket);
    pktContent = `<pre style="white-space: pre-wrap; font-family: monospace;">${formatted}</pre>`;
    document.getElementById("popup-content").innerHTML = pktContent;
    document.getElementById("popup-modal").style.display = "block";
    collapseSipLayers();
}

function closePopup() {
    document.getElementById("popup-modal").style.display = "none";
}


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




// ************* different color according to call_id

function generateColorClass(index, callIdClassMap) {
    const hue = (index * 137.508) % 360; 
    const color = `hsl(${hue}, 70%, 60%)`;
    const className = `kcid${index}`;

    // Inject dynamic style if not already added
    if (!callIdClassMap[className]) {
        const style = document.createElement("style");
        style.innerHTML = `.${className} line{stroke: ${color};}`;
        document.head.appendChild(style);
        callIdClassMap[className] = true; // Mark as injected
    }

    return className;
}

function colorForEachCallId() {
    const signalElements = document.querySelectorAll(".signal");
    const callIdToClass = {};
    const injectedStyles = {};
    let currIndex = 1;
    signalElements.forEach(element => {
        const id = element.id;
        const nid = extractNumbers(id);
        const pkt = sipDictData[nid];
        const callId = pkt["sip.Call-ID"];        

        if (!(callId in callIdToClass)) {
            callIdToClass[callId] = generateColorClass(currIndex, injectedStyles);
            currIndex++;
        }

        const className = callIdToClass[callId];
        element.classList.add(className);
    });
}




function fetchMediaInfo(){
    let signalElements = document.querySelectorAll(".signal");
    let currIndx = 0;
    let callIdClass = {};
    let kClass = ["kcid1", "kcid2", "kcid3", "kcid4", "kcid5"];
    

    signalElements.forEach(element => {
        // Get the ID of the current element
        let id = element.id;
        nid=extractNumbers(id)
        let pktContent=sipDictData[nid];
        // console.log(pktContent)
        if (pktContent && pktContent.includes("Media Description, name and address (m):")) {
            let mediaLine = pktContent.match(/Media Description, name and address \(m\):(.+)/)[1];
            mediaLine = mediaLine.replace(/\x1b\[[0-9;]*m/g, '');
            let maxLen = 28
            if (mediaLine.length > maxLen){
                mediaLine = mediaLine.substring(0, maxLen) + "..."
            }
            let txtLenPx = mediaLine.length * 5

            // console.log("Media Line for", id + ":", mediaLine);
            let textElement = document.createElementNS("http://www.w3.org/2000/svg", "text");

            let referenceLine = element.querySelector("line");
            // Set attributes for the text element
            let refX1 = parseFloat(referenceLine.getAttribute("x1"));
            let refX2 = parseFloat(referenceLine.getAttribute("x2"));
            let refY = parseFloat(referenceLine.getAttribute("y1"));
            let refX = Math.floor(((refX2 - refX1) - txtLenPx)/2)
            // console.log(refX)
            let newX = refX1 + refX
            let newY = refY + 10

            textElement.setAttribute("x", newX);
            textElement.setAttribute("y", newY);
            textElement.setAttribute("style", "font-size: 10px; font-family: 'Andale Mono', monospace;")
            textElement.setAttribute("fill", "black");
            textElement.textContent = mediaLine;

            element.appendChild(textElement);
        };

        // class based on call-id

        if (pktContent && pktContent.includes("Call-ID:")) {
            let callId = pktContent.match(/Call-ID:(.+)/)[1];
            callId = callId.replace(/\x1b\[[0-9;]*m/g, '');
            callId = callId.trim()
            
            if (!(callId in callIdClass)){
                callIdClass[callId] = kClass[currIndx];
                currIndx = (currIndx + 1) % kClass.length;
            };
            element.classList.add(callIdClass[callId])
        };
    });

};

// Move participant actor left or right

function participantsArrows() {
    let actorElements = document.querySelectorAll(".actor");
    let rectIndx = 0;
    let rectClasses = ['#E6B0AA', '#A9CCE3','#D7BDE2', '#F9E79F', '#A9DFBF', '#F5CBA7']
    actorElements.forEach(element => {
        const leftArrow = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
        const rightArrow = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
        let refRect = element.querySelector("rect");
        let refX = parseFloat(refRect.getAttribute('x'));
        let refY = parseFloat(refRect.getAttribute('y'));
        let refRX = parseFloat(refRect.getAttribute('width')) + refX

        // Define the points for the left-pointing arrow
        let leftP = `${refX-8},${refY + 17} ${refX+4},${refY+5} ${refX+4},${refY+29}`;
        let rightP = `${refRX-4},${refY+5} ${refRX-4},${refY + 29} ${refRX+8},${refY+17}`;

        leftArrow.setAttribute('class', 'k-left-arrow');
        leftArrow.setAttribute('points', leftP);
        leftArrow.setAttribute('fill', '#aaa');
        leftArrow.setAttribute('style', 'cursor: pointer;');
        leftArrow.setAttribute('onclick', 'moveActor(this, -1)')

        rightArrow.setAttribute('class', 'k-right-arrow');
        rightArrow.setAttribute('points', rightP);
        rightArrow.setAttribute('fill', '#aaa');
        rightArrow.setAttribute('style', 'cursor: pointer;');
        rightArrow.setAttribute('onclick', 'moveActor(this, 1)');

        element.appendChild(leftArrow);
        element.appendChild(rightArrow);

        // add participants in array
        let textActor = element.querySelector("text");
        let actor = textActor.textContent.trim();
        if (!participants.includes(actor)) {
            participants.push(actor);
        }

        let kIndx
        if(k==0){            
            kIndx = participants.indexOf(actor);
        }
        else{kIndx = participants_orig.indexOf(actor);}

        kIndx = (kIndx) % rectClasses.length;
        element.querySelector('rect').setAttribute('fill', rectClasses[kIndx]);

    });
    
    // console.log(k)
    if(k==0){
        participants_orig=[...participants];
        // console.log(participants_orig)
        k+=1;
    };

    return participants;
};

function moveActor(polygon, direction){
    let pElm=polygon.parentElement;
    let tElm=pElm.querySelector("text");
    party=tElm.textContent.trim();
    let index = participants.indexOf(party);
    if (index !== -1) {
        let newIndex = index + direction;
        if (newIndex >= 0 && newIndex < participants.length) {
            // Swap the elements
            [participants[index], participants[newIndex]] = [participants[newIndex], participants[index]];
        } else {
            console.log("Cannot move the name further in this direction.");
        }
    } else {
        console.log("Name not found.", party);
    }

    let actors = participants.map(actor => `participant "${actor}"`);
    umlDataNew = actors.join('\n') + '\n' + umlData;
    // console.log(umlDataNew)

    document.getElementById('diagram').innerHTML = '';
    kpacketId = 0 //initialise again for reloading diagram with proper nid
    diagram = Diagram.parse(umlDataNew);
    diagram.drawSVG('diagram', {theme: 'simple'});

    // fetchMediaInfo();
    colorForEachCallId();
    participants = participantsArrows();

};


