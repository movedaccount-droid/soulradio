alert("test");

let ws = new WebSocket("ws://localhost:8080/testingurlresponse")
let dirpath = "/"

ws.onmessage = GSFReceive

function sendMessage(msg){
    // Wait until the state of the socket is not ready and send the message when it is...
    waitForSocketConnection(ws, function(){
        ws.send(msg);
    });
}

// Make the function wait until the connection is made...
function waitForSocketConnection(socket, callback){
    setTimeout(
        function () {
            if (socket.readyState === 1) {
                console.log("Connection is made")
                if (callback != null){
                    callback();
                }
            } else {
                console.log("wait for connection...")
                waitForSocketConnection(socket, callback);
            }

        }, 5); // wait 5 milisecond for the connection...
}

function GSFReceive(event) {

    const lines = event.data.split("\r\n")
    let index = 0
    let type, area

    while (index < lines.length) {
        [type, area, index] = ExtractArea(lines, index)
        switch(type) {
            case "CHAT":
                GSFReceiveChatMessage(area);
                break;
            case "DIR":
                GSFReceiveDirUpdate(area);
                break;
        }
    }

}

function GSFReceiveChatMessage(messages) {

    for (let message of messages) {
        const chat_element = document.createElement("p");
        chat_element.innerText = message;
        chat_element.classList.add("chat-message");
        document.getElementById("chat").appendChild(chat_element);
    }

}

// TODO: check what kindof file was sent serverside
function GSFReceiveDirUpdate(files) {

    document.getElementById("file-explorer").innerHTML = '';
    console.log(files)
    dirpath += files.pop()

    for (let file of files) {
        console.log(file);
        const file_element = document.createElement("button");
        file_element.innerText = file;
        file_element.classList.add("file-button");
        const file_destination = dirpath + file
        file_element.onclick = function() { GSFSendDirUpdate(file_destination) }
        document.getElementById("file-explorer").appendChild(file_element);
    }
}

function GSFSendChatMessage() {
    sendMessage(GenerateArea("CHAT", document.getElementById("chat-textarea").value));
    document.getElementById("chat-textarea").value = "";
}

function GSFSendDirUpdate(file) {
    sendMessage(GenerateArea("DIR", file));
}

function GenerateArea(type, datas) {
    if (Array.isArray(datas)) { datas = datas.join("\r\n") }
    if (datas != null) { datas = datas + "\r\n" }
    return type + "\r\n" + datas + "END"
}

function ExtractArea(lines, index) {

    const type = lines[index]
    let area = []

    while (lines[++index] != "END") {
        area.push(lines[index])
    }

    return [type, area, ++index]

}