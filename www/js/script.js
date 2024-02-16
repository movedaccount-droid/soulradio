let ws = new WebSocket("ws://10.0.0.33:8080/testingurlresponse")
let dirpath = "/"
let nick = "guest" + (Math.floor(Math.random() * 9999) + 1)

ws.onmessage = GSFReceive

// these two functions are modified from stackoverflow,
// but i don't have the link to source it..
function SendMessage(msg) {
    WaitForSocketConnection(ws, function(){
        ws.send(msg);
    }, 1);
}

function WaitForSocketConnection(socket, callback, i) {
    // break if we have been waiting too long
    if (i > 250) {
        return;
    }
    setTimeout(
        function () {
            console.log("hitting")
            if (socket.readyState === 1) {
                if (callback != null){
                    callback();
                }
            } else {
                WaitForSocketConnection(socket, callback, i++);
            }
        }, i
    )
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
            case "QUEUE":
                GSFReceiveQueueUpdate(area);
                break;
            case "NOW_PLAYING":
                GSFReceiveNowPlayingUpdate(area);
                break;
        }
    }

}

function GSFReceiveChatMessage(messages) {

    for (let message of messages) {
        AppendChatMessage(message, "chat-message")
    }

}

function GSFReceiveDirUpdate(files) {

    document.getElementById("file-explorer").innerHTML = '';
    dirpath = files.pop()

    const up_destination = PopLastSlash(dirpath).dir
    if (up_destination != null) {
        const up_element = document.createElement("button");
        up_element.innerText = "../"
        up_element.classList.add("file-button");
        up_element.onclick = function() { GSFSendDirUpdate(up_destination) }
        document.getElementById("file-explorer").appendChild(up_element);
    }


    for (let file of files) {
        const file_element = document.createElement("button");
        file_element.innerText = file;
        file_element.classList.add("file-button");
        const file_destination = dirpath + file
        file_element.onclick = function() { GSFSendDirUpdate(file_destination) }
        document.getElementById("file-explorer").appendChild(file_element);
    }
}

function GSFReceiveQueueUpdate(queue) {

    document.getElementById("queue").innerHTML = '';

    queue.forEach(function(track, i) {
        const queue_element = document.createElement("button");
        queue_element.innerText = (i + 1) + " | " + PopLastSlash(track).file;
        queue_element.classList.add("queue-button");
        const track_destination = track
        queue_element.onclick = function() { GSFSendQueueRemove(track_destination) }
        document.getElementById("queue").appendChild(queue_element);
    });

}

function GSFReceiveNowPlayingUpdate(track) {

    document.getElementById("now-playing").innerHTML = '';
    track = track.pop()
    
    const np_element = document.createElement("p");
    np_element.innerText = "now playing: " + track;
    np_element.classList.add("now-playing-text");
    document.getElementById("now-playing").appendChild(np_element);

}

function GSFSendChatMessage() {
    const message = document.getElementById("chat-textarea").value

    const NICK_COMMAND = /\/nick ([\w ]+)/
    const match = message.match(NICK_COMMAND)
    if (match != null && match[1] != null) {
        nick = match[1]
        AppendChatMessage("changed nickname to \"" + nick + "\"", "info-message")
    } else {
        SendMessage(GenerateArea("CHAT", nick + ": " + message));
    }
    document.getElementById("chat-textarea").value = "";
}

function GSFSendDirUpdate(file) {
    SendMessage(GenerateArea("DIR", file));
}

function GSFSendQueueRemove(file) {
    SendMessage(GenerateArea("REMOVE", file));
}

function GSFSendSkip() {
    SendMessage(GenerateArea("SKIP"));
}

function GSFSendNowPlayingRequest() {
    SendMessage(GenerateArea("NOW_PLAYING"));
}

function GSFSendInitMessage() {
    SendMessage(GenerateArea("INIT"));
}

function GenerateArea(type, datas) {
    if (Array.isArray(datas)) { datas = datas.join("\r\n") }
    if (typeof datas === 'undefined') { return type + "\r\nEND" }
    return type + "\r\n" + datas + "\r\nEND"
}

function ExtractArea(lines, index) {

    const type = lines[index]
    let area = []

    while (lines[++index] != "END") {
        area.push(lines[index])
    }

    return [type, area.reverse(), ++index]

}

function PopLastSlash(path) {

    const POP_LAST_SLASH = /(.*\/)([^/]+?\/?)$/
    let match = path.match(POP_LAST_SLASH)

    let dir, file
    if (match != null && match[1] != null) {
        dir = match[1]
    }

    if (match != null && match[2] != null){
        file = match[2]
    }

    return { dir, file }

}

function AppendChatMessage(message, html_class) {
    const chat_element = document.createElement("p");
    chat_element.innerText = message;
    chat_element.classList.add(html_class);
    document.getElementById("chat").appendChild(chat_element);
}

GSFSendInitMessage()
setInterval(GSFSendNowPlayingRequest, 5000);