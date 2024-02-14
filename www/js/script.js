alert("test");

let ws = new WebSocket("ws://10.0.0.33:8080/testingurlresponse")

ws.onmessage = function(event) {
    alert("message: " + event.data)
}

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

sendMessage("")