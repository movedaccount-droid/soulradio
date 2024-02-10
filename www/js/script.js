alert("test");

let socket = new WebSocket("ws://10.0.0.33:8080/testingurlresponse")

socket.onmessage = function(event) {
    alert("message: " + event.data)
}

socket.send("fdsjuifdsaiu")