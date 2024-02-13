alert("test");

let socket = new WebSocket("ws://localhost:8080/testingurlresponse")

socket.onmessage = function(event) {
    alert("message: " + event.data)
}

socket.send("fdsjuifdsaiu")