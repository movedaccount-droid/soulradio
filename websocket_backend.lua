websocket_backend = {}

local socket = require("socket")

websocket_backend.handle_text = function(message)

    local request = { ["lines"] = {}, ["index"] = 0 }
    local MATCH_BETWEEN_NEWLINES <const> = "[^\r\n]+"
    for line in string.gmatch(message.unmasked_payload_data, MATCH_BETWEEN_NEWLINES) do
        table.insert(request.lines, line)
    end

    local AREAS = {
        ["CHAT"] = websocket_backend.handle_chat(request),
        ["NOW_PLAYING"] = websocket_backend.handle_now_playing(request)
    }

    local response_payload = {}
    local response_area, should_flood
    local any_should_flood = false

    while request.index < #request.lines do
        request, response_area, should_flood = AREAS[request.lines[request.index]](request)
        if should_flood then any_should_flood = true end
        table.insert(response_payload, response_area)
    end

    local should_flood

    local response = {
        ["opcode"] = "TEXT_FRAME",
        ["rsv1"] = message.rsv1,
        ["rsv2"] = message.rsv2,
        ["rsv3"] = message.rsv3,
        ["unmasked_payload_data"] =  table.concat(response_payload, "\r\n")
    }

    return { ["response"] = response, ["flood"] = any_should_flood, ["close"] = false }

end

websocket_backend.is_end = function(request)
    return not (request.lines[request.index] ~= nil and request.lines[request.index] ~= "END")
end

websocket_backend.skip_to_end = function(request)
    while not websocket_backend.is_end(request) do
        request.index = request.index + 1
    end
    return request
end

websocket_backend.handle_chat = function(request)

    local response_area = { "CHAT", "END" }
    request.index = request.index + 1

    while not websocket_backend.is_end(request) do
        table.insert(response_area, request.lines[request.index], 2)
        request.index = request.index + 1
    end

    return request, table.concat(response_area, "\r\n"), true

end

websocket_backend.handle_now_playing = function(request)

    request = websocket_backend.skip_to_end(request)

    local np_file = io.open("./now_playing.txt", "r")
    local np = np_file:read("a")
    np_file:close()

    return request, "CHAT\r\n" .. np .. "\r\nEND", false

end

websocket_backend.handle_binary = function(message)

    local response = {
        ["opcode"] = "BINARY_FRAME",
        ["rsv1"] = message.rsv1,
        ["rsv2"] = message.rsv2,
        ["rsv3"] = message.rsv3,
        ["unmasked_payload_data"] = message.unmasked_payload_data
    }

    return { ["response"] = response, ["flood"] = false, ["close"] = false }

end

local port = 8081
print("[.] opening liquidsoap telnet server on port " .. port)
local err
websocket_backend.socket, err = socket.bind("0.0.0.0", port)
assert(websocket_backend.socket, "[!] ERR in websocket_backend init: could not open telnet server: " .. tostring(err))
websocket_backend.client, err = websocket_backend.socket:connect("0.0.0.0", 1234)
assert(websocket_backend.client, "[!] ERR in websocket_backend init: could not open telnet client: " .. tostring(err))