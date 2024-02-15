if not websocket_backend then websocket_backend = {} end

local socket = require("socket")

websocket_backend.queue = {}
websocket_backend.now_playing = "./www/img/audio.ogg"

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
        table.insert(response_area, 2, request.lines[request.index])
        request.index = request.index + 1
    end

    return request, table.concat(response_area, "\r\n"), true

end

websocket_backend.next_track = function()

    websocket_backend.now_playing = table.remove(websocket_backend.queue, 1)
    
    if websocket_backend.now_playing ~= nil then
        return websocket_backend.now_playing
    else
        return "./www/img/audio.ogg"
    end

end

websocket_backend.handle_now_playing = function(request)

    request = websocket_backend.skip_to_end(request)

    return request, "CHAT\r\n" .. websocket.now_playing .. "\r\nEND", false

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