if not websocket_backend then websocket_backend = {} end

local socket = require("socket")

websocket_backend.queue = {}
websocket_backend.now_playing = "./www/img/audio.ogg"

websocket_backend.handle_text = function(message)

    local request = { ["lines"] = {}, ["index"] = 1 }
    local MATCH_BETWEEN_NEWLINES <const> = "[^\r\n]+"
    for line in string.gmatch(message.unmasked_payload_data, MATCH_BETWEEN_NEWLINES) do
        table.insert(request.lines, line)
    end

    local AREAS <const> = {
        ["CHAT"] = websocket_backend.handle_chat,
        ["DIR"] = websocket_backend.handle_dir,
        ["REMOVE"] = websocket_backend.handle_remove,
        ["SKIP"] = websocket_backend.handle_skip,
        ["NOW_PLAYING"] = websocket_backend.handle_now_playing,
        ["INIT"] = websocket_backend.handle_init
    }

    local response_payload = {}
    local response_area, should_flood
    local any_should_flood = false

    while request.index < #request.lines do
        print("wsrequest", request.lines[request.index])
        request, response_area, should_flood = AREAS[request.lines[request.index]](request)
        if should_flood then any_should_flood = true end
        if response_area then table.insert(response_payload, response_area) end
    end

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

websocket_backend.handle_dir = function(request)

    request.index = request.index + 1
    local requested_dir = request.lines[request.index]

    local CONTAINS_TRAVERSAL <const> = "%.%."
    if string.find(requested_dir, CONTAINS_TRAVERSAL) then return websocket_backend.skip_to_end(request), nil, false end

    local file = websocket_backend.pop_on_final_slash(requested_dir, requested_dir)

    local IS_FILE <const> = "%."
    if string.find(file, IS_FILE) then

        table.insert(websocket_backend.queue, requested_dir)
        return websocket_backend.skip_to_end(request), websocket_backend.generate_queue_area(), true

    else

        return websocket_backend.skip_to_end(request), websocket_backend.generate_dir_area(requested_dir), false
        
    end
        
end

websocket_backend.handle_now_playing = function(request)

    return websocket_backend.skip_to_end(request), websocket_backend.generate_now_playing_area(), false

end

websocket_backend.handle_init = function(request)

    local response_areas = {}

    table.insert(response_areas, websocket_backend.generate_dir_area("/"));
    table.insert(response_areas, websocket_backend.generate_queue_area());
    table.insert(response_areas, websocket_backend.generate_now_playing_area());

    return websocket_backend.skip_to_end(request), table.concat(response_areas, "\r\n"), false

end

websocket_backend.pop_on_final_slash = function(path, default)

    local POP_ON_FINAL_SLASH <const> = "/([^/]-)$"
    local file = string.match(path, POP_ON_FINAL_SLASH)
    if not file then file = default end

    return file

end

websocket_backend.generate_queue_area = function()

    local response_area = { "QUEUE", "END" }

    local buffered = websocket_backend.track_or_default(websocket_backend.buffered)
    if buffered ~= websocket_backend.config.default_track then
        table.insert(response_area, 2, buffered)
    end
    for _, v in ipairs(websocket_backend.queue) do
        table.insert(response_area, 2, v)
    end

    return table.concat(response_area, "\r\n")

end

websocket_backend.generate_dir_area = function(dir)

    local response_area = { "DIR", dir, "END" }

    local dir_contents = io.popen("ls -p " .. websocket_backend.config.music_dir .. dir):lines()
    for dir in dir_contents do
        table.insert(response_area, 3, dir)
    end

    return table.concat(response_area, "\r\n")

end

websocket_backend.generate_now_playing_area = function()

    local now_playing = websocket_backend.track_or_default(websocket_backend.now_playing)

    now_playing = websocket_backend.pop_on_final_slash(now_playing, now_playing)

    return "NOW_PLAYING\r\n" .. now_playing .. "\r\nEND"

end

websocket_backend.handle_remove = function(request)

    request.index = request.index + 1
    local removed_track = request.lines[request.index]

    for i, v in ipairs(websocket_backend.queue) do
        if v == removed_track then
            table.remove(websocket_backend.queue, i)
        end
    end

    return websocket_backend.skip_to_end(request), websocket_backend.generate_queue_area(), true

end

websocket_backend.handle_skip = function(request)

    local err = liquidsoap.skip()
    if err then print(err) end

    -- this is hacky. liquidsoap will take time to request the next track and
    -- update our internal queues, so we have to emulate as if they already changed.

    local track
    local queue = {}
    local index

    if websocket_backend.track_or_default(websocket_backend.buffered) == websocket_backend.config.default_track then
        track = websocket_backend.queue[1]
        index = 2
    else
        track = websocket_backend.buffered
        index = 1
    end

    track = websocket_backend.pop_on_final_slash(websocket_backend.track_or_default(track))
    for i=index,#websocket_backend.queue do
        table.insert(queue, 1, websocket_backend.queue[i])
    end

    local response_area = { "NOW_PLAYING", track, "END", "QUEUE", "END"}
    if #queue > 0 then
        table.insert(response_area, 5, table.concat(queue, "\r\n"))
    end
    
    return websocket_backend.skip_to_end(request), table.concat(response_area, "\r\n"), true

end

websocket_backend.goto_next_track = function()

    -- liquidsoap buffers one track, so we keep track of it
    websocket_backend.now_playing = websocket_backend.buffered
    websocket_backend.buffered = table.remove(websocket_backend.queue, 1)

end

websocket_backend.track_or_default = function(track)

    if track ~= nil then
        return websocket_backend.config.music_dir .. track
    else
        return websocket_backend.config.default_track
    end

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