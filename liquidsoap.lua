if not liquidsoap then liquidsoap = {} end

local socket = require("socket")

function liquidsoap.incoming(client)

    client:receive('*l')
    websocket_backend.goto_next_track()
    return { ["response"] = websocket_backend.track_or_default(websocket_backend.buffered), ["flood"] = false, ["close"] = true }

end

function liquidsoap.skip()

    local client, err = socket.connect("localhost", liquidsoap.config.liquidsoap_telnet_port)
    if err then
        return "[?] WRN in liquidsoap.skip: couldn't open client: " .. err
    end

    -- skip twice if liquidsoap has buffered the default track already
    if websocket_backend.track_or_default(websocket_backend.buffered) == websocket_backend.config.default_track
    and websocket_backend.track_or_default(websocket_backend.queue[1]) ~= websocket_backend.config.default_track then
        client:send(liquidsoap.config.flush_command .. "\r\n")
    else
        client:send(liquidsoap.config.skip_command .. "\r\n")
    end

    client:close()

end

-- start server
local _, err = server.open_server("0.0.0.0", liquidsoap.config.port, "liquidsoap")
assert(not err, "[!] ERR in liquidsoap init sequence: could not open server: " .. tostring(err))