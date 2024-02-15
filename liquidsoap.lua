if not liquidsoap then liquidsoap = {} end

function liquidsoap.incoming(client)

    client:receive('*l')
    return { ["response"] = websocket_backend.next_track(), ["flood"] = false, ["close"] = true }

end

-- start server
local _, err = server.open_server("0.0.0.0", liquidsoap.config.port, "liquidsoap")
assert(not err, "[!] ERR in liquidsoap init sequence: could not open server: " .. tostring(err))