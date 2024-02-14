websocket_backend = {}

websocket_backend.handle_text = function(message)

    local response = {
        ["opcode"] = "TEXT_FRAME",
        ["rsv1"] = message.rsv1,
        ["rsv2"] = message.rsv2,
        ["rsv3"] = message.rsv3,
        ["unmasked_payload_data"] = message.unmasked_payload_data
    }

    return { ["response"] = response, ["flood"] = false, ["close"] = false }

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