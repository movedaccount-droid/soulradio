websocket_backend = {}

websocket_backend.handle_text = function(message)

    local response = {
        ["rsv1"] = message.rsv1,
        ["rsv2"] = message.rsv2,
        ["rsv3"] = message.rsv3,
        ["payload_data"] = message.payload_data
    }

    return response

end