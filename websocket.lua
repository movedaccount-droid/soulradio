-- websocket: websocket message handler for lua-server-lplp
require "websocket_backend"

websocket = {}

websocket.buffers = {}

websocket.MESSAGE_TEMPLATE = {
    ["fin"] = 1,
    ["rsv1"] = 0,
    ["rsv2"] = 0,
    ["rsv3"] = 0,
    ["opcode"] = nil,
    ["masked"] = 0,
    ["payload_length"] = nil,
    ["payload_data"] = nil
}

websocket.split_char_to_bytes = function(char)
    local bytes = {}

    bytes[1] = (char & 240) >> 4
    bytes[2] = (char & 15) >> 4

    return bytes
end

websocket.split_byte_to_bits = function(byte)
    local bits = {}

    bits[1] = (byte & 8) >> 3
    bits[2] = (byte & 4) >> 2
    bits[3] = (byte & 2) >> 1
    bits[4] = (byte & 1)

    return bits
end

-- take an incoming message and respond to any appropriate client
websocket.incoming = function(socket)

    local incoming, err = websocket.read_message(socket)

    if not (incoming.fin == 1 and incoming.opcode ~= 0) then incoming = websocket.handle_fragment(incoming, socket) end

    local outgoing, err = websocket.generate_response(incoming)
    
    if err then outgoing = websocket.fail_connection(err) end

    return outgoing

end

-- reads a message fully including the unmasked payload
websocket.read_message = function(socket)

    local raw_message, err = websocket.read_message_from_socket(socket)
    if err then return nil, err end

    local valid, err = websocket.validate_message(raw_message)
    if not valid then return nil, err end

    raw_message.unmasked_payload_data = websocket.unmask_payload_data(raw_message.payload_data, raw_message.masking_key)
    raw_message.payload_data = nil

    return raw_message

end

-- reads a message to a mostly-raw format with minimum validation
websocket.read_message_from_socket = function(socket)

    local err = nil

    local fin_rsv = websocket.parse_fin_rsv_from_raw(socket:receive(1))
    local opcode = websocket.parse_opcode_from_raw(socket:receive(1))

    local masked_payload_length = websocket.parse_masked_payload_length_from_raw(socket:receive(2))

    if masked_payload_length.payload_length >= 126 then

        local raw_extra_payload_length = websocket.read_extra_payload_length_from_socket(socket, masked_payload_length.payload_length)
        masked_payload_length.payload_length, err = websocket.parse_extra_payload_length_from_raw(raw_extra_payload_length)

    end

    local masking_key = socket:receive(8)
    local payload_data = socket:receive(masked_payload_length.payload_length)

    if err then return nil, err end

    return {
        ["fin"] = fin_rsv.fin,
        ["rsv1"] = fin_rsv.rsv1,
        ["rsv2"] = fin_rsv.rsv2,
        ["rsv3"] = fin_rsv.rsv3,
        ["opcode"] = opcode,
        ["masked"] = masked_payload_length.masked,
        ["payload_length"] = masked_payload_length.payload_length,
        ["masking_key"] = masking_key,
        ["payload_data"] = payload_data
    }
end

websocket.read_extra_payload_length_from_socket = function(socket, length)
    -- TODO: check status_code
    if length > 127 then return nil, { ["error"] = "[!] ERR: length was above normal limits", ["status_code"] = 1002 }
    elseif length == 127 then return socket:receive(16)
    elseif length == 126 then return socket:receive(4)
    else return nil end
end

websocket.parse_fin_rsv_from_raw = function(raw_fin_rsv)

    local bits = websocket.split_byte_to_bits(raw_fin_rsv)
    return {
        ["fin"] = bits[1],
        ["rsv1"] = bits[2],
        ["rsv2"] = bits[3],
        ["rsv3"] = bits[4],
    }

end

websocket.parse_opcode_from_raw = function(raw_opcode)

    local OPCODES <const> = {
        [0] = "FRAME_CONTINUATION",
        [1] = "TEXT_FRAME",
        [2] = "BINARY_FRAME",
        [8] = "CONNECTION_CLOSE",
        [9] = "PING",
        [10] = "PONG"
    }

    if OPCODES[raw_opcode] ~= nil then return OPCODES[raw_opcode] else return "RESERVED" end

end

websocket.parse_masked_payload_length_from_raw = function(raw_masked_payload_length)

    return {
        ["masked"] = raw_masked_payload_length & 128 >> 7,
        ["payload_length"] = raw_masked_payload_length & 127
    }

end

websocket.parse_extra_payload_length_from_raw = function(raw_extra_payload_length)

    -- only allowed to be up to this value
    if raw_extra_payload_length > 9223372036854775807 then
        return nil, { ["error"] = "[!] ERR: extra payload length had too large value", ["status_code"] = TEMP_CODE }
    else
        return raw_extra_payload_length >> 0
    end

end

websocket.validate_message = function(raw_message)

    -- 5.2: if a non-zero value is received... fail the websocket connection
    if not raw_message.rsv1 == 0 or not raw_message.rsv2 == 0 or not raw_message.rsv2 == 0 then
        return false, { ["error"] = "[!] ERR: rsv values should be 0", ["status_code"] = TEMP_CODE }
    end

    -- 5.2: if an unknown opcode is received... fail the websocket connection
    if raw_message.opcode == "RESERVED" then return false, { ["error"] = "[!] ERR: unrecognized opcode", ["status_code"] = TEMP_CODE } end

    -- 5.3: a masked frame MUST have the field frame-masked set to 1
    if not raw_message.masked then return false, { ["error"] = "[!] ERR: client messages was not marked as masked", ["status_code"] = 1002 } end

    return true

end

websocket.unmask_payload_data = function(payload_data, masking_key)

    local transformed_octets = {}

    for i = 1, payload_data.len() do
        local j = i % 4
        table.insert(transformed_octets, payload_data[i] ~ masking_key[j])
    end

    return table.concat(transformed_octets, "")

end

-- append message to defragmentation buffer for socket, and return message if complete
websocket.handle_fragment = function(incoming, socket)

    if websocket.buffers[socket] == nil then
        incoming.unmasked_payload_data = { incoming.unmasked_payload_data }
        websocket.buffers[socket] = { incoming }
    else
        table.insert(websocket.buffers[socket].unmasked_payload_data, incoming.unmasked_payload_data)
    end

    if incoming.fin == 1 then return websocket.read_fragments(socket) end

    return nil

end

websocket.read_fragments = function(socket)

    local buffered_message = websocket.buffers[socket]
    websocket.buffers[socket] = nil

    -- this is a naive approach that may fail as lua handles our data as a string,
    -- and the data boundary is not necessarily aligned to a UTF-8 character
    -- but that might be fine...
    buffered_message.unmasked_payload_data = table.concat(buffered_message.unmasked_payload_data)

    return buffered_message

end

-- generate response to incoming message, either directly to the sender or flooded to all users
websocket.generate_response = function(incoming)

    local OPCODE_FUNCTIONS <const> = {
        ["TEXT_FRAME"] = websocket_backend.handle_binary,
        ["BINARY_FRAME"] = websocket_backend.handle_text,
        ["CONNECTION_CLOSE"] = websocket.handle_close,
        ["PING"] = websocket.handle_ping,
        ["PONG"] = websocket.handle_pong,
    }

    return OPCODE_FUNCTIONS[incoming.opcode](incoming)

end

websocket.handle_binary = function(incoming)

    local backend_pass = {
        ["rsv1"] = incoming.rsv1,
        ["rsv2"] = incoming.rsv2,
        ["rsv3"] = incoming.rsv3,
        ["payload_data"] = incoming.unmasked_payload_data
    }

    local response = websocket.MESSAGE_TEMPLATE
    local backend_response = websocket_backend.handle_binary(backend_pass)
    response.opcode = "BINARY_FRAME"
    response.rsv1 = backend_response.rsv1
    response.rsv2 = backend_response.rsv2
    response.rsv3 = backend_response.rsv3
    response.payload_data = backend_response.payload_data
    return { ["response"] = response, ["flood"] = false, ["close"] = false }

end

websocket.handle_text = function(incoming)

    local backend_pass = {
        ["rsv1"] = incoming.rsv1,
        ["rsv2"] = incoming.rsv2,
        ["rsv3"] = incoming.rsv3,
        ["payload_data"] = incoming.unmasked_payload_data
    }

    local response = websocket.MESSAGE_TEMPLATE
    local backend_response = websocket_backend.handle_text(backend_pass)
    response.opcode = "TEXT_FRAME"
    response.rsv1 = backend_response.rsv1
    response.rsv2 = backend_response.rsv2
    response.rsv3 = backend_response.rsv3
    response.payload_data = backend_response.payload_data
    return { ["response"] = response, ["flood"] = false, ["close"] = false }

end

websocket.handle_close = function(incoming)

    print("[.] INF: client is closing connection, reason: " .. incoming.unmasked_payload_data)

    local response = websocket.MESSAGE_TEMPLATE
    response.opcode = "CONNECTION_CLOSE"
    response.payload_data = incoming.unmasked_payload_data

    return { ["response"] = response, ["flood"] = false, ["close"] = true }

end

websocket.handle_ping = function(incoming)

    local response = websocket.MESSAGE_TEMPLATE
    response.opcode = "PONG"
    response.payload_data = incoming.unmasked_payload_data

    return { ["response"] = response, ["flood"] = false, ["close"] = false }

end

websocket.handle_pong = function(incoming)

    -- we do nothing :]

end

websocket.fail_connection = function(err)

    print("[!] ERR: closing connection...")

    local response = websocket.MESSAGE_TEMPLATE
    response.opcode = "CONNECTION_CLOSE"
    response.payload_data = err.status_code .. err.error

    return { ["response"] = response, ["flood"] = false, ["close"] = true }

end

tests = {}

tests["parse_fin_rsv_from_raw_1111"] = function()
    local fin_rsv = websocket.parse_fin_rsv_from_raw(16)

    if not fin_rsv.fin == 1
    or not fin_rsv.rsv1 == 1
    or not fin_rsv.rsv2 == 1
    or not fin_rsv.rsv3 == 1
    then return false end

    return true
end

tests["parse_fin_rsv_from_raw_0000"] = function()
    local fin_rsv = websocket.parse_fin_rsv_from_raw(0)

    if not fin_rsv.fin == 0
    or not fin_rsv.rsv1 == 0
    or not fin_rsv.rsv2 == 0
    or not fin_rsv.rsv3 == 0
    then return false end

    return true
end

tests["parse_fin_rsv_from_raw_1001"] = function()
    local fin_rsv = websocket.parse_fin_rsv_from_raw(0)

    if not fin_rsv.fin == 1
    or not fin_rsv.rsv1 == 0
    or not fin_rsv.rsv2 == 0
    or not fin_rsv.rsv3 == 1
    then return false end

    return true
end

local successes, failures = 0, 0

for n, test in pairs(tests) do
    io.write(n .. "... ")
    if not test() then
        io.write("FAILED.\n")
        failures = failures + 1
    else
        io.write("passed.\n")
        successes = successes + 1
    end
end

print("")
print(successes .. " passed. " .. failures .. " failed.")