-- websocket: websocket message handler for lua-server-lplp

if not websocket then websocket = {} end

count = 1

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

websocket.split_char_to_four_bits = function(char)

    char = string.byte(char)

    local b1 = (char & 0xF0) >> 4
    local b2 = char & 0xF

    return b1, b2

end

websocket.split_four_bits_to_bits = function(byte)
    local bits = {}

    -- force convert to number
    local byte = string.byte(byte)

    bits[1] = (byte & 8) >> 3
    bits[2] = (byte & 4) >> 2
    bits[3] = (byte & 2) >> 1
    bits[4] = (byte & 1)

    return bits
end

websocket.join_four_bits_to_char = function(b1, b2)

    return string.char((b1 << 4) | b2)

end

websocket.join_four_bits = function(b1, b2, b3, b4)

    return (b1 << 3) | (b2 << 2) | (b3 << 1) | b4

end

websocket.bytes_to_chars = function(bs)

    local reversed_chars = {}

    while bs ~= 0 do
        table.insert(reversed_chars, string.char(bs & 0xFF))
        bs = bs >> 8
    end

    local chars = {}

    for i = #reversed_chars, 1, -1 do
        table.insert(chars, reversed_chars[i])
    end

    return table.concat(chars)

end

websocket.chars_to_bytes = function(cs)

    local bytes = 0

    for i=1, string.len(cs), 1 do
        bytes = (bytes << 8) | string.byte(cs,i,i)
    end
    
    return bytes

end

-- take an incoming message and respond to any appropriate client
websocket.incoming = function(socket)

    local incoming, err = websocket.read_message(socket)
    if not incoming or err then return websocket.fail_connection(err) end

    if not (incoming.fin == 1 and incoming.opcode ~= 0) then
        incoming = websocket.handle_fragment(incoming, socket)
        if not incoming then return nil end
    end

    local outgoing, err = websocket.generate_response(incoming)
    if err then return websocket.fail_connection(err) end

    return outgoing

end

-- reads a message fully including the unmasked payload
websocket.read_message = function(socket)

    local raw_message, err = websocket.read_message_from_socket(socket)
    if not raw_message or err then return nil, err end

    local valid, err = websocket.validate_message(raw_message)
    if not valid then return nil, err end

    if raw_message.payload_data then
        raw_message.unmasked_payload_data = websocket.unmask_payload_data(raw_message.payload_data, raw_message.masking_key)
        raw_message.payload_data = nil
    end

    return raw_message

end

-- reads a message to a mostly-raw format with minimum validation
websocket.read_message_from_socket = function(socket)

    local err = nil

    local raw_fin_rsv, raw_opcode
    local raw_fin_rsv_opcode, err = socket:receive(1)
    -- TODO: tjs is fucked
    if err then return print(err)
    else raw_fin_rsv, raw_opcode = websocket.split_char_to_four_bits(raw_fin_rsv_opcode) end

    local fin_rsv = websocket.parse_fin_rsv_from_raw(raw_fin_rsv)
    local opcode = websocket.parse_opcode_from_raw(raw_opcode)

    local masked_payload_length = websocket.parse_masked_payload_length_from_raw(socket:receive(1))

    if masked_payload_length.payload_length == 126 then
        masked_payload_length.payload_length = websocket.read_u16_from_socket(socket)
    elseif masked_payload_length.payload_length == 127 then
        masked_payload_length.payload_length = websocket.read_u64_from_socket(socket)
        if masked_payload_length.payload_length > 9223372036854775807 then return err, "[?] WRN in websocket.read_message_from_socket: received length too long" end
    end

    local masking_key = socket:receive(4)
    local payload_data
    if masked_payload_length.payload_length > 0 then
        payload_data, err = socket:receive(masked_payload_length.payload_length)
    end

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



websocket.parse_fin_rsv_from_raw = function(raw_fin_rsv)

    local bits = websocket.split_four_bits_to_bits(raw_fin_rsv)
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

websocket.parse_opcode_to_raw = function(opcode)

    local OPCODES <const> = {
        ["FRAME_CONTINUATION"] = 0,
        ["TEXT_FRAME"] = 1,
        ["BINARY_FRAME"] = 2,
        ["CONNECTION_CLOSE"] = 8,
        ["PING"] = 9,
        ["PONG"] = 10
    }

    if OPCODES[opcode] ~= nil then return OPCODES[opcode]
    else return nil, "[?] WRN in websocket.parse_opcode_to_raw: did not recognise opcode " .. opcode end

end

websocket.parse_masked_payload_length_from_raw = function(raw_masked_payload_length)

    raw_masked_payload_length = string.byte(raw_masked_payload_length)

    return {
        ["masked"] = raw_masked_payload_length & 128 >> 7,
        ["payload_length"] = raw_masked_payload_length & 127
    }

end

websocket.read_u16_from_socket = function(socket)

    return websocket.chars_to_bytes(socket:receive(2))

end

websocket.read_u64_from_socket = function(socket)

    return websocket.chars_to_bytes(socket:receive(8))

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

    for i = 1, string.len(payload_data) do

        local index = i % 4
        if index == 0 then index = 4 end

        local c = string.byte(payload_data, i, i)
        local m = string.byte(masking_key, index, index)
        table.insert(transformed_octets, string.char(c ~ m))

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
        ["TEXT_FRAME"] = websocket_backend.handle_text,
        ["BINARY_FRAME"] = websocket_backend.handle_binary,
        ["CONNECTION_CLOSE"] = websocket.handle_close,
        ["PING"] = websocket.handle_ping,
        ["PONG"] = websocket.handle_pong,
    }

    local response = OPCODE_FUNCTIONS[incoming.opcode](incoming)
    response.response = websocket.serialize_message(response.response)
    
    return response

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
    response.unmasked_payload_data = backend_response.unmasked_payload_data
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
    response.unmasked_payload_data = backend_response.unmasked_payload_data
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

    local error_string, status_code
    if err then
        error_string = err.error
        status_code = err.status_code
    else
        error_string = "[!] ERR: unknown error"
        -- TODO: checkl this
        status_code = 1000
    end

    print("[?] failing ws connection: " .. error_string)

    local response = websocket.MESSAGE_TEMPLATE
    response.opcode = "CONNECTION_CLOSE"
    response.payload_data = status_code .. error_string

    return { ["response"] = websocket.serialize_message(response), ["flood"] = false, ["close"] = true }

end

websocket.serialize_message = function(msg)

    local response = {}

    local fin_rsv = websocket.join_four_bits(1, msg.rsv1, msg.rsv2, msg.rsv3)
    local opcode, err = websocket.parse_opcode_to_raw(msg.opcode)
    if err then return nil, err end

    table.insert(response, websocket.join_four_bits_to_char(fin_rsv, opcode))

    local payload_length
    if msg.unmasked_payload_data ~= nil then payload_length = string.len(msg.unmasked_payload_data)
    else payload_length = 0 end

    local masked_payload, err = websocket.serialize_masked_payload_length(payload_length)
    if err then return nil, err end

    table.insert(response, masked_payload)
    table.insert(response, msg.unmasked_payload_data)

    return table.concat(response)
    
end

websocket.serialize_masked_payload_length = function(payload_length)

    local SIXTEEN_BIT_MAX_VALUE <const> = 65535
    local SIXTY_FOUR_BIT_MAX_VALUE <const> = 18446744073709551615
    local SIXTEEN_BIT_BASE <const> = (126 & 0x7F) << 16
    local SIXTY_FOUR_BIT_BASE <const> = (127 & 0x7F) << 64
    local serialized

    if payload_length <= 125 then

        serialized = payload_length & 0x7F

    elseif payload_length <= SIXTEEN_BIT_MAX_VALUE then

        serialized = SIXTEEN_BIT_BASE | (payload_length & 0xFFFF)

    elseif payload_length <= SIXTY_FOUR_BIT_MAX_VALUE then

        serialized = SIXTY_FOUR_BIT_BASE | (payload_length & 0xFFFFFFFFFFFFFFFF)

    else return nil, "[?] WRN in websocket.serialize_masked_payload_length: length too long" end

    return websocket.bytes_to_chars(serialized)

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

require "websocket_backend"

-- local successes, failures = 0, 0

-- for n, test in pairs(tests) do
--     io.write(n .. "... ")
--     if not test() then
--         io.write("FAILED.\n")
--         failures = failures + 1
--     else
--         io.write("passed.\n")
--         successes = successes + 1
--     end
-- end

-- print("")
-- print(successes .. " passed. " .. failures .. " failed.")