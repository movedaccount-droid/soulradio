-- runs a suite of tests on the webserver to check bugs and regressions

function build_failure_message(test, response)
    return "FAILED: " .. test .. "\r\nPACKET DUMP:\r\n" .. response
end

function parse_field_line(field_line, table_to_append_to)
    if table_to_append_to == nil then table_to_append_to = {} end
    -- parse a header field line and return values as a table, appending if one is provided
    -- ex. Sec-Fetch-Dest: document
    -- TODO: handle malformed field line with generic error
    -- TODO: A server MUST reject, with a response status code of 400 (Bad Request), any received request message that contains whitespace between a header field name and colon
    -- TODO: reject folded field lines with 400 (5.2)
    local start_index, end_index = string.find(field_line,":%s?")
    local field_name = string.sub(field_line, 1, start_index - 1)
    local field_value = string.sub(field_line, end_index + 1, -1)
    table_to_append_to[field_name] = field_value
    return table_to_append_to
  end

function get_client_response(client)
    -- parse first line
    local line, err = client:receive()
    local tokens = string.gmatch(line,"[^%s]+")
    local protocol_version = tokens()
    local code = tokens()
    local code_name = tokens()

    -- parse headers
    local field_lines = {}
    local field_name, field_value
    local buffer
    while 1 do
      line, err = client:receive()
      if not err then
        if line == "" then
          if buffer ~= nil then
            field_name, field_value = parse_field_line(buffer, field_lines)
            field_lines[field_name] = field_value
          end
          break
        elseif buffer == nil then buffer = line
        elseif line[1] == " " then buffer = buffer .. line
        else
          field_name, field_value = parse_field_line(buffer, field_lines)
          field_lines[field_name] = field_value
          buffer = line
        end
      end
    end

    -- read body from length
    if field_lines["Content-Length"] ~= nil and field_lines["Content-Length"] ~= 0 then
        body = client:receive(field_lines["Content-Length"])
        body = string.gsub(body, "<div>", "\r\n")
    end

    -- create formatted dump for logging
    local output = "\r\nPROTOCOL VERSION: " .. protocol_version .. "\r\nRESPONSE CODE: " .. code .. "\r\nCODE NAME: " .. code_name
    output = output .. "\r\n\r\n--- HEADERS ---"
    for key, value in pairs(field_lines) do
        output = output .. "\r\n" .. key .. ": " .. value
    end
    if body ~= nil then output = output .. "\r\n\r\n--- BODY ---\r\n" .. body end
    
    return { protocol_version = protocol_version, response_code = tonumber(code), code_name = code_name }, field_lines, body, output
end

socket = require("socket")
io.write("input port number...")
io.flush()
local port = io.read()
local client = socket.connect("localhost", port)
local test_message, test_request

test_message = "7.1: A recipient MUST be able to parse and decode the chunked transfer coding."
test_request = "GET /test.html HTTP/1.1\r\nTransfer-Encoding: chunked\r\nHost: localhost\r\n\r\n5\r\nhello\r\n7\r\n server\r\n0\r\nExpires: Sat, 27 Mar 2004 21:12:00 GMT\r\n\r\n"
client:send(test_request)
local first_line, headers, body, output = get_client_response(client)
assert(string.find(body, "hello server") ~= nil and first_line["response_code"] == 200, build_failure_message(test_message, output))
print("PASSED: " .. test_message)