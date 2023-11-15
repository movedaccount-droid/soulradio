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
-- io.write("input port number...")
-- io.flush()
local port = 8080 -- io.read()
local client = socket.connect("localhost", port)
local test_message, test_request

test_message = "2.2: a server that is expecting to receive and parse a request-line SHOULD ignore at least one empty line (CRLF) received prior to the request-line."
test_request = "\r\n\r\nGET /test.html HTTP/1.1\r\nsuccess: successful\r\nhost:localhost:8080\r\n\r\n"
client:send(test_request)
print(body)
local first_line, headers, body, output = get_client_response(client)
assert(string.find(body, "success: successful") ~= nil and first_line["response_code"] == 200, build_failure_message(test_message, output))
print("PASSED: " .. test_message)

-- test_message = "2.2: A recipient of such a bare CR MUST consider that element to be invalid or replace each bare CR with SP before processing the element or forwarding the message."
-- testing against chunked for harder test case
-- test_request = "GET /test.html\rHTTP/1.1\r\nTransfer-Encoding: chunked\r\nHost: localhost\r\n\r\n11\r\nspace\rhere\r\n7\r\n server\r\n0\r\nExpires: Sat, 27 Mar 2004 21:12:00 GMT\r\n\r\n"
-- client:send(test_request)
-- local first_line, headers, body, output = get_client_response(client)
-- assert(string.find(body, "space here") ~= nil and first_line["response_code"] == 200, build_failure_message(test_message, output))
-- print("PASSED: " .. test_message)

test_message = "2.2: A recipient that receives whitespace between the start-line and the first header field MUST either reject the message as invalid or consume each whitespace-preceded line without further processing of it"
test_request = "\r\n\r\nGET /test.html HTTP/1.1\r\n ignored: success\r\n ignored2: success \r\nincluded: success\r\n folded\r\nhost:localhost:8080\r\n\r\n"
client:send(test_request)
local first_line, headers, body, output = get_client_response(client)
assert(string.find(body, "included: success folded") ~= nil and string.find(body, "ignored: success") == nil and string.find(body, "ignored2: success") == nil and first_line["response_code"] == 200, build_failure_message(test_message, output))
print("PASSED: " .. test_message)

test_message = "3.3: Reconstructing the Target URI, origin-form"
test_request = "\r\nGET /where?q=now HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"
client:send(test_request)
local first_line, headers, body, output = get_client_response(client)
assert(string.find(body, "absolute uri%: http%:%/%/localhost%:8080%/where%?q%=now") ~= nil and first_line["response_code"] == 200, build_failure_message(test_message, output))
print("PASSED: " .. test_message)

test_message = "3.3: Reconstructing the Target URI, absolute-form"
test_request = "\r\nGET http://localhost:8080/pub/WWW/TheProject.html HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"
client:send(test_request)
local first_line, headers, body, output = get_client_response(client)
assert(string.find(body, "absolute uri%: http%:%/%/localhost%:8080%/pub%/WWW%/TheProject%.html") ~= nil and first_line["response_code"] == 200, build_failure_message(test_message, output))
print("PASSED: " .. test_message)

test_message = "3.3: Reconstructing the Target URI, authority-form"
test_request = "\r\nCONNECT localhost:8080 HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"
client:send(test_request)
local first_line, headers, body, output = get_client_response(client)
assert(string.find(body, "absolute uri: http%:%/%/localhost%:8080") ~= nil and first_line["response_code"] == 200, build_failure_message(test_message, output))
print("PASSED: " .. test_message)

test_message = "3.3: Reconstructing the Target URI, asterisk-form"
test_request = "\r\nOPTIONS * HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"
client:send(test_request)
local first_line, headers, body, output = get_client_response(client)
assert(string.find(body, "absolute uri: http%:%/%/localhost%:8080") ~= nil and first_line["response_code"] == 200, build_failure_message(test_message, output))
print("PASSED: " .. test_message)

test_message = "5: Each field line consists of a case-insensitive field name followed by a colon (':'), optional leading whitespace, the field line value, and optional trailing whitespace."
test_request = "\r\n\r\nGET /test.html HTTP/1.1\r\nnospace:success\r\nhost:localhost:8080\r\nonespace: success \r\ntwospace:  success  \r\ntab:	success	\r\nmixed:  	   	    success   	  	   \r\n\r\n"
client:send(test_request)
local first_line, headers, body, output = get_client_response(client)
assert(string.find(body, "nospace: success") ~= nil and string.find(body, "onespace: success") ~= nil and string.find(body, "twospace: success") ~= nil and string.find(body, "tab: success") ~= nil and string.find(body, "mixed: success") ~= nil and first_line["response_code"] == 200, build_failure_message(test_message, output))
print("PASSED: " .. test_message)

-- test_message = "6.1: A server that receives a request message with a transfer coding it does not understand SHOULD respond with 501 (Not Implemented)."
-- test_request = "GET /test.html HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
-- client:send(test_request)
-- local first_line, headers, body, output = get_client_response(client)
-- assert(first_line["response_code"] == 501, build_failure_message(test_message, output))
-- print("PASSED: " .. test_message)

test_message = "7.1: A recipient MUST be able to parse and decode the chunked transfer coding."
test_request = "GET /test.html HTTP/1.1\r\nTransfer-Encoding: chunked\r\nHost: localhost\r\n\r\n5\r\nhello\r\n7\r\n server\r\n0\r\nExpires: Sat, 27 Mar 2004 21:12:00 GMT\r\n\r\n"
client:send(test_request)
local first_line, headers, body, output = get_client_response(client)
assert(string.find(body, "hello server") ~= nil and first_line["response_code"] == 200, build_failure_message(test_message, output))
print("PASSED: " .. test_message)

print ("---------------------------------------")
print ("!!         ALL TESTS PASSED          !!")
print ("---------------------------------------")