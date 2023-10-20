-- run with ctrl+shift+b
-- install rocks with luarocks in console

-- useful links:
-- implementation steps, https://stackoverflow.com/questions/176409/build-a-simple-http-server-in-c
-- http made really easy, https://www.jmarshall.com/easy/http/
-- http rfc, https://datatracker.ietf.org/doc/html/rfc9112#line.folding

function parse_start_line(start_line)
  -- parse the first line of a http request (2.3-3.1)
  -- contains method, target and protocol, space separated
  -- see https://stackoverflow.com/questions/1426954/split-string-in-lua
  tokens = string.gmatch(start_line,"[^%s]+")
  return tokens(), tokens(), tokens()
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

function read_field_lines_until_crlf(client)
  -- unfold and parse field lines until empty line
  -- check if end of field lines and parse buffer if true
  -- else handle exception for first line, then handle unfolding and new field line case.
  -- TODO: folded headers are untested. set up a test case for this
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
  return field_lines
end

function construct_status_line(code)
  local protocol_version = "HTTP/1.1"
  -- lookup the status text against the code
  local status_text_lookup <const> = {[200] = "OK", [404] = "Not Found", [100] = "Continue"}
  local status_text = status_text_lookup[code]
  return protocol_version .. " " .. code .. " " .. status_text
end

function construct_field_line(field_name, field_value)
  return field_name .. ": " .. field_value
end

function construct_and_send_response(client, response_code, response_fields, response_body)
  -- constructing the response message
  -- construct the status line
  local response = construct_status_line(response_code)
  -- construct each field line
  if response_fields ~= nil then for field_name, field_value in pairs(response_fields) do
    response = response .. "\r\n" .. construct_field_line(field_name, field_value)
  end end
  -- end headers
  response = response .. "\r\n\r\n"
  -- construct the body
  if response_body ~= nil then response = response .. response_body end
  -- send
  client:send(response)
end

-- 1xx http/1.0 check is not required, since all 1xx responses stem from 1.1 client-requests

function construct_xxx_response()

end

function construct_1xx_response()

end

function construct_2xx_response()

end

function construct_3xx_response()

end

function construct_4xx_response()

end

function construct_5xx_response(client)

end

-- sending a code is abstracted to a single function each,
-- with arguments intended to act as a template.
-- this might get refactored, but we'll see.

function respond_with_100(client, protocol_version)
  -- Continue
  construct_and_send_response(client, 100)
end

-- NOT IMPLEMENTED: 101 Switching Protocols
-- no other protocols are planned for implementation, so we can ignore all Upgrade headers and continue


function respond_with_200(client, file, metadata)
  -- OK
  -- TODO: this
end

function respond_with_201(client, location, validators)
  -- Created
  local response_fields = { Location = location }
  -- validators are optional for PUT requests in some cases
  if validators ~= nil then
    for key, value in pairs(validators) do response_fields[key] = value end
  else print("[?] NOTE: 201 responded without validators. was this because of a PUT request?") end
  construct_and_send_response(client, 201, response_fields)
end

function respond_with_202(client)
  -- Accepted
  construct_and_send_response(client, 202)
end

function respond_with_204(client, validators)
  -- No Content
  local response_fields = validators
  construct_and_send_response(client, 204, validators)
end

function respond_with_205(client)
  -- Reset Content
  construct_and_send_response(client, 205)
end

function respond_with_400(client)
  -- Bad Request
  construct_and_send_response(client, 400)
end

function respond_with_404(client)
  -- Not Found
  construct_and_send_response(client, 404)
end

function update_validators(resource_table, resource, modified_timestamp)
  -- TODO: make backend push updates here
  -- TODO: what is the resource_table? where is it stored?
  -- resource table: resource_uri, last_modified, etag
  resource_table[resource][last_modified] = modified_timestamp
  -- TODO: may be necessary to make this modular, i.e. choose between node updates and hashes
  resource_table[resource][etag] = resource_table[resource][etag] + 1
end

function get_validators(resource_table, resource)
  return resource_table[resource][last_modified], resource_table[resource][etag]
end

function get_html_time(unix_time_seconds)
  -- ex. Sun, 06 Nov 1994 08:49:37 GMT
  if unix_time == nil then return os.date("%a, %d %b %Y %H:%M:%S GMT")
  else return os.date("%a, %d %b %Y %H:%M:%S GMT", unix_time_seconds) end
end

function parse_html_time(html_time)
  -- TODO: do we even need this??
  -- html-time regex: (Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} (2[0-4]|[0-1][0-9]):[0-5][0-9]:(60|[0-5][0-9]) GMT
end

function close_connection(client, connections)
  -- close connection and remove from list
  client:shutdown()
  for i, connection in ipairs(connections) do
    if connection == client then
      table.remove(connections, i)
      break
    end
  end
end

-- load namespace
local socket = require("socket")
-- create a TCP socket and bind it to the local host, at any port
local server = assert(socket.bind("*", 8080))
server:settimeout(0.2)
-- find out which port the OS chose for us
local ip, port = server:getsockname()
local connections = {server}
-- print a message informing what's up
print("Please telnet to localhost on port " .. port)
print("After connecting, you have 10s to enter a line to be echoed")
-- loop forever waiting for clients
local packet_num = 0
while 1 do
  ::start::

  -- wait for a socket to have something to read
  local readable_sockets, trash, err = socket.select(connections, nil)
  
  -- iterate all existing connections to check what we need to do
  local line, err, client
  for i, connection in ipairs(readable_sockets) do
    if connection == server then
      -- accept the incoming connection
      local new_connection = server:accept()
      new_connection:settimeout(0.2)
      table.insert(connections, new_connection)
      goto start
    else
      -- read the incoming line
      line, err = connection:receive()
      if not err then
        -- we have a start line, move on
        -- TODO: functionise everything after this point so our flow is less fucked and we can handle all incoming data in a row
        client = connection
        break
      elseif err == "closed" then
        close_connection(connection, connections)
      end
    end
  end
  -- if we don't have a line, go back
  -- this will be less dumb after refactor
  if line == nil then goto start end

  -- logging
  packet_num = packet_num + 1
  print("-------[PACKET " .. packet_num .. " BEGINS]-------")

  -- process the line we just got
  local method_token, request_target, protocol_version
  if not err then
    method_token, request_target, protocol_version = parse_start_line(line)
  end
  print("-------[DUMPED START LINE]-------")
  print("method token: " .. method_token)
  print("request target: " .. request_target)
  print("protocol version: " .. protocol_version)


  -- unfold and parse field lines until empty line for end of headers
  local headers = read_field_lines_until_crlf(client)

  -- log headers
  print("-------[DUMPED HEADERS]-------")
  for key, value in pairs(headers) do
    print(key .. ": " .. value)
  end


  -- determine how to read the body
  local body_length, decode_method
  if headers["Transfer-Encoding"] ~= nil then
    -- TODO: if chunked transfer coding is final encoding, message body length determined by reading and decoding chunked data until transfer encode indications completion
    -- TODO: if chunks transfer is not final, respond with 400 bad request
    if headers["Transfer-Encoding"] == "chunked" then
      decode_method = "chunked"
    else respond_with_400(client) break end
  elseif headers["Content-Length"] ~= nil then
    -- TODO: there's some shit about invalid fields here and lists.
    decode_method = "length"
    body_length = headers["Content-Length"]
  else body_length = 0 end

  -- TODO: after full implemenation, check that this is valid for "if everything is okay, throw 100" (15.2.1)
  if headers["Expect"] == "100-continue" then respond_with_100(client, protocol_version) end


  -- read body
  -- TODO: handle incomplete messages (8)
  local body
  if decode_method == "length" and body_length ~= nil and body_length ~= 0 then
    -- length decoding
    body, err = client:receive(body_length)
  elseif decode_method == "chunked" then
    -- chunked decoding
    -- read chunks
    body = ""
    body_length = 0
    local chunk_header, err = client:receive()
    local tokens = string.gmatch(chunk_header,"[^%s]+")
    local chunk_size, chunk_ext = tonumber(tokens()), tokens()
    while chunk_size > 0 do
      -- need to offset chunk_size to account for additional \r\n
      chunk_data, err = client:receive(chunk_size+2)
      body = body .. string.sub(chunk_data,1,-3)
      print("chunk_data: " .. chunk_data)
      print("chunk handled: " .. string.sub(chunk_data,1,-3))
      print("body: " .. body)
      body_length = body_length + chunk_size
      chunk_header, err = client:receive()
      print("header: " .. chunk_header)
      tokens = string.gmatch(chunk_header,"[^%s]+")
      chunk_size, chunk_ext = tokens(), tokens()
      print("chunk size: " .. chunk_size)
      chunk_size = tonumber(chunk_size)
    end
    -- read trailer field until crlf
    local trailer_field = read_field_lines_until_crlf(client)
    for key, value in pairs(trailer_field) do
      -- TODO: do we always store/forward separate trailer fields?
    end
    -- TODO: remove chunked from Transfer-Encoding. currently we do not parse this as a list, so there is no point
  end

  -- log body
  print("-------[DUMPED BODY]-------")
  print("body length: " .. body_length)
  print(body)
  print("-------[END OF PACKET " .. packet_num .. "]-------\r\n\r\n")


  -- process body based on content_type.
  -- this is where, for instance, we would determine what to do with a url-encoded form
  -- this will likely be handed back somewhere else for processing as we extend from this webserver, so for now we should just skip this.
  local processed_body = body
  local response_code, response_body
  local response_fields = {}

  -- TEMPORARILY set everything to respond 200
  response_code = 200
  
  -- persistence handling (9.3)
  local connection_close = headers["Connection"] == "close"
  local http_11_continue = (protocol_version == "HTTP/1.1")
  local http_10_continue = (protocol_version == "HTTP/1.0" and response_fields["Connection"] == "keep-alive")
  if connection_close or not (http_11_continue or http_10_continue) then response_fields["Connection"] = "close" end

  -- emulating page for test suite, for now
  if request_target == "/test.html" then
    response_code = 200
    response_body = "method token: " .. method_token .. "<br>request target: " .. request_target .. "<br>protocol version: " .. protocol_version
    response_body = response_body .. "<img src='pic_trulli.jpg' alt='Italian Trulli'><img src='pic_trulldi.jpg' alt='Italian Trulli'><img src='pic_trulsli.jpg' alt='Italian Trulli'><img src='pic_trulcli.jpg' alt='Italian Trulli'><img src='pic_trullpli.jpg' alt='Italian Trulli'>"
    response_body = response_body .. "<br>"
    for key, value in pairs(headers) do
      response_body = response_body .. "<br>" .. key .. ": " .. value
    end
    response_body = response_body .. "<br>"
    response_body = response_body .. "<br>body_length: " .. body_length
    if body ~= nil then response_body = response_body .. "<br>body: " .. body else response_body = response_body .. "<br>body: nil" end
    response_fields["Content-Length"] = response_body:len()
  end


  -- construct and send response message
  construct_and_send_response(client, response_code, response_fields, response_body)

  -- follow through on persistence (9.3)
  if response_fields["Connection"] == "close" then close_connection(client, connections) end

end

-- TODO: implement 9.5 graceful timeouts