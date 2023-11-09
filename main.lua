package.path = "../?.lua;" .. package.path
require "uridecoder"

local OWS <const> = " 	"
local TCHAR <const> = "%!%#%$%%%&%'%*%+%-%.%6%_%`%|%~%d%a"
local TOKEN <const> = "[" .. TCHAR .. "]+"
local FIELD_NAME <const> = TOKEN
local VCHAR <const> = "%!%\"%#%$%%%&%'%(%)%*%+%,%-%.%/%w%:%;%<%=%>%?%@%[%\\%]%^%_%`%{%|%}%~"
local OBS_TEXT <const> = "€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"
local FIELD_VCHAR <const> = "[" .. VCHAR .. OBS_TEXT .. "]"

-- all headers MUST be able to be parsed as a list.
-- however, resolving lists is non-trivial. unique syntax each header field.
-- so far implemented:
local COMMA_SEPARATED_HEADERS <const> = {["Transfer-Encoding"] = true, ["Content-Length"] = true}
local SEMICOLON_SEPARATED_HEADERS <const> = {["Prefer"] = true, [ "Content-Type"] = true, ["Cookie"] = true}

-- run with ctrl+shift+b
-- install rocks with luarocks in console

-- useful links:
-- implementation steps, https://stackoverflow.com/questions/176409/build-a-simple-http-server-in-c
-- http made really easy, https://www.jmarshall.com/easy/http/
-- http rfc, https://datatracker.ietf.org/doc/html/rfc9112#line.folding

function match_field_content(field_content)
  local char_found
  field_content, char_found = field_content:gsub("^" .. FIELD_VCHAR, "")
  if char_found == 0 then return false end
  if field_content == "" then return true end
  field_content, char_found = field_content:gsub(FIELD_VCHAR .. "$", "")
  if char_found == 0 then return false end
  return field_content:find("^[" .. OWS .. FIELD_VCHAR .. "]$") ~= nil
end

function match_field_value(field_value)
  -- TODO: can this be more efficient?
  local start_index = 1
  local end_index = field_value:len()
  while true do
    -- iterate backwards from end of string to find largest match, or fail if we find nothing
    while not match_field_content(field_value:sub(start_index, end_index)) do
      if end_index == start_index then return false
      else
        end_index = end_index - 1
      end
    end
    -- if our match hits the end of the string, we've validated everything. else loop again from current validated position
    if end_index == field_value:len() then return true
    else
      start_index = end_index + 1
      end_index = field_value:len()
    end
  end
end

function reconstruct_target_uri(method_token, request_target, fixed_uri_scheme, host_header_field_value)
  -- determine uri form
  -- TODO: can we bypass checking the method token directly?
  -- ex. localhost:8080 is valid authority /and/ absolute form, so we have to differentiate by method_token
  local uri_form
  if uridecoder.match_http_origin_form(request_target) then uri_form = "origin-form"
  elseif uridecoder.match_http_authority_form(request_target) and method_token == "CONNECT" then uri_form = "authority-form"
  elseif uridecoder.match_http_absolute_form(request_target) then uri_form = "absolute-form"
  elseif uridecoder.match_http_asterisk_form(request_target) then uri_form = "asterisk-form"
  else -- TODO: return error code?
  end

  print(uri_form)

  -- return early for absolute-form
  if uri_form == "absolute-form" then return request_target end
  -- determine scheme
  local scheme
  if fixed_uri_scheme ~= nil then scheme = fixed_uri_scheme
  else scheme = "http" end -- no implementation for https, no need to check for it

  -- determine authority
  -- TODO: check for invalid header field? what does an invalid field look like?
  local authority
  if uri_form == "authority-form" then authority = request_target
  elseif host_header_field_value ~= nil then authority = host_header_field_value
  else authority = "" end

  -- check authority against scheme for compliance
  if authority == "" and scheme == "http" then end -- TODO: "reject request"
  
  -- determine combined path and query component
  local combined_path_and_query_component
  if uri_form == "authority-form" or uri_form == "asterisk-form" then combined_path_and_query_component = ""
  else combined_path_and_query_component = request_target end

  -- reconstruct absolute-uri form
  return scheme .. "://" .. authority .. combined_path_and_query_component
end

function receive_sanitized(client, receive_argument)
  -- sanitizes bare cr to sp
  local line, err = client:receive(receive_argument)
  if not err then line = line:gsub("\r(?!\n)"," ") end
  return line, err
end

function parse_start_line(start_line)
  -- parse the first line of a http request (2.3-3.1)
  -- contains method, target and protocol, space separated
  -- see https://stackoverflow.com/questions/1426954/split-string-in-lua
  tokens = string.gmatch(start_line,"[^ \t]+")
  return tokens(), tokens(), tokens()
end

function parse_field_line(field_line, table_to_append_to)
  if table_to_append_to == nil then table_to_append_to = {} end
  -- parse a header field line and return values as a table, appending if one is provided
  -- ex. Sec-Fetch-Dest: document
  -- TODO: handle malformed field line with generic error
  -- TODO: A server MUST reject, with a response status code of 400 (Bad Request), any received request message that contains whitespace between a header field name and colon
  -- TODO: reject folded field lines with 400 (5.2)
  -- TODO: validation validation validation on field line etc.
  -- local field_name_end, field_value_start = string.find(field_line,":[ \t]*")
  -- trim end whitespace
  print(field_line)
  local field_value, field_value_start, field_name
  field_line = field_line:gsub("[" .. OWS .. "]*$", "")
  field_value_start, _, field_value = field_line:find("%:[" .. OWS .. "]*(.*)")
  field_name = field_line:sub(1, field_value_start - 1)
  if not match_field_value(field_value) then end -- TODO: throw error
  if not field_name:find("^" .. field_name .. "$") then end -- TODO: throw error
  table_to_append_to[field_name] = field_value
  return table_to_append_to
end

function read_field_lines_until_crlf(client, disallow_leading_whitespace)
  -- unfold and parse field lines until empty line
  -- check if end of field lines and parse buffer if true
  -- else handle exception for first line, then handle unfolding and new field line case.
  -- TODO: folded headers are untested. set up a test case for this
  -- TODO: disallow duplicate fields, ex. host
  local field_lines = {}
  local field_name, field_value, buffer, line, err
  -- get first line
  while 1 do
    line, err = receive_sanitized(client)
    local first_char = line:sub(1, 1)
    if not err then
      if line == "" then
        if buffer ~= nil then
          field_name, field_value = parse_field_line(buffer, field_lines)
          field_lines[field_name] = field_value
        end
        break
      elseif buffer == nil then
        if disallow_leading_whitespace == true then
          -- disallow leading whitespace on first header line
          if not first_char:find("[" .. OWS .. "]") then buffer = line end
        else buffer = line end
      elseif first_char:find("[" .. OWS .. "]")  then buffer = buffer .. line
      else
        field_name, field_value = parse_field_line(buffer, field_lines)
        field_lines[field_name] = field_value
        buffer = line
      end
    end
  end
  return field_lines
end

function define_field_values(headers)
  for field_name, field_value in pairs(headers) do
    -- TODO: check order of operations
    if COMMA_SEPARATED_HEADERS[field_name] then field_value = process_field_list(field_value, ",") end
    headers[field_name] = field_value
  end
  return headers
end

function process_field_list(field_value, delimiter)
  -- rfc9110 5.6.1.2
  -- TODO: first code back from break. messy
  local elements = {}
  local element, delim_start, delim_end
  local index = 0
  while true do
    index = index + 1
    ::skipped::
    print("processing: " .. field_value)
    delim_start, delim_end = field_value:find("[" .. OWS .. "]*" .. delimiter .. "[" .. OWS .. "]*")
    if delim_start == nil then break end
    element = field_value:sub(1, delim_start - 1)
    field_value = field_value:sub(delim_end + 1, -1)
    if element == "" then goto skipped end
    elements[index] = element
  end
  -- push last value in list, if not blank
  print(field_value)
  print(index)
  if field_value ~= "" then elements[index] = field_value end
  print(elements[1])
  return elements
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
  resource_table[resource]["last_modified"] = modified_timestamp
  -- TODO: may be necessary to make this modular, i.e. choose between node updates and hashes
  resource_table[resource]["etag"] = resource_table[resource]["etag"] + 1
end

function get_validators(resource_table, resource)
  return resource_table[resource]["last_modified"], resource_table[resource]["etag"]
end

function get_html_time(unix_time_seconds)
  -- ex. Sun, 06 Nov 1994 08:49:37 GMT
  if unix_time_seconds == nil then return os.date("%a, %d %b %Y %H:%M:%S GMT")
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
      line, err = receive_sanitized(connection)
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
  print(line)

  -- initiate variables for server response
  local response_code, response_body
  local response_fields = {}

  -- logging
  packet_num = packet_num + 1
  print("-------[PACKET " .. packet_num .. " BEGINS]-------")

  -- process the line we just got
  -- skip arbitrary number of crlf
  -- TODO: limit this so a client can't hold up the server forever with unlimited crlf
  while line == "" do line = receive_sanitized(client) end
  local method_token, request_target, protocol_version
  if not err then
    method_token, request_target, protocol_version = parse_start_line(line)
  end
  print("-------[DUMPED START LINE]-------")
  print("method token: " .. method_token)
  print("request target: " .. request_target)
  print("protocol version: " .. protocol_version)


  -- unfold and parse field lines until empty line for end of headers
  local headers = read_field_lines_until_crlf(client, true)
  -- define header field values
  headers = define_field_values(headers)

  -- log headers
  print("-------[DUMPED HEADERS]-------")
  for key, value in pairs(headers) do
    if type(value) == "table" then
      value = table.concat(value, " | ")
    end
    print(key .. ": " .. value)
  end

  -- validate headers
  if headers["Host"] == nil or uridecoder.match_http_uri_host(headers["Host"]) == false then --TODO: respond_with_400(client)
  end

  -- determine how to read the body
  local body_length, decode_method
  if headers["Transfer-Encoding"] ~= nil then
    if headers["Content-Length"] ~= nil or protocol_version == "HTTP/1.0" then
      response_fields["Connection"] = "close"
    end
    -- TODO: is content-length and transfer-encoding valid if both specified? etc.
    if headers["Transfer-Encoding"][#headers["Transfer-Encoding"]]:lower() == "chunked" then
      -- 501 unrecognised encodings in queue
      for i, v in ipairs(headers["Transfer-Encoding"]) do
        if v:lower() ~= "chunked" then -- TODO: respond_with_501(client)
        end
      end
      -- else decode chunked
      decode_method = "chunked"
    else -- TODO: respond_with_400(client)
    end
  elseif headers["Content-Length"] ~= nil then
    -- list validity check (6.3)
    for i, v in ipairs(headers["Content-Length"]) do
      for k, x in ipairs(headers["Content-Length"]) do
        if v ~= x then -- TODO: respond_with_400(client) and close the connection
        end
      end
    end
    -- if valid continue
    decode_method = "length"
    body_length = headers["Content-Length"]
  else body_length = 0 end

  -- TODO: after full implementation, check that this is valid for "if everything is okay, throw 100" (15.2.1)
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
    local chunk_header, err = receive_sanitized(client)
    local tokens = string.gmatch(chunk_header,"[^%s]+")
    local chunk_size, chunk_ext = tonumber(tokens()), tokens()
    -- 7.1.1 chunk extensions. we do not recognise any chunk extensions, so we ignore them.
    while chunk_size > 0 do
      -- need to offset chunk_size to account for additional \r\n
      chunk_data, err = client:receive(chunk_size+2)
      body = body .. string.sub(chunk_data,1,-3)
      print("chunk_data: " .. chunk_data)
      print("chunk handled: " .. string.sub(chunk_data,1,-3))
      print("body: " .. body)
      body_length = body_length + chunk_size
      chunk_header, err = receive_sanitized(client)
      print("header: " .. chunk_header)
      tokens = string.gmatch(chunk_header,"[^%s]+")
      chunk_size, chunk_ext = tonumber(tokens()), tokens()
      -- ignore extensions
      print("chunk size: " .. chunk_size)
      chunk_size = tonumber(chunk_size)
    end
    -- read trailer field until crlf
    local trailer_field = read_field_lines_until_crlf(client)
    -- don't do anything with these. but we have them anyway
    -- remove chunked from Transfer-Encoding
    headers["Transfer-Encoding"][#headers["Transfer-Encoding"]] = nil
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

  -- TEMPORARILY set everything to respond 200
  response_code = 200
  
  -- persistence handling (9.3)
  local connection_close = headers["Connection"] == "close"
  local http_11_continue = (protocol_version == "HTTP/1.1")
  local http_10_continue = (protocol_version == "HTTP/1.0" and response_fields["Connection"] == "keep-alive")
  if connection_close or not (http_11_continue or http_10_continue) then response_fields["Connection"] = "close" end

  -- emulating page for test suite, for now
  if true then
    response_code = 200
    response_body = "method token: " .. method_token .. "<br>request target: " .. request_target .. "<br>protocol version: " .. protocol_version
    response_body = response_body .. "<br>absolute uri: " .. reconstruct_target_uri(method_token, request_target, nil, headers["Host"])
    --response_body = response_body .. "<img src='pic_trulli.jpg' alt='Italian Trulli'><img src='pic_trulldi.jpg' alt='Italian Trulli'><img src='pic_trulsli.jpg' alt='Italian Trulli'><img src='pic_trulcli.jpg' alt='Italian Trulli'><img src='pic_trullpli.jpg' alt='Italian Trulli'>"
    response_body = response_body .. "<br>"
    for key, value in pairs(headers) do
      if type(value) == "table" then
        local new_value = ""
        for i, v in ipairs(value) do
          if new_value ~= "" then new_value = new_value .. ", " end
          new_value = new_value .. v
        end
        value = new_value
      end
      response_body = response_body .. "<br>" .. key .. ": " .. value
    end
    response_body = response_body .. "<br>"
    response_body = response_body .. "<br>body_length: " .. body_length
    if body ~= nil then response_body = response_body .. "<br>body: " .. body else response_body = response_body .. "<br>body: nil" end
    response_fields["Content-Length"] = response_body:len()
  end

  -- send blank Transfer-Encodings to imply chunked allowed (7.4)
  response_fields["Transfer-Encoding"] = ""
  response_fields["Connection"] = ""

  -- construct and send response message
  construct_and_send_response(client, response_code, response_fields, response_body)

  -- follow through on persistence (9.3)
  if response_fields["Connection"] == "close" then close_connection(client, connections) end

end

-- TODO: implement 9.5 graceful timeouts