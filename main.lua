package.path = "../?.lua;" .. package.path
require "uridecoder"
require "backend"
require "utils"
require "base64"
require "sha1"
-- load namespace
local socket = require("socket")
local ltn12 = require("ltn12")

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
local COMMA_SEPARATED_HEADERS <const> = {["transfer-encoding"] = true, ["content-length"] = true}
-- local SEMICOLON_SEPARATED_HEADERS <const> = {["prefer"] = true, [ "content-type"] = true, ["cookie"] = true}
local RESPONSE_TEMPLATE <const> = {["field"] = {}}

local packet_num = 0

-- run with ctrl+shift+b
-- install rocks with luarocks in console

-- useful links:
-- implementation steps, https://stackoverflow.com/questions/176409/build-a-simple-http-server-in-c
-- http made really easy, https://www.jmarshall.com/easy/http/
-- http rfc, https://datatracker.ietf.org/doc/html/rfc9112#line.folding

function close_connection(connections, closing_connection)
  for k, connection in pairs(connections) do
    if connection == closing_connection then
      connection:shutdown()
      connections[k] = nil 
    end
  end
end

function code_400(current_response, close)
  current_response["code"] = 400
  if close then current_response["field"]["Connection"] = "close" end
  return current_response
end

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
  local uri = {}
  if uridecoder.match_http_origin_form(request_target) then uri["uri_form"] = "origin-form"
  elseif uridecoder.match_http_authority_form(request_target) and method_token == "CONNECT" then uri["uri_form"] = "authority-form"
  elseif uridecoder.match_http_absolute_form(request_target) then uri["uri_form"] = "absolute-form"
  elseif uridecoder.match_http_asterisk_form(request_target) then uri["uri_form"] = "asterisk-form"
  else return nil, "[?] WRN in reconstruct_target_uri: target uri failed to match any known format during reconstruction"
  end

  -- parse generic components and return early for absolute-form
  if uri["uri_form"] == "absolute-form" then
    uri["target"] = request_target
    _, uri["authority"], uri["scheme"], uri["path"], uri["query"] = uridecoder.match_http_absolute_form(request_target)
    if uri["query"] then uri["combined_path_and_query_component"] = uri["path"] .. uri["query"]
    else uri["combined_path_and_query_component"] = uri["path"] end
    return uri
  end

  -- determine scheme
  if fixed_uri_scheme ~= nil then uri["scheme"] = fixed_uri_scheme
  else uri["scheme"] = "http" end -- no implementation for https -> no check

  -- determine authority
  if uri["uri_form"] == "authority-form" then uri["authority"] = request_target
  elseif type(host_header_field_value) == "string" and uridecoder.match_http_uri_host(host_header_field_value) then uri["authority"] = host_header_field_value
  else return nil, "[?] WRN in reconstruct_target_uri: request message featured invalid host header field line" end

  -- check authority against scheme for compliance
  if uri["authority"] == "" and uri["scheme"] == "http" then return nil, "[?] WRN in reconstruct_target_uri: request target uri authority empty when uri scheme required non-empty authority" end -- "reject request" assumed as 400
  
  -- determine combined path and query component
  if uri["uri_form"] == "authority-form" or uri["uri_form"] == "asterisk-form" then uri["combined_path_and_query_component"] = ""
  else uri["combined_path_and_query_component"] = request_target end

  -- reconstruct absolute-uri form and return uri information
  uri["path"] = uri["combined_path_and_query_component"] -- TODO: remove query
  uri["target"] = uri["scheme"] .. "://" .. uri["authority"] .. uri["combined_path_and_query_component"]

  -- extract queries and fragments separately
  for fragment in uri["combined_path_and_query_component"]:gmatch("#([^#]*)$") do uri["fragment"] = fragment end
  for query in uri["combined_path_and_query_component"]:gmatch("?([|^#]*).*$") do uri["query"] = query end
  for path in uri["combined_path_and_query_component"]:gmatch("^([^#?]*)") do uri["path"] = path end
  for k, v in pairs(uri) do
    print(k .. ": " .. v)
  end
  return uri
end

function write_sanitized_field(fields, field_name, field_value)
  -- TODO: finish this
  -- sanitizes bare cr and 
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
  local tokens = string.gmatch(start_line,"[^ \t]+")
  return tokens(), tokens(), tokens()
end

function parse_field_line(field_line, table_to_append_to)
  if table_to_append_to == nil then table_to_append_to = {} end
  -- parse a header field line and return values as a table, appending if one is provided
  -- ex. Sec-Fetch-Dest: document
  local field_value, field_value_start, field_name
  field_line = field_line:gsub("[" .. OWS .. "]*$", "")
  field_value_start, _, field_value = field_line:find("%:[" .. OWS .. "]*(.*)")
  field_name = field_line:sub(1, field_value_start - 1)
  if not match_field_value(field_value) then return nil, "[!] ERR: found field value in field line was invalid" end
  if not field_name:find("^" .. FIELD_NAME .. "$") then return nil, "[!] ERR: found field name '" .. field_name .. "' in field line was invalid" end
  -- force case insensitivity
  field_name = field_name:lower()
  -- merge duplicates into table
  if table_to_append_to[field_name] == nil then table_to_append_to[field_name] = field_value
  else table.insert(table_to_append_to[field_name],field_value) end
  return table_to_append_to
end

function read_field_lines_until_crlf(client, disallow_leading_whitespace)
  -- unfold and parse field lines until empty line
  -- check if end of field lines and parse buffer if true
  -- else handle exception for first line, then handle unfolding and new field line case.
  local field_lines = {}
  local field_name, field_value, buffer, line, err
  -- get first line
  while 1 do
    line, err = receive_sanitized(client)
    if err then return nil, "[!] ERR: no field lines found (read_field_lines_until_crlf)" end
    local first_char = line:sub(1, 1)
    if not err then
      if line == "" then
        if buffer ~= nil then
          local parsed_lines, err = parse_field_line(buffer, field_lines)
          if err then return nil, err
          elseif parsed_lines == nil then return nil, "[!] ERR: null lines parsed when reading field lines (read_field_lines_until_crlf)" end
        end
        break
      elseif buffer == nil then
        if disallow_leading_whitespace == true then
          -- disallow leading whitespace on first header line
          if not first_char:find("[" .. OWS .. "]") then buffer = line end
        else buffer = line end
      elseif first_char:find("[" .. OWS .. "]")  then buffer = buffer .. line
      else
        local parsed_lines, err = parse_field_line(buffer, field_lines)
        if err then return nil, err
        elseif parsed_lines == nil then return nil, "[!] ERR: null lines parsed when reading field lines (read_field_lines_until_crlf)" end
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

  local status_text_lookup <const> = {
    [100] = "Continue",
    [101] = "Switching Protocols",
    [200] = "OK",
    [206] = "Partial Content",
    [400] = "Bad Request",
    [404] = "Not Found",
    [416] = "Range Not Satisfiable",
    [426] = "Upgrade Required",
    [501] = "Not Implemented"
  }
  
  local status_text = status_text_lookup[code]

  return "HTTP/1.1 " .. code .. " " .. status_text

end

function construct_field_line(field_name, field_value)
  return field_name .. ": " .. field_value
end

function construct_and_send_response(client, response)
  -- dump response to console
  print("-------[RESPONSE " .. packet_num .. " BEGINS]-------")
  print("code: " .. response["code"])
  print("-------[DUMPED RESPONSE FIELDS]-------")
  for key, value in pairs(response["field"]) do
    if type(value) == "table" then
      value = table.concat(value, " | ")
    end

    print(key .. ": " .. value)
  end
  print("-------[DUMPED RESPONSE BODY]-------")
  if response["body"] ~= nil and string.len(response["body"]) > 1024 then
    print(response["body"]:sub(1, 1024) .. "<snip>")
  else
    print(response["body"])
  end
  print("-------[END OF RESPONSE " .. packet_num .. "]-------\r\n\r\n")
  -- constructing the response message
  -- construct the status line
  local response_string = construct_status_line(response["code"])
  -- construct each field line
  if response["field"] ~= nil then
    for field_name, field_value in pairs(response["field"]) do
      response_string = response_string .. "\r\n" .. construct_field_line(field_name, field_value)
    end
  end
  -- end headers
  response_string = response_string .. "\r\n\r\n"
  -- construct the body
  if response["body"] ~= nil then response_string = response_string .. response["body"] end
  -- send
  sink = socket.sink("keep-open", client)
  source = ltn12.source.string(response_string)
  ltn12.pump.all(source, sink)
  --client:send(response_string)
end

function merge_response_message(overwritten_message, new_message)
  if new_message["code"] ~= nil then overwritten_message["code"] = new_message["code"] end
  if new_message["body"] ~= nil then overwritten_message["body"] = new_message["body"] end
  overwritten_message["field"] = merge_field_lines(overwritten_message["field"], new_message["field"])
  return overwritten_message
end

function merge_field_lines(overwritten_lines, new_lines)
  -- takes two tables of field lines and recursively merges second onto first, overwriting if necessary
  if new_lines ~= nil then for k, _ in pairs(new_lines) do
    overwritten_lines[k] = new_lines[k]
  end end
  return overwritten_lines
end

function print_headers(headers)
  for key, value in pairs(headers) do
    if type(value) == "table" then
      value = table.concat(value, " | ")
    end
    print(key .. ": " .. value)
  end
end

function calculate_sec_websocket_accept(sec_websocket_key)
  local RFC_APPEND_UUID <const> = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  return base64.encode(sha1.calculate(sec_websocket_key .. RFC_APPEND_UUID))
end


function process_incoming(client, line)
  -- if we don't have a line, go back
  if line == nil then return nil, "no line found" end

  -- initiate variables for server response
  -- should contain line, fields, body
  local response = luattp_utils.copy_table(RESPONSE_TEMPLATE)

  -- logging
  packet_num = packet_num + 1
  print("-------[PACKET " .. packet_num .. " BEGINS]-------")

  -- process the line we just got
  -- skip arbitrary number of crlf, limited so a client can't hold up the server forever with unlimited crlf
  local err
  local count = 0
  while line == "" do
    line, err = receive_sanitized(client)
    if err then
      print("[!] ERR: during processing of pre-header crlf: " .. err)
      return code_400(response, true)
    end
    count = count + 1
    if count > 15 then
      print("crlf count passed 15 limit whilst receiving, aborting")
      return code_400(response, true)
    end
  end
  local method_token, request_target, protocol_version
  if not err then
    method_token, request_target, protocol_version = parse_start_line(line)
  end
  print("-------[DUMPED START LINE]-------")
  print("method token: " .. method_token)
  print("request target: " .. request_target)
  print("protocol version: " .. protocol_version)


  -- unfold and parse field lines until empty line for end of headers
  local headers, err = read_field_lines_until_crlf(client, true)
  if err then
    print(err)
    return code_400(response, true)
  end
  -- define header field values
  headers = define_field_values(headers)

  -- log headers
  print("-------[DUMPED HEADERS]-------")
  print_headers(headers)

  -- validate headers
  -- todo; force lowercase headers for case insensitivity if needed
  local target_uri, err = reconstruct_target_uri(method_token, request_target, nil, headers["host"])
  if err then
    print(err)
    return code_400(response, true)
  end

  -- determine how to read the body and its length
  local decode_method, body_length
  if headers["transfer-encoding"] ~= nil then

    -- close connection for deprecated clients
    if content_length_header ~= nil or protocol_version == "HTTP/1.0" then
      response["field"]["Connection"] = "close"
    end

    local final_encoding = transfer_encoding_header[#transfer_encoding_header]

    -- last encoding must always be chunked
    if final_encoding ~= "chunked" then
      print("last encoding was not chunked, aborting")
      return code_400(response, true)
    end

    -- return 501 on any unrecognised encodings in queue [which for now is. anything not chunked]
    for i, v in ipairs(headers["transfer-encoding"]) do
      if v:lower() ~= "chunked" then
        -- 501 Not Implemented
        -- TODO: thisis uufckked. sutrely
        response["code"] = 501
        return response
      end
    end

  elseif headers["content-length"] ~= nil then

    -- perform list validity check (6.3)
    for i, v in ipairs(headers["content-length"]) do
      for k, x in ipairs(headers["content-length"]) do
        if v ~= x then
          print("length was list but was not valid, aborting")
          return code_400(response, true)
        end
      end
    end

    decode_method = "length"
    body_length = headers["content-length"][1]

  else body_length = 0 end


  -- persistence handling (9.3)
  local client_wants_to_close = headers["connection"] == "close"
  local protocol_should_persist = (protocol_version == "HTTP/1.1") or (protocol_version == "HTTP/1.0" and headers["connection"] == "keep-alive")
  if client_wants_to_close or not protocol_should_persist then response["field"]["Connection"] = "close" end

  -- continue implementation
  -- TODO: fix this
  if headers["expect"] == "100-continue" then respond_with_100(client, protocol_version) end
  

  -- read body
  -- TODO: handle incomplete messages (8)
  local body

  if decode_method == "length" and body_length ~= nil and body_length > 0 then

    body, err = client:receive(body_length)
    
    if err or body:len() ~= body_length then
      return code_400(response, true)
    end

  elseif decode_method == "chunked" then

    -- read chunks
    body = ""
    body_length = 0

    local chunk_header, err = receive_sanitized(client)

    if err then
      print(err)
      return code_400(response, true)
    end

    local tokens = string.gmatch(chunk_header,"[^%s]+")
    local chunk_size, chunk_ext = tonumber(tokens()), tokens()
    
    -- 7.1.1 chunk extensions. we do not recognise any chunk extensions, so we ignore them.
    while chunk_size > 0 do
      -- need to offset chunk_size to account for additional \r\n
      local chunk_data, err = client:receive(chunk_size+2)
      if err then
        print(err)
        return code_400(response, true)
      end
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
    headers["transfer-encoding"][#headers["transfer-encoding"]] = nil
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

  -- hacky place to handle websocket entry
  if protocol_version == "HTTP/1.1"
  and headers["upgrade"] ~= nil
  and string.lower(headers["upgrade"]) == "websocket"
  then 

    if headers["host"] ~= luattp_backend.config.host then
      -- TODO: we are not handling this right as we don't have the infrastructure
    end

    local decoded_sec_websocket_key = base64.decode(headers["sec-websocket-key"])
    if decoded_sec_websocket_key:len() ~= 16 then
      return {
        ["code"] = 400,
        ["field"] = {},
        ["body"] = nil
      }
    end

    if headers["sec-websocket-version"] ~= "13" then
      return {
        ["code"] = 426,
        ["field"] = {
          ["Sec-WebSocket-Version"] = 13
        },
        ["body"] = nil
      }
    end

    -- TODO: resource names, extensions, subprotocols. we do not necessarily have to  do this for our task
    return {
      ["code"] = 101,
      ["field"] = {
        ["Upgrade"] = "websocket",
        ["Connection"] = "Upgrade",
        ["Sec-WebSocket-Accept"] = calculate_sec_websocket_accept(headers["sec-websocket-key"])
      }
    }

  end

  -- hand to backend to generate response
  -- emulating page for test suite, for now
  if target_uri["path"]:find("test.html") then
    response["code"] = 200
    response["body"] = "method token: " .. method_token .. "<br>request target: " .. request_target .. "<br>protocol version: " .. protocol_version
    response["body"] = response["body"] .. "<br>absolute uri: " .. target_uri["target"]
    --response_body = response_body .. "<img src='pic_trulli.jpg' alt='Italian Trulli'><img src='pic_trulldi.jpg' alt='Italian Trulli'><img src='pic_trulsli.jpg' alt='Italian Trulli'><img src='pic_trulcli.jpg' alt='Italian Trulli'><img src='pic_trullpli.jpg' alt='Italian Trulli'>"
    response["body"] = response["body"] .. "<br>"
    -- print headers
    for key, value in pairs(headers) do
      if type(value) == "table" then
        local new_value = ""
        for i, v in ipairs(value) do
          if new_value ~= "" then new_value = new_value .. ", " end
          new_value = new_value .. v
        end
        value = new_value
      end
      response["body"] = response["body"] .. "<br>" .. key .. ": " .. value
    end
    response["body"] = response["body"] .. "<br>"
    response["body"] = response["body"] .. "<br>body_length: " .. body_length
    if body ~= nil then response["body"] = response["body"] .. "<br>body: " .. body else response["body"] = response["body"] .. "<br>body: nil" end
  else
    if method_token == "GET" then
      local backend_response = luattp_backend.GET(target_uri["path"], headers)
      response = merge_response_message(backend_response, response)
    elseif method_token == "HEAD" then
      local backend_response = luattp_backend.HEAD(target_uri["path"], headers)
      response = merge_response_message(backend_response, response)
    end
  end

  -- handle encodings
  if response["field"]["Content-Length"] == nil then response["field"]["Content-Length"] = 0 end
  if response["field"]["Content-Length"] > 1024 then
    response["field"]["Transfer-Encoding"] = "chunked"
    response["field"]["Content-Length"] = nil
    if method_token ~= "HEAD" then
      -- encode as chunked due to large size
      local chunked_body = {}
      local chunk_index = 1
      local body_length = response["body"]:len()
      while chunk_index < body_length do
        -- get chunk
        local chunk = response["body"]:sub(chunk_index, chunk_index + 1023)
        chunk_index = chunk_index + 1024
        -- append to new body
        local chunk_size = string.format("%x", chunk:len())
        table.insert(chunked_body, chunk_size .. "\r\n" .. chunk .. "\r\n")
      end
      -- append last chunk of 0
      table.insert(chunked_body, "0\r\n\r\n")
      response["body"] = table.concat(chunked_body, "")
    end
  end

  return response
end

function send_response(client, response)
  -- finalize and send response

  -- send blank Transfer-Encodings to imply chunked allowed (7.4)
  if response["field"]["Transfer-Encoding"] == nil then response["field"]["Transfer-Encoding"] = "" end
  if response["field"]["Connection"] == nil then response["field"]["Connection"] = "" end
  if response["field"]["ETag"] == nil then response["field"]["ETag"] = "1" end

  -- construct and send response message
  construct_and_send_response(client, response)

end

function accept_connection(server)
  
  print("accepting...")
  local new_connection = server:accept()
  new_connection:settimeout(0.2)
  new_connection:setoption('keepalive', true)
  return new_connection

end

-- TODO: implement 9.5 graceful timeouts

-- create a TCP socket and bind it to localhost:8080
local port = 8080
local server = assert(socket.bind("*", port))
server:settimeout(0.2)
-- find out which port the OS chose for us
local connections = {server}
-- print a message informing server start
print("server started on localhost port " .. port)
-- loop forever waiting for clients
while 1 do
  
  -- wait for a socket to have something to read
  print("waiting...")
  local readable_sockets, _, err = socket.select(connections, nil)
  
  -- iterate all existing connections to check what we need to do
  local line, err
  for i, connection in ipairs(readable_sockets) do
    if connection == server then

      table.insert(connections, accept_connection(server))

    else
      -- read the incoming line
      line, err = receive_sanitized(connection)
      if not err then

        -- we have a start line, move on
        local response = process_incoming(connection, line)

        send_response(connection, response)

        if response["field"]["Connection"] == "close" then close_connection(connections, connection) end

      elseif err == "closed" then

        print("closing...")
        -- clean shutdown connections
        close_connection(connections, connection)

      else

        -- reset connection
        print("resetting...")
        print("error: " .. err)
        send_response(connection, code_400(RESPONSE_TEMPLATE, true))
        close_connection(connections, connection)

      end
    end
  end
end
