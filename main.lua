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
  local uri_form
  if uridecoder.match_http_origin_form(request_target) then uri_form = "origin-form"
  elseif uridecoder.match_http_authority_form(request_target) and method_token == "CONNECT" then uri_form = "authority-form"
  elseif uridecoder.match_http_absolute_form(request_target) then uri_form = "absolute-form"
  elseif uridecoder.match_http_asterisk_form(request_target) then uri_form = "asterisk-form"
  else return nil, "target uri failed to match any known format during reconstruction"
  end

  -- return early for absolute-form
  if uri_form == "absolute-form" then return request_target end
  -- determine scheme
  local scheme
  if fixed_uri_scheme ~= nil then scheme = fixed_uri_scheme
  else scheme = "http" end -- no implementation for https, no need to check for it

  -- determine authority
  local authority
  if uri_form == "authority-form" then authority = request_target
  elseif type(host_header_field_value) == "string" and uridecoder.match_http_uri_host(host_header_field_value) then authority = host_header_field_value
  else return nil, "request message featured invalid host header field line" end

  -- check authority against scheme for compliance
  if authority == "" and scheme == "http" then return "request target uri authority empty when uri scheme required non-empty authority" end -- "reject request" assumed as 400
  
  -- determine combined path and query component
  local combined_path_and_query_component
  if uri_form == "authority-form" or uri_form == "asterisk-form" then combined_path_and_query_component = ""
  else combined_path_and_query_component = request_target end

  -- reconstruct absolute-uri form
  return scheme .. "://" .. authority .. combined_path_and_query_component
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
  -- lookup the status text against the code
  local status_text_lookup <const> = {[200] = "OK", [404] = "Not Found", [100] = "Continue", [400] = "Bad Request", [501] = "Not Implemented"}
  local status_text = status_text_lookup[code]
  return protocol_version .. " " .. code .. " " .. status_text
end

function construct_field_line(field_name, field_value)
  return field_name .. ": " .. field_value
end

function construct_and_send_response(client, response)
  -- dump response to console
  print("-------[DUMPED RESPONSE]-------")
  print("code: " .. response["code"])
  print("-------[DUMPED RESPONSE FIELDS]-------")
  for key, value in pairs(response["field"]) do
    if type(value) == "table" then
      value = table.concat(value, " | ")
    end

    print(key .. ": " .. value)
  end
  print("-------[DUMPED RESPONSE BODY]-------")
  print(response["body"])
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
  client:send(response_string)
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

function process_incoming(client, line)
  -- if we don't have a line, go back
  -- this will be less dumb after refactor
  if line == nil then return nil, "no line found" end

  -- initiate variables for server response
  -- should contain line, fields, body
  local response = {}
  response["field"] = {}

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
  for key, value in pairs(headers) do
    if type(value) == "table" then
      value = table.concat(value, " | ")
    end
    print(key .. ": " .. value)
  end

  -- validate headers
  -- todo; force lowercase headers for case insensitivity if needed
  local target_uri, err = reconstruct_target_uri(method_token, request_target, nil, headers["host"])
  if err then
    print(err)
    return code_400(response, true)
  end

  -- determine how to read the body
  local body_length, decode_method
  if headers["transfer-encoding"] ~= nil then
    if headers["content-length"] ~= nil or protocol_version == "HTTP/1.0" then
      response["field"]["Connection"] = "close"
    end
    if headers["transfer-encoding"][#headers["transfer-encoding"]]:lower() == "chunked" then
      -- 501 unrecognised encodings in queue
      for i, v in ipairs(headers["transfer-encoding"]) do
        if v:lower() ~= "chunked" then
          -- 501 Not Implemented
          response["code"] = 501
          return response
        end
      end
      -- else decode chunked
      decode_method = "chunked"
    else
      print("last encoding was not chunked, aborting")
      return code_400(response, true)
    end
  elseif headers["content-length"] ~= nil then
    -- list validity check (6.3)
    for i, v in ipairs(headers["content-length"]) do
      for k, x in ipairs(headers["content-length"]) do
        if v ~= x then
          print("length was list but was not valid, aborting")
          return code_400(response, true)
        end
      end
    end
    -- if valid continue
    decode_method = "length"
    body_length = headers["content-length"][1]
  else body_length = 0 end

  -- persistence handling (9.3)
  local connection_close = headers["connection"] == "close"
  local http_11_continue = (protocol_version == "HTTP/1.1")
  local http_10_continue = (protocol_version == "HTTP/1.0" and headers["connection"] == "keep-alive")
  if connection_close or not (http_11_continue or http_10_continue) then response["field"]["Connection"] = "close" end

  -- continue implementation
  if headers["expect"] == "100-continue" then respond_with_100(client, protocol_version) end

  -- read body
  -- TODO: handle incomplete messages (8)
  local body
  if decode_method == "length" and body_length ~= nil and body_length ~= 0 then
    -- length decoding
    body, err = client:receive(body_length)
    if err or body:len() ~= body_length then
      return code_400(response, true)
    end
  elseif decode_method == "chunked" then
    -- chunked decoding
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

  -- TEMPORARILY set everything to respond 200
  response["code"] = 200

  -- emulating page for test suite, for now
  if true then
    response["code"] = 200
    response["body"] = "method token: " .. method_token .. "<br>request target: " .. request_target .. "<br>protocol version: " .. protocol_version
    response["body"] = response["body"] .. "<br>absolute uri: " .. target_uri
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
    response["field"]["Content-Length"] = response["body"]:len()
  end

  return response
end

function send_response(client, response)
  -- finalize and send response

  -- send blank Transfer-Encodings to imply chunked allowed (7.4)
  response["field"]["Transfer-Encoding"] = ""
  if response["field"]["Connection"] == nil then response["field"]["Connection"] = "" end

  -- construct and send response message
  construct_and_send_response(client, response)

  -- follow through on persistence (9.3)
  return response["field"]["Connection"] == "close"
end

-- TODO: implement 9.5 graceful timeouts

-- load namespace
local socket = require("socket")
-- create a TCP socket and bind it to the local host, at any port
local server = assert(socket.bind("*", 8080))
server:settimeout(0.2)
-- find out which port the OS chose for us
local ip, port = server:getsockname()
local connections = {server}
-- print a message informing what's up
print("server started on localhost port " .. port)
-- loop forever waiting for clients
while 1 do
  
  -- wait for a socket to have something to read
  print("waiting...")
  for k, v in ipairs(connections) do print("connection " .. k .. ": " .. tostring(v:dirty())) end
  local readable_sockets, _, err = socket.select(connections, nil)

  for i, connection in ipairs(connections) do
    print("in array as ".. i .. ": ")
    print(connections[i])
  end
  
  -- iterate all existing connections to check what we need to do
  local line, err
  for i, connection in ipairs(readable_sockets) do
    print("handling: ")
    print(connection)
    print("server: ")
    print(server)
    if connection == server then
      print("hello")
      -- accept the incoming connection
      local new_connection = server:accept()
      new_connection:settimeout(0.2)
      table.insert(connections, new_connection)
    else
      -- read the incoming line
      line, err = receive_sanitized(connection)
      if not err then
        -- we have a start line, move on
        local response = process_incoming(connection, line)
        local should_close = send_response(connection, response)
        if should_close then close_connection(connections, connection) end
      elseif err == "closed" then
        -- clean shutdown connections
        close_connection(connections, connection)
      else
        -- reset connection
        print("error: " .. err)
        send_response(connection, code_400(RESPONSE_TEMPLATE, true))
        close_connection(connections, connection)
      end
    end
  end
end