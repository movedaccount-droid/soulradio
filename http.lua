require "uridecoder"
require "http_backend"
require "utils"
require "base64"
require "sha1"
local socket = require("socket")
local ltn12 = require("ltn12")


-- http.abnf: various rfc abnf matchers
http.abnf = {
  ["HTAB"] = "	",
  ["HTTP_VERSION"] = "HTTP/%d%.%d",
  ["HEXDIG"] = "%x",
  ["OBS_TEXT"] = "[€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ]",
  ["OWS"] = "[ 	]",
  ["TCHAR"] = "[%!%#%$%%%&%'%*%+%-%.%6%_%`%|%~%d%a]",
  ["VCHAR"] = "[%!%\"%#%$%%%&%'%(%)%*%+%,%-%.%/%w%:%;%<%=%>%?%@%[%\\%]%^%_%`%{%|%}%~]",
}

function http.abnf.combine(sets)

  local full_set = {"[", "]"}
  
  for set in sets do
    table.insert(full_set, 2, string.sub(set, 1, -1))
  end
  
  return table.concat(full_set)

end

function http.abnf.build_ascii(lower_bound, upper_bound)

  if lower_bound > upper_bound then
    local temp = lower_bound
    lower_bound = upper_bound
    upper_bound = temp
  end

  local set = {"[", "]"}
  local MAGIC_CHARACTERS <const> = "[%(%)%.%%%+%-%*%?%[%^%$]"

  for i=lower_bound,upper_bound do
    local char = string.char(i)
    if string.find(char, MAGIC_CHARACTERS) then table.insert(set, -2, "%") end
    table.insert(set, 2, string.char(i))
  end

  return table.concat(set)

end

http.abnf.BWS = http.abnf.OWS
http.abnf.CHUNK_EXT_NAME = http.abnf.TCHAR .. "+"
http.abnf.FIELD_NAME = http.abnf.CHUNK_EXT_NAME
http.abnf.FIELD_VCHAR = http.abnf.combine(table.pack(http.abnf.VCHAR, http.abnf.OBS_TEXT))
http.abnf.FIELD_CONTENT = http.abnf.FIELD_VCHAR .. "[]"
http.abnf.TOKEN = http.abnf.CHUNK_EXT_NAME
http.abnf.QDTEXT = http.abnf.combine({ http.abnf.HTAB, "[ ]", http.abnf.build_ascii(33, 39), http.abnf.build_ascii(42, 91), http.abnf.build_ascii(93, 126), http.abnf.OBS_TEXT })
http.abnf.QUOTED_PAIR = "\\" .. http.abnf.combine({ http.abnf.HTAB, "[ ]", http.abnf.VCHAR, http.abnf.OBS_TEXT })

-- each matcher returns:
-- if the string was a complete match for the matcher (i.e. result was "")
-- the string with any match stripped
-- the match
function http.abnf.matcher.FIELD_CONTENT(fc)
  local OPTIONAL_EXTENSION <const> = "[" .. http.abnf.combine(table.pack("[ 	]", http.abnf.FIELD_VCHAR .. "]+" .. http.abnf.FIELD_VCHAR))
  local mfc = string.gsub(fc, "^" .. http.abnf.FIELD_VCHAR, "", 1)
  local mfc = string.gsub(mfc, "^" .. OPTIONAL_EXTENSION, "", 1)
  return mfc == "", mfc
end

function http.abnf.matcher.FIELD_VALUE(fv)
  local buf = fv
  repeat 
  _, fv = http.abnf.matcher.FIELD_CONTENT(fv)
  until buf == fv
  return fv == "", fv
end

function http.abnf.matcher.QUOTED_STRING_END(qv)
  local INSIDE_QUOTES <const> = "\"(.-)\"$"
  local inner 
  local mqv = string.gsub(
    qv, INSIDE_QUOTES,
    function(m) inner = m; return "" end
  )

  if not inner then return false, qv end

  local i
  while i <= string.len(inner) do
    if string.find(string.sub(inner, i, i), http.abnf.QDTEXT) then
      i = i + 1
    elseif string.find(string.sub(inner, i, i+1), http.abnf.QUOTED_PAIR) then
      i = i + 2
    else
      return false, qv
    end
  end

  return mqv == "", mqv, inner

end


-- http.consts: constants for the lib
-- all headers MUST be able to be parsed as a list.
-- however, resolving lists is non-trivial. unique syntax each header field.
-- so far implemented:
http.consts.COMMA_SEPARATED_HEADERS = {["transfer-encoding"] = true, ["content-length"] = true}
http.packet_num = 0



-- http.field_line/field_lines: object to represent http message header groups [or field lines in general]
http.field_line = {}

function http.field_line:new(name, value)

  local fl = {
    ["name"] = name,
    ["value"] = value or nil
  }

  self.__index = self
  setmetatable(fl, self)
  return fl

end

function http.field_line:as_list()

  local list = {}
  local value = self.value
  local OPTIONAL_END_ELEMENT <const> = http.abnf.OWS .. "," .. http.abnf.OWS .. "(.-)$"  
  
  repeat
    table.insert(list, string.match(value, OPTIONAL_END_ELEMENT))
    value = string.gsub(value, OPTIONAL_END_ELEMENT, "")
  until list[#list] == nil

  list[#list] = value

  return value

end

http.field_lines = {}

function http.field_lines:new(headers)

  local fls = {
    ["headers"] = headers or {},
    ["headers_case_lookup"] = {}
  }

  for k, _ in pairs(headers) do
    fls:add_case_lookup(k)
  end

  self.__index = self
  self.__add = self.add
  setmetatable(fls, self)
  return fls
end

function http.field_lines:add_case_lookup(cased_header_name)
  self.headers_case_lookup[string.lower(cased_header_name)] = cased_header_name
end

function http.field_lines:get_case_lookup(cased_header_name)
  return self.headers_case_lookup[string.lower(cased_header_name)]
end

-- gets the header_name as field_line safely and case-insensitively
function http.field_lines:get(header_name)
  local cased = self.get_case_lookup(header_name)
  local value = self.headers[cased]
  if not cased or not value then return nil
  else return http.field_line:new(cased, value) end
end

-- appends the header to the list, overwriting if necessary
-- if a canon case has already been specified, it will not be changed
function http.field_lines:append(header)

  local header_name = self:get_case_lookup(header.name)
  if not header_name then
    self:add_case_lookup(header.name)
    header_name = header.name
  end

  self.headers[header_name] = header.value

end

-- combines field_lines, overwriting any existing in the headers already
function http.field_lines:append_lines(headers)
  for k, v in pairs(headers.headers) do
    self:set(k, v)
  end
end



-- http.response: extension of field_lines to represent http response data
http.response = http.field_lines:new()

function http.response:new(code, headers, body, close)
  local r = http.field_lines:new(headers)
  r.code = code
  r.body = body
  r.close = close or false
  -- TODO: this is where we should ubstantioate new headers for our response for anyhting that always needs them
  return r
end

function http.response:new_400()
  return self:new(400, { ["Connection"] = "close" }, nil, true)
end



-- http.e/r: rust Result<Result, Err> equivalent
http.e = {}

function http.e:new(response, err_string)
  return {
    ["string"] = err_string or "[!] unknown error occurred",
    ["response"] = response or nil,
    ["err"] = true
  }
end

http.r = {}

function http.r:new(result)
  if type(result) ~= "table" then result = table.pack(result) end
  local r = {
    ["result"] = result,
    ["err"] = false
  }
  self.__index = self
  setmetatable(r, self)
  return r
end

function http.r:unwrap()
  return table.unpack(self.result)
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


function process_incoming(client)

  local line = receive_sanitized(client)

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
      return http.response:new_400(response, true)
    end
    count = count + 1
    if count > 15 then
      print("crlf count passed 15 limit whilst receiving, aborting")
      return http.response:new_400(response, true)
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
    return http.response:new_400(response, true)
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
    return http.response:new_400(response, true)
  end

  -- determine how to read the body and its length
  local decode_method, body_length
  if headers["transfer-encoding"] ~= nil then

    -- close connection for deprecated clients
    -- STILL-TODO: this check later on
    if content_length_header ~= nil or protocol_version == "HTTP/1.0" then
      response["field"]["Connection"] = "close"
    end

    local final_encoding = transfer_encoding_header[#transfer_encoding_header]

    -- last encoding must always be chunked
    if final_encoding ~= "chunked" then
      print("last encoding was not chunked, aborting")
      return http.response:new_400(response, true)
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
          return http.response:new_400(response, true)
        end
      end
    end

    decode_method = "length"
    body_length = headers["content-length"][1]

  else body_length = 0 end


  -- persistence handling (9.3)
  -- STILL-TODO: why is this here same for continue
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
      return http.response:new_400(response, true)
    end

  elseif decode_method == "chunked" then

    -- read chunks
    body = ""
    body_length = 0

    local chunk_header, err = receive_sanitized(client)

    if err then
      print(err)
      return http.response:new_400(response, true)
    end

    local tokens = string.gmatch(chunk_header,"[^%s]+")
    local chunk_size, chunk_ext = tonumber(tokens()), tokens()
    
    -- 7.1.1 chunk extensions. we do not recognise any chunk extensions, so we ignore them.
    while chunk_size > 0 do
      -- need to offset chunk_size to account for additional \r\n
      local chunk_data, err = client:receive(chunk_size+2)
      if err then
        print(err)
        return http.response:new_400(response, true)
      end
      body = body .. string.sub(chunk_data,1,-3)
      body_length = body_length + chunk_size
      chunk_header, err = receive_sanitized(client)
      tokens = string.gmatch(chunk_header,"[^%s]+")
      chunk_size, chunk_ext = tonumber(tokens()), tokens()
      -- ignore extensions
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

    if headers["host"] ~= http_backend.config.host then
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
      local backend_response = http_backend.GET(target_uri["path"], headers)
      response = merge_response_message(backend_response, response)
    elseif method_token == "HEAD" then
      local backend_response = http_backend.HEAD(target_uri["path"], headers)
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

function http.handle_request(client)

  local request = http.read_request(client)
  if request.err then return http.build_server_response_from_error(request)
  else request = request:unwrap() end

  local response = http.build_response(request)

  send_response(client, response)
  if response["field"]["Connection"] == "close" then http.close_connection(client) end

end

function http.read_request(client)

  local request_result = http.read_parse_and_validate_request_line(client)
  local method_token, request_target, protocol_version
  if request_result.err then return request_result
  else method_token, request_target, protocol_version = request_result:unwrap() end

  -- headers are validated later when used
  local parsed_headers = http.read_and_parse_field_lines_until_crlf(client)
  if parsed_headers.err then return parsed_headers
  else parsed_headers = parsed_headers.unwrap() end

  -- parse request target now we have access to host
  request_target = http.parse_request_target(method_token, request_target, nil, parsed_headers:get("Host"))

  local transfer_encoding_header = parsed_headers:get("Transfer-Encoding")
  local content_length_header = parsed_headers:get("Content-Length")

  local body = http.read_body(client, transfer_encoding_header, content_length_header)
  if body.err then return body
  else body, transfer_encoding_header, content_length_header = body.unwrap() end

  parsed_headers:append(transfer_encoding_header)
  parsed_headers:append(content_length_header)

  -- return finished request
  parsed_headers.method_token = method_token
  parsed_headers.request_target = request_target
  parsed_headers.protocol_version = protocol_version
  parsed_headers.request_target = request_target
  parsed_headers.body = body

  return http.r:new(parsed_headers)

end

function http.read_parse_and_validate_request_line(socket)

  local raw_request_line = http.skip_crlf_and_receive_sanitized(socket)
  if raw_request_line.err then return raw_request_line
  else raw_request_line = raw_request_line:unwrap() end

  local parsed_request_line = http.parse_request_line(raw_request_line)
  local method_token, request_target, protocol_version
  if parsed_request_line.err then return parsed_request_line
  else method_token, request_target, protocol_version = parsed_request_line:unwrap() end

  if not http.validate_request_tokens(method_token, request_target, protocol_version)
  then return http.e:new(http.response:new_400(), "[?] WRN in http.read_parse_and_validate_request_line: found malformed request tokens") end

  return http.r:new(table.pack(method_token, request_target, protocol_version))

end

function http.skip_crlf_and_receive_sanitized(client)

  local line = receive_sanitized(client)
  local count = 0
  local err

  while line == "" do
    line, err = receive_sanitized(client)
    count = count + 1
    if err then
      return http.e:new(http.response:new_400(), "[?] WRN in http.skip_crlf_and_receive_sanitized: err during skipping crlf: " .. err)
    end
    if count > 15 then
      return http.e:new(http.response:new_400(), "[?] WRN in http.skip_crlf_and_receive_sanitized: crlf count passed 15 limit whilst receiving")
    end
  end

  return http.r:new(line)

end

function http.parse_request_line(raw_request_line)

  local CAPTURE <const> = "(.-) (.-) (.-)"
  local method_token, request_target, protocol_version = string.match(raw_request_line, CAPTURE)

  if not method_token or not request_target or not protocol_version then
    return http.e:new(http.response:new_400(), "[?] WRN in http.parse_request_line: found malformed request line")
  end

  return http.r:new(table.pack(method_token, request_target, protocol_version))

end

function http.validate_request_tokens(method_token, request_target, protocol_version)

  if not string.find(method_token, "^" .. http.abnf.TOKEN .. "$")
  or not uridecoder.match_http_request_target(request_target)
  or not string.find(protocol_version, "^" .. http.abnf.HTTP_VERSION .. "$")
  then return false end

end

function http.read_and_parse_field_lines_until_crlf(socket)

  local raw_headers = http.read_lines_until_crlf(socket, 256)
  if raw_headers.err then return raw_headers
  else raw_headers = raw_headers.unwrap() end

  local parsed_headers = http.parse_raw_field_lines(raw_headers)
  if parsed_headers.err then return parsed_headers
  else parsed_headers = parsed_headers.unwrap() end

  return parsed_headers

end

function http.parse_request_target(method_token, request_target, fixed_uri_scheme, host_header)

  -- determine uri form
  local uri = {}
  if uridecoder.match_http_origin_form(request_target) then uri["uri_form"] = "origin-form"
  elseif uridecoder.match_http_authority_form(request_target) and method_token == "CONNECT" then uri["uri_form"] = "authority-form"
  elseif uridecoder.match_http_absolute_form(request_target) then uri["uri_form"] = "absolute-form"
  elseif uridecoder.match_http_asterisk_form(request_target) then uri["uri_form"] = "asterisk-form"
  else return http.e:new(http.response:new_400(), "[?] WRN in http.parse_request_target: target uri failed to match any known format during reconstruction")
  end

  -- parse generic components and return early for absolute-form
  if uri["uri_form"] == "absolute-form" then
    uri["target"] = request_target
    _, uri["authority"], uri["scheme"], uri["path"], uri["query"] = uridecoder.match_http_absolute_form(request_target)
    if uri["query"] then uri["combined_path_and_query_component"] = uri["path"] .. uri["query"]
    else uri["combined_path_and_query_component"] = uri["path"] end
    return http.r:new(uri)
  end

  -- determine scheme
  if fixed_uri_scheme ~= nil then uri["scheme"] = fixed_uri_scheme
  else uri["scheme"] = "http" end -- no implementation for https -> no check

  -- determine authority
  -- TODO: shouold lwe readlly be checking this here and not generically validayting needed headers  earlier?
  if not host_header then return http.e:new(http.response:new_400(), "[?] WRN in http.parse_request_target: did not find host field whilst determining authority") end

  if uri["uri_form"] == "authority-form" then uri["authority"] = request_target
  elseif uridecoder.match_http_uri_host(host_header.value) then uri["authority"] = host_header.value
  else return http.e:new(http.response:new_400(), "[?] WRN in http.parse_request_target: request message featured invalid host header field line") end

  -- check authority against scheme for compliance
  if uri["authority"] == "" and uri["scheme"] == "http" then return http.e:new(http.response:new_400(), "[?] WRN in http.parse_request_target: request target uri authority empty when uri scheme required non-empty authority") end
  
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

  return http.r:new(uri)
end

function http.read_lines_until_crlf(client, max_before_error)

  local line, err = receive_sanitized(client)
  if err then return http.e:new(http.response:new_400(), "[?] WRN in http.read_field_lines_until_crlf: failed to read next field line") end

  local lines
  local count = 0
  while not line == "" do

    table.insert(lines, line)
    line, err = receive_sanitized(client)

    if count > max_before_error then return http.e:new(http.response:new_400(), "[?] WRN in http.read_field_lines_until_crlf: received over max field lines of count " .. max_before_error) end
    count = count + 1

  end

  return http.r:new(lines)

end

function http.parse_raw_field_lines(field_lines)

  -- unfold lines
  local unfolded_lines = http.unfold_field_lines(field_lines)
  if unfolded_lines.err then return unfolded_lines else unfolded_lines = unfolded_lines:unwrap() end

  -- parse

  local parsed_lines = http.parse_field_lines(unfolded_lines)
  if parsed_lines.err then return parsed_lines else return parsed_lines:unwrap() end

end

function http.unfold_field_lines(field_lines)

  local unfolded_lines, buffer = {}, {}
  local STARTING_WHITESPACE <const> = "^" .. http.abnf.OWS

  for line in field_lines do

    -- check if line should be folded
    if string.find(line, STARTING_WHITESPACE) then

      if buffer == {} then return http.e:new(http.response:new_400(), "[?] WRN in http.unfold_field_lines: found folded line whilst buffer was empty")
      else table.insert(buffer, (string.gsub(line, STARTING_WHITESPACE, " "))) end
    
    else

      if buffer ~= {} then table.insert(unfolded_lines, table.concat(buffer)) end
      buffer = { line }

    end

  end

  return unfolded_lines

end

function http.parse_field_lines(field_lines)

  local parsed_lines = http.field_lines:new()

  for line in field_lines do
    local parsed_line = http.parse_field_line(line)
    if parsed_line.err then
      return parsed_line
    else 
      parsed_lines:append(parsed_line:unwrap())
    end
  end

  return http.r:new(parsed_lines)

end

function http.parse_field_line(field_line)

  local FIELD_LINE <const> = "^(" .. http.abnf.FIELD_NAME .. "):" .. http.abnf.OWS .. "(.*)" .. http.abnf.OWS .. "$"
  local field_name, field_value = string.match(field_line, FIELD_LINE)

  if not field_name or not http.abnf.matcher.FIELD_VALUE(field_value)
  then return http.e:new(http.response:new_400(), "[?] WRN in http.parse_field_line: found malformed field line") end

  return http.r:new(http.field_line:new(field_name, field_value))

end

function http.read_body(socket, transfer_encoding_header, content_length_header)

  local body_info = http.determine_body_info(transfer_encoding_header, content_length_header)
  local decode_method, body_length
  if body_info.err then return body_info
  else decode_method, body_length = body_info.unwrap() end

  local body
  if decode_method == "Content-Length" then

    body = http.read_length(socket, body_length)
    if body.err then return body
    else body = body:unwrap() end

  elseif decode_method == "Chunked" then

    body = http.read_chunked(socket)
    if body.err then return body
    else
      -- discard trailers at this point
      body, _, body_length = body:unwrap()

      local transfer_encoding_list = transfer_encoding_header:as_list()
      table.remove(transfer_encoding_list, -1)
      transfer_encoding_header.value = table.concat(transfer_encoding_list, ", ")

      content_length_header.value = body_length

    end

  else body = nil end

  return http.r:new(table.pack(body, transfer_encoding_header, content_length_header))

end

function http.determine_body_info(transfer_encoding, content_length)

  local decode_method, body_length

  if transfer_encoding.value ~= nil then

    if not http.check_all_encodings_recognized(transfer_encoding)
    then return http.e:new(http.response:new(501), "[?] WRN in http.determine_body_info: found unrecognised encoding of type " .. v)
    else return http.r:new(table.pack("Chunked", nil)) end
    
  elseif content_length.value ~= nil then

    -- perform list validity check (6.3)
    local content_length_list = content_length:as_list()
    if not http.list_elements_all_identical(content_length_list)
    then return http.e:new(http.response:new_400(), "[?] WRN in http.determine_body_info: found discordant value in content_length list") end

    local body_length = tonumber(content_length_list[1])

    if not body_length then return http.e:new(http.response:new_400(), "[?] WRN in http.determine_body_info: found non-numeric content-length")
    else return http.r:new(table.pack("Content-Length", body_length)) end

  else return http.r:new(table.pack("None", 0)) end

end

function http.check_all_encodings_recognized(transfer_encoding)
  -- we should separately check last_encoding == "chunked"
  -- and for any unrecognised encodings. but we only recognise
  -- chunked, so we don't need to bother

  for i, v in ipairs(transfer_encoding:as_list()) do
    if v:lower() ~= "chunked" then
      return false
    end
  end
  return true
end

function http.list_elements_all_identical(list)
  if list == {} then return true end
  local base = list[1]
  for _, element in ipairs(list) do
    if element ~= base then return false end
  end
  return true
end

function http.read_length(socket, length)

  local data, err = socket:receive(length)
    
  if err or body:len() ~= length then
    return http.e:new(http.response:new_400(), "[?] WRN in http.read_length: failed to read a correctly-lengthed body")
  end

  return http.r:new(data)

end

function http.read_chunked(socket)

  local content_length = 0
  local content = {}

  local raw_chunk_header, err = receive_sanitized(socket)
  if err then return http.e:new(http.response:new_400(), "[?] WRN in http.read_chunked: failed to read chunk header from socket") end

  -- we define chunk_exts, but currently never use them...
  local parse_result = http.parse_and_validate_raw_chunk_header(raw_chunk_header)
  local chunk_size, chunk_exts
  if parse_result.err then return parse_result
  else chunk_size, chunk_exts = parse_result:unwrap() end

  while chunk_size > 0 do
    
    local chunk_data, err = socket:receive(chunk_size)
    if err then return http.e:new(http.response:new_400(), "[?] WRN in http.read_chunked: failed to read chunk data from socket") end
    
    -- skip crlf
    local _, err = socket:receive(4)
    if err then return http.e:new(http.response:new_400(), "[?] WRN in http.read_chunked: failed to read chunk data crlf from socket") end
  
    table.insert(content, chunk_data)
    content_length = content_length + chunk_size

    local raw_chunk_header, err = receive_sanitized(socket)
    if err then return http.e:new(http.response:new_400(), "[?] WRN in http.read_chunked: failed to read chunk header from socket") end
  
    parse_result = http.parse_and_validate_raw_chunk_header(raw_chunk_header)
    if parse_result.err then return parse_result
    else chunk_size, chunk_exts = parse_result:unwrap() end

  end

  local trailer_fields = http.read_and_parse_field_lines_until_crlf(client)
  if trailer_fields.err then return trailer_fields
  else trailer_fields = trailer_fields.unwrap() end

  local content = table.concat(content)
  return http.r:new(table.pack(content, trailer_fields, content_length))

end

function http.parse_and_validate_raw_chunk_header(raw_chunk_header)

  local parse_chunk_result = http.parse_chunk_ext(raw_chunk_header)
  local chunk_exts
  if parse_chunk_result.err then return parse_chunk_result
  else raw_chunk_header, chunk_exts = parse_chunk_result:unwrap() end

  local HEXNUM = http.abnf.HEXDIG .. "+"
  local chunk_size = tonumber(string.match(raw_chunk_header, HEXNUM))

  if not chunk_size then return http.e:new(http.response:new_400(), "[?] WRN in http.parse_and_validate_raw_chunk_header: found chunk with no attached size") end

  return http.r:new(table.pack(chunk_size, chunk_exts))

end

function http.parse_chunk_ext(raw_chunk_header)

  local chunk_exts = {}

  repeat

    local chunk_ext_name, chunk_ext_val

    raw_chunk_header, chunk_ext_val = http.parse_chunk_ext_val(raw_chunk_header)
    raw_chunk_header, chunk_ext_name = http.parse_chunk_ext_name(raw_chunk_header)

    if chunk_ext_val and not chunk_ext_name then
      return http.e:new(http.response:new_400(), "[?] WRN in http.strip_chunk_ext: did not find chunk ext name in chunk")
    elseif chunk_ext_val and chunk_ext_name then
      table.insert(chunk_exts, { ["name"] = chunk_ext_name, ["value"] = chunk_ext_val } )
    end

  until chunk_ext_name == nil

  return http.r:new(table.pack(raw_chunk_header, chunk_exts))

end

function http.parse_chunk_ext_val(raw_chunk_header)

  local _, raw_chunk_header, chunk_ext_val = http.abnf.matcher.QUOTED_STRING_END(raw_chunk_header)
    
  if not chunk_ext_val then
    raw_chunk_header = string.gsub(
      raw_chunk_header, http.abnf.TOKEN .. "$",
      function(m) chunk_ext_val = m; return "" end
    )
  end

  if chunk_ext_val then
    local CHUNK_EXT_VAL_SPACER <const> = http.abnf.BWS .. "%=" .. http.abnf.BWS
    raw_chunk_header = string.gsub(raw_chunk_header, CHUNK_EXT_VAL_SPACER, "")
  end

  return raw_chunk_header, chunk_ext_val

end

function http.parse_chunk_ext_name(raw_chunk_header)

  local CHUNK_EXT_NAME_SEGMENT <const> = http.abnf.BWS .. ";" .. http.abnf.BWS .. "(" .. http.abnf.CHUNK_EXT_NAME .. ")" .. "$"
  local chunk_ext_name
  raw_chunk_header = string.gsub(
    raw_chunk_header, CHUNK_EXT_NAME_SEGMENT,
    function(m) chunk_ext_name = m; return "" end
  )

  return raw_chunk_header, chunk_ext_name

end

function http.build_server_response_from_error(request)

  print(request.string)
  return { ["response"] = request.response, ["flood"] = false, ["close"] = true }

end

function http.build_response(request)


  return { ["response"] = request.response, ["flood"] = false, ["close"] = true }

end
