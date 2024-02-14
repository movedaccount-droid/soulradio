-- http: http message handler for lua-server-lplp
require "uridecoder"
require "http_backend"
require "base64"
require "sha1"

http = {}

-- http.abnf: various rfc abnf matchers
http.abnf = {
  ["HTAB"] = "	",
  ["HTTP_VERSION"] = "HTTP/%d%.%d",
  ["HEXDIG"] = "%x",
  ["OBS_TEXT"] = "[€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ]",
  ["RWS"] = "[ 	]",
  ["TCHAR"] = "[%!%#%$%%%&%'%*%+%-%.%6%_%`%|%~%d%a]",
  ["VCHAR"] = "[%!%\"%#%$%%%&%'%(%)%*%+%,%-%.%/%w%:%;%<%=%>%?%@%[%\\%]%^%_%`%{%|%}%~]",
}

function http.abnf.combine(sets)

  local full_set = {"[", "]"}
  
  for _, set in ipairs(sets) do
    table.insert(full_set, 2, string.sub(set, 2, -2))
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
    if string.find(char, MAGIC_CHARACTERS) then table.insert(set, #set - 1, "%") end
    table.insert(set, 2, string.char(i))
  end

  return table.concat(set)

end

http.abnf.BWS = http.abnf.RWS .. "?"
http.abnf.CHUNK_EXT_NAME = http.abnf.TCHAR .. "+"
http.abnf.FIELD_NAME = http.abnf.CHUNK_EXT_NAME
http.abnf.FIELD_VCHAR = http.abnf.combine({ http.abnf.VCHAR, http.abnf.OBS_TEXT })
http.abnf.OWS = http.abnf.BWS
http.abnf.QDTEXT = http.abnf.combine({ "[" .. http.abnf.HTAB .. "]", "[ ]", http.abnf.build_ascii(33, 39), http.abnf.build_ascii(42, 91), http.abnf.build_ascii(93, 126), http.abnf.OBS_TEXT })
http.abnf.QUOTED_PAIR = "\\" .. http.abnf.combine({ "[" .. http.abnf.HTAB .. "]", "[ ]", http.abnf.VCHAR, http.abnf.OBS_TEXT })
http.abnf.TOKEN = http.abnf.CHUNK_EXT_NAME

-- each matcher returns:
-- if the string was a complete match for the matcher (i.e. result was "")
-- the string with any match stripped
-- the match
http.abnf.matcher = {}

function http.abnf.matcher.FIELD_CONTENT(fc)
  local ENDS_WITH_VCHAR <const> = http.abnf.combine({ "[ ]", "[" .. http.abnf.HTAB .. "]", http.abnf.FIELD_VCHAR }) .. "+" .. http.abnf.FIELD_VCHAR .. "$"
  local mfc, count = string.gsub(fc, "^" .. http.abnf.FIELD_VCHAR, "", 1)
  local mfc = string.gsub(mfc, "^" .. ENDS_WITH_VCHAR, "", 1)
  return count > 0, mfc
end

function http.abnf.matcher.FIELD_VALUE(fv)
  repeat 
  local buf = fv
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



-- http.consts: generic constants
http.consts = {}

http.consts.status_text_lookup = {
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

  self.__index = self
  self.__add = self.add
  setmetatable(fls, self)

  if headers ~= nil then
    for k, _ in pairs(headers) do
      fls:add_case_lookup(k)
    end
  end

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
  local cased = self:get_case_lookup(header_name)
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

function http.response:new(code, headers, body, close, upgrade)

  if not headers then headers = http.field_lines:new() end

  headers.code = code
  headers.body = body
  headers.close = close or false
  headers.upgrade = upgrade

  self.__index = self
  setmetatable(headers, self)

  return headers

end

function http.response:new_400(close)
  local headers
  if close then headers = http.field_lines:new({ ["Connection"] = "close" }) end
  return self:new(400, headers, nil, close)
end

function http.response:serialize()

  -- set encoding early so we have headers ready for later
  if self.body then
    self:set_body_encoding()
  end

  local serialized_pieces = {}

  table.insert(serialized_pieces, self:serialize_response_line())
  table.insert(serialized_pieces, self:serialize_field_lines())
  table.insert(serialized_pieces, "")

  if self.body then
    table.insert(serialized_pieces, self:serialize_body())
  else
    table.insert(serialized_pieces, "")
  end

  return table.concat(serialized_pieces, "\r\n")

end

function http.response:set_body_encoding()

  if string.len(self.body) > 1024 then
    self:append(http.field_line:new("Transfer-Encoding", "chunked"))
  else
    self:append(http.field_line:new("Content-Length", string.len(self.body)))
  end

end

function http.response:serialize_response_line()
  return "HTTP/1.1 " .. self.code .. " " .. http.consts.status_text_lookup[self.code]
end

function http.response:serialize_field_lines()

  local serialized_field_lines = {}

  for k, v in pairs(self.headers) do
    table.insert(serialized_field_lines, k .. ": " .. v)
  end

  return table.concat(serialized_field_lines, "\r\n")

end

function http.response:serialize_body()

  local transfer_encoding_header = self:get("Transfer-Encoding")

  if transfer_encoding_header and transfer_encoding_header.value == "chunked" then
    return self:serialize_body_chunked()
  else
    return self.body
  end

end

function http.response:serialize_body_chunked()

  local chunks = {}
  local CHUNK_SIZE <const> = 1024
  local index = 1

  while index < self.body:len() do
    
    local chunk = string.sub(self.body, index, index + CHUNK_SIZE - 1)
    local chunk_size = string.format("%x", chunk:len())

    table.insert(chunks, chunk_size)
    table.insert(chunks, chunk)

    index = index + CHUNK_SIZE

  end

  -- tail blank chunk of length 0
  table.insert(chunks, "0")
  table.insert(chunks, "")
  table.insert(chunks, "")

  return table.concat(chunks, "\r\n")

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
  local r = {
    ["result"] = result,
    ["err"] = false
  }
  self.__index = self
  setmetatable(r, self)
  return r
end

function http.r:unwrap()
  return self.result
end

function http.r:unpack()
  return table.unpack(self.result)
end



-- http: main serving and message handling capabilities
function http.incoming(client)

  local request = http.read_request(client)
  if request.err then
    print(request.string)
    return http.build_server_response(request.response)
  else request = request:unwrap() end

  local response = http.build_response(request)

  return http.build_server_response(response)

end

function http.read_request(client)

  local request_result = http.read_parse_and_validate_request_line(client)
  local method_token, request_target, protocol_version
  if request_result.err then return request_result
  else method_token, request_target, protocol_version = request_result:unpack() end

  -- headers are validated later when used
  local parsed_headers = http.read_and_parse_field_lines_until_crlf(client)
  if parsed_headers.err then return parsed_headers
  else parsed_headers = parsed_headers:unwrap() end

  -- parse request target now we have access to host
  request_target = http.parse_request_target(method_token, request_target, nil, parsed_headers:get("Host"))
  if request_target.err then return request_target
  else request_target = request_target:unwrap() end

  if parsed_headers:get("Expect") == "100-continue" then http.send_continue(client) end

  local transfer_encoding_header = parsed_headers:get("Transfer-Encoding")
  local content_length_header = parsed_headers:get("Content-Length")

  -- OLD-TODO: handle incomp.ete messages (8)
  local body = http.read_body(client, transfer_encoding_header)
  if body.err then return body
  else body, transfer_encoding_header = body:unpack() end

  if transfer_encoding_header then parsed_headers:append(transfer_encoding_header) end

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
  else method_token, request_target, protocol_version = parsed_request_line:unpack() end

  if not http.validate_request_tokens(method_token, request_target, protocol_version)
  then return http.e:new(http.response:new_400(true), "[?] WRN in http.read_parse_and_validate_request_line: found malformed request tokens") end

  return http.r:new(table.pack(method_token, request_target, protocol_version))

end

function http.skip_crlf_and_receive_sanitized(client)

  local line = http.receive_sanitized(client)
  local count = 0
  local err

  while line == nil or line == "" do

    line, err = http.receive_sanitized(client)
    count = count + 1
    if err then
      return http.e:new(http.response:new_400(true), "[?] WRN in http.skip_crlf_and_receive_sanitized: err during skipping crlf: " .. err)
    end
    if count > 15 then
      return http.e:new(http.response:new_400(true), "[?] WRN in http.skip_crlf_and_receive_sanitized: crlf count passed 15 limit whilst receiving")
    end
  end

  return http.r:new(line)

end

function http.receive_sanitized(client, receive_argument)
  local BARE_CR <const> = "\r(?!\n)"
  local line, err = client:receive(receive_argument)
  if not err then line = string.gsub(line, BARE_CR, " ") end
  return line, err
end

function http.parse_request_line(raw_request_line)

  local SPLIT_ON_SPACES <const> = "^(.-) (.-) (.-)$"
  print("reqlkiine", raw_request_line)
  local method_token, request_target, protocol_version = string.match(raw_request_line, SPLIT_ON_SPACES)

  if not method_token or not request_target or not protocol_version then
    return http.e:new(http.response:new_400(true), "[?] WRN in http.parse_request_line: found malformed request line")
  end

  return http.r:new(table.pack(method_token, request_target, protocol_version))

end

function http.validate_request_tokens(method_token, request_target, protocol_version)

  return string.find(method_token, "^" .. http.abnf.TOKEN .. "$")
  and uridecoder.match_http_request_target(request_target)
  and string.find(protocol_version, "^" .. http.abnf.HTTP_VERSION .. "$")

end

function http.read_and_parse_field_lines_until_crlf(socket)

  local raw_headers = http.read_lines_until_crlf(socket, 256)
  if raw_headers.err then return raw_headers
  else raw_headers = raw_headers:unwrap() end

  return http.parse_raw_field_lines(raw_headers)

end

function http.parse_request_target(method_token, request_target, fixed_uri_scheme, host_header)

  -- determine uri form
  local uri = {}
  if uridecoder.match_http_origin_form(request_target) then uri["uri_form"] = "origin-form"
  elseif uridecoder.match_http_authority_form(request_target) and method_token == "CONNECT" then uri["uri_form"] = "authority-form"
  elseif uridecoder.match_http_absolute_form(request_target) then uri["uri_form"] = "absolute-form"
  elseif uridecoder.match_http_asterisk_form(request_target) then uri["uri_form"] = "asterisk-form"
  else return http.e:new(http.response:new_400(true), "[?] WRN in http.parse_request_target: target uri failed to match any known format during reconstruction")
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
  if not host_header then return http.e:new(http.response:new_400(true), "[?] WRN in http.parse_request_target: did not find host field whilst determining authority") end

  if uri["uri_form"] == "authority-form" then uri["authority"] = request_target
  elseif uridecoder.match_http_uri_host(host_header.value) then uri["authority"] = host_header.value
  else return http.e:new(http.response:new_400(true), "[?] WRN in http.parse_request_target: request message featured invalid host header field line") end

  -- check authority against scheme for compliance
  if uri["authority"] == "" and uri["scheme"] == "http" then return http.e:new(http.response:new_400(true), "[?] WRN in http.parse_request_target: request target uri authority empty when uri scheme required non-empty authority") end
  
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

  local line, err = http.receive_sanitized(client)
  if err then return http.e:new(http.response:new_400(true), "[?] WRN in http.read_field_lines_until_crlf: failed to read first field line") end

  local lines = {}
  local count = 0
  while not (line == "") do
    
    table.insert(lines, line)
    line, err = http.receive_sanitized(client)
    if err then return http.e:new(http.response:new_400(true), "[?] WRN in http.read_field_lines_until_crlf: failed to read next field line") end

    if count > max_before_error then return http.e:new(http.response:new_400(true), "[?] WRN in http.read_field_lines_until_crlf: received over max field lines of count " .. max_before_error) end
    count = count + 1

  end

  return http.r:new(lines, true)

end

function http.parse_raw_field_lines(field_lines)

  local unfolded_lines = http.unfold_field_lines(field_lines)
  if unfolded_lines.err then return unfolded_lines else unfolded_lines = unfolded_lines:unwrap() end

  local parsed_lines = http.parse_field_lines(unfolded_lines)
  if parsed_lines.err then return parsed_lines else return parsed_lines end

end

function http.unfold_field_lines(field_lines)

  local unfolded_lines, buffer = {}, {}
  -- match on RWS, so we know that it *is* a folded line
  local STARTING_WHITESPACE <const> = "^" .. http.abnf.RWS

  for _, line in ipairs(field_lines) do

    -- check if line should be folded
    if string.find(line, STARTING_WHITESPACE) then

      if #buffer ~= 0 then return http.e:new(http.response:new_400(true), "[?] WRN in http.unfold_field_lines: found folded line whilst buffer was empty")
      else table.insert(buffer, (string.gsub(line, STARTING_WHITESPACE, " "))) end
    
    else

      if #buffer ~= 0 then table.insert(unfolded_lines, table.concat(buffer)) end
      buffer = { line }

    end

  end

  return http.r:new(unfolded_lines)

end

function http.parse_field_lines(field_lines)

  local parsed_lines = http.field_lines:new()

  for _, line in ipairs(field_lines) do
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
  then return http.e:new(http.response:new_400(true), "[?] WRN in http.parse_field_line: found malformed field line") end

  return http.r:new(http.field_line:new(field_name, field_value))

end

function http.send_continue(socket)

  local continue_response = http.response:new(100)
  
  -- not hacky or fucked. trust me#
  server.oneshot(socket, continue_response:serialize())

end

function http.read_body(socket, transfer_encoding_header, content_length_header)

  local body_info = http.determine_body_info(transfer_encoding_header, content_length_header)
  local decode_method, body_length
  if body_info.err then return body_info
  else decode_method, body_length = body_info:unpack() end

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
      body, _, body_length = body:unpack()

      local transfer_encoding_list = transfer_encoding_header:as_list()
      table.remove(transfer_encoding_list, -1)
      transfer_encoding_header.value = table.concat(transfer_encoding_list, ", ")

      -- we SHOULD set the Content-Length header to this value for later
      -- but it's not useful for any reason, and it just gets in our way later
      -- when validating if Transfer-Encoding and Content-Length were set at once
      -- content_length_header.value = body_length

    end

  else body = nil end

  return http.r:new(table.pack(body, transfer_encoding_header))

end

function http.determine_body_info(transfer_encoding, content_length)

  local decode_method, body_length

  if transfer_encoding ~= nil then

    if not http.check_all_encodings_recognized(transfer_encoding)
    then return http.e:new(http.response:new(501), "[?] WRN in http.determine_body_info: found unrecognised encoding")
    else return http.r:new(table.pack("Chunked", nil)) end
    
  elseif content_length ~= nil then

    -- perform list validity check (6.3)
    local content_length_list = content_length:as_list()
    if not http.list_elements_all_identical(content_length_list)
    then return http.e:new(http.response:new_400(true), "[?] WRN in http.determine_body_info: found discordant value in content_length list") end

    local body_length = tonumber(content_length_list[1])

    if not body_length then return http.e:new(http.response:new_400(true), "[?] WRN in http.determine_body_info: found non-numeric content-length")
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
    return http.e:new(http.response:new_400(true), "[?] WRN in http.read_length: failed to read a correctly-lengthed body")
  end

  return http.r:new(data)

end

function http.read_chunked(socket)

  local content_length = 0
  local content = {}

  local raw_chunk_header, err = http.receive_sanitized(socket)
  if err then return http.e:new(http.response:new_400(true), "[?] WRN in http.read_chunked: failed to read chunk header from socket") end

  -- we define chunk_exts, but currently never use them...
  local parse_result = http.parse_and_validate_raw_chunk_header(raw_chunk_header)
  local chunk_size, chunk_exts
  if parse_result.err then return parse_result
  else chunk_size, chunk_exts = parse_result:unwrap() end

  while chunk_size > 0 do
    
    local chunk_data, err = socket:receive(chunk_size)
    if err then return http.e:new(http.response:new_400(true), "[?] WRN in http.read_chunked: failed to read chunk data from socket") end
    
    -- skip crlf
    local _, err = socket:receive(4)
    if err then return http.e:new(http.response:new_400(true), "[?] WRN in http.read_chunked: failed to read chunk data crlf from socket") end
  
    table.insert(content, chunk_data)
    content_length = content_length + chunk_size

    local raw_chunk_header, err = http.receive_sanitized(socket)
    if err then return http.e:new(http.response:new_400(true), "[?] WRN in http.read_chunked: failed to read chunk header from socket") end
  
    parse_result = http.parse_and_validate_raw_chunk_header(raw_chunk_header)
    if parse_result.err then return parse_result
    else chunk_size, chunk_exts = parse_result:unwrap() end

  end

  local trailer_fields = http.read_and_parse_field_lines_until_crlf(socket)
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

  if not chunk_size then return http.e:new(http.response:new_400(true), "[?] WRN in http.parse_and_validate_raw_chunk_header: found chunk with no attached size") end

  return http.r:new(table.pack(chunk_size, chunk_exts))

end

function http.parse_chunk_ext(raw_chunk_header)

  local chunk_exts = {}

  repeat

    local chunk_ext_name, chunk_ext_val

    raw_chunk_header, chunk_ext_val = http.parse_chunk_ext_val(raw_chunk_header)
    raw_chunk_header, chunk_ext_name = http.parse_chunk_ext_name(raw_chunk_header)

    if chunk_ext_val and not chunk_ext_name then
      return http.e:new(http.response:new_400(true), "[?] WRN in http.strip_chunk_ext: did not find chunk ext name in chunk")
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

function http.build_response(request)

  local response_base = http.get_response_base(request)

  local response = http.append_success_headers(request, response_base)

  return response

end

function http.get_response_base(request)

  -- determine response code
  if http.is_websocket_upgrade(request:get("Upgrade")) then

    return http.build_websocket_response(
      request.protocol_version,
      request:get("Host"),
      request:get("Sec-WebSocket-Key"),
      request:get("Sec-WebSocket-Version")
    )

  end

  if request.method_token == "GET" then
    -- TODO: update backend to take requests instead of headers and use e/r instead of nil, err
    return http_backend.GET(request)
  end

  if request.method_token == "HEAD" then
    return http_backend.HEAD(request)
  end

  return http.response:new(501) -- not implemented

end

function http.is_websocket_upgrade(upgrade_header)

  if not upgrade_header then return false end

  return string.lower(upgrade_header.value) == "websocket"

end

function http.build_websocket_response(protocol_version, host_header, sec_websocket_key_header, sec_websocket_version_header)

  if protocol_version ~= "HTTP/1.1"
  or host_header == nil
  or sec_websocket_version_header == nil
  or sec_websocket_key_header == nil
  or host_header.value ~= http.config.host
  then
    return http.response:new_400()
  end

  local decoded_sec_websocket_key = base64.decode(sec_websocket_key_header.value)
  if decoded_sec_websocket_key:len() ~= 16 then
    return http.response:new_400()
  end

  if sec_websocket_version_header.value ~= "13" then
    return http.response:new(
      426,
      http.field_lines:new({ ["Sec-WebSocket-Version"] = 13 })
    )
  end

  -- TODO: resource names, extensions, subprotocols. we do not necessarily have to  do this for our task
  return http.response:new(
    101,
    http.field_lines:new({
      ["Upgrade"] = "websocket",
      ["Connection"] = "Upgrade",
      ["Sec-WebSocket-Accept"] = http.calculate_sec_websocket_accept(sec_websocket_key_header.value)
    }),
    nil, false, "websocket"
  )

end

function http.calculate_sec_websocket_accept(sec_websocket_key_value)

  local NOTHING_UP_MY_SLEEVE_UUID <const> = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  print("concat value", sec_websocket_key_value .. NOTHING_UP_MY_SLEEVE_UUID)
  print("hashed value", sha1.calculate(sec_websocket_key_value .. NOTHING_UP_MY_SLEEVE_UUID))
    
  return base64.encode(sha1.calculate(sec_websocket_key_value .. NOTHING_UP_MY_SLEEVE_UUID))

end

-- appends headers that can only be appended to successfully read requests
function http.append_success_headers(request, response_base)

  local transfer_encoding_close = (request:get("Transfer-Encoding") ~= nil and
                                  (request:get("Content-Length") ~= nil or
                                  request.protocol_version == "HTTP/1.0"))

  local client_header_close = request:get("Connection") == "close"

  local protocol_can_persist = (request.protocol_version == "HTTP/1.1") or
                               (request.protocol_version == "HTTP/1.0" and request:get("Connection") == "keep-alive")

  if transfer_encoding_close or client_header_close or not protocol_can_persist then
    response_base:append(http.field_line:new("Connection", "close"))
    response_base.close = true
  end

  return response_base

end

function http.build_server_response(response)

  http.append_universal_headers(response)
  
  local serialized_response = response:serialize()

  return {
    ["response"] = serialized_response,
    ["flood"] = false,
    ["close"] = response.close,
    ["upgrade"] = response.upgrade
  }

end

-- appends headers that can be appended to any reponse, regardless of if we saw the request
function http.append_universal_headers(response)

  local http_date = os.date("!%a, %d %b %Y %H:%M:%S GMT")
  response:append(http.field_line:new("Date", http_date))

  response:append(http.field_line:new("Server", "lua-server-lplp/1.0"))

  -- suggests server can provide chunked
  if not response:get("Transfer-Encoding") then
    response:append(http.field_line:new("Transfer-Encoding", ""))
  end

  -- suggests server is keeping connection alive
  if not response:get("Connection") then
    response:append(http.field_line:new("Connection", ""))
  end

  if http_backend.consts.implemented.range_requests then
    response:append(http.field_line:new("Accept-Ranges", "bytes"))
  end

end

