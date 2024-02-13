-- rfc-compliant http/websocket server, pure lua + luasocket socket objects only

-- useful links:
-- implementation steps, https://stackoverflow.com/questions/176409/build-a-simple-http-server-in-c
-- http made really easy, https://www.jmarshall.com/easy/http/
-- http rfc, https://datatracker.ietf.org/doc/html/rfc9112#line.folding

package.path = "../?.lua;" .. package.path

require "http"
require "websocket"

local socket = require("socket")
local ltn12 = require("ltn12")

server = {}
server.connections = {}

function server.accept_connection(open_server)

  print("[.] accepting new client connection")
  local connection = open_server:accept()
  -- TODO: move config parsing
  connection:settimeout(server.config.timeout)
  connection:setoption('keepalive', true)
  table.insert(server.connections, connection)
  -- TODO: configurable default
  server.connection_protocol_lookup[connection] = "http"

end

-- TODO: implement 9.5 graceful timeouts

function server.open_server(host, port)

  print("[.] opening server on port " .. port)
  local opened_server, err = socket.bind(host, port)

  opened_server:settimeout(server.config.timeout)

  return opened_server, err

end

-- TODO: tnhis is not how you shut down properly
function server.close_connection(connection)

  for i, open_connection in ipairs(server.connections) do

    if open_connection == connection then
      connection:shutdown()
      server.connections[i] = nil
    end

  end

end

-- TODO: this might not work this way. might have to store bytes hopefully not
function server.clean_connections()

  print("[.] cleaning connections...")

  for i, connection in ipairs(server.connections) do

    if not server.connection_protocol_lookup[connect] == "server" then
      local _, err = connection:receive(0)
      if err then 
        print("[.] cleaning connection due to unnoticed closure")
        server.close_connection(connection)
      end
    end

  end

end

-- handles the main response from a backend
function server.handle_response(client, response)

  if response.upgrade then
    server.connection_protocol_lookup[client] = response.upgrade
  end

  server.oneshot(client, response)

  if response.close then
    server.close_connection(client)
  end

end

-- handles any additional mid-process oneshot responses a backend wishes to send
function server.oneshot(client, response)

  local source = ltn12.source.string(response.response)
  local sink, err

  if response.flood then
    for _, s in server.connections do
      sink = socket.sink("keep-open", s)
      _, err = ltn12.pump.all(source, sink)
      if err then print("[.] could not flood response to client...") end
    end
  else
    sink = socket.sink("keep-open", client)
    _, err = ltn12.pump.all(source, sink)
    if err then print("[?] WRN in server.handle_response: could not send response to client") end
  end

end

function server.read_conf(conf_path)
  
  local read_as_number_lookup = {
    ["timeout"] = true,
    ["garbage_collection_cycle"] = true
  }

  local conf, err = io.open(conf_path, "r")
  if not conf or err then return nil, "[?] WRN in server.parse_conf: could not read config file with err " .. err end
  
  local config = {}
  for line in conf:lines() do

      local CAPTURE_EITHER_SIDE_OF_COLON <const> = "([^%:]*)%:(.*)"
      local recipient_and_key, value = string.match(line, CAPTURE_EITHER_SIDE_OF_COLON)
      
      local SPLIT_ON_DOT <const> = "^(.-)%.(.*)$"
      local recipient, key = string.match(recipient_and_key, SPLIT_ON_DOT)

      if recipient and key and value then

        if read_as_number_lookup[key] then value = tonumber(value) end
        if not config[recipient] then config[recipient] = {} end
        config[recipient][key] = value

      else print("[?] WRN in server.parse_conf: invalid configuration line read, key " .. key or "nil" .. ", value " .. value or "nil") end
  
    end

  return config

end

-- distributes configs to tables, i.e. a conf entry "http.host = x.x.x.x"
-- will go to http.config.host after loading
function server.distribute_conf(conf)

  for k, v in pairs(conf) do
    _ENV[k].config = v
  end

end

-- initialize config
local config, err = server.read_conf("./lua-server-lplp.conf")
assert(not err, err)
server.distribute_conf(config)

-- setup main server loop
local opened_server, err = server.open_server("0.0.0.0", 8080)
assert(server, "[!] ERR in server main loop: could not open server: " .. tostring(err))
server.connections = { opened_server }
server.connection_protocol_lookup = { [opened_server] = "server" }
local garbage_collection_countdown = server.config.garbage_collection_cycle

while 1 do

  ::continue::
  print("waiting to read...")

  -- TODO: this needs to timeout eventually
  local readable_sockets, _, err = socket.select(server.connections)

  if err then
    print("[?] WRN in server main loop: socket selection reported error: " .. err)
    goto continue
  end
  
  for _, connection in ipairs(readable_sockets) do
    local protocol = server.connection_protocol_lookup[connection]
    local response
    -- TODO: this should just be a callk to env.
    -- websocket can reutrn nil so handle_repsonse also should do thathanlde it whatever
    if protocol == "server" then
      server.accept_connection(connection)
    else
      response = _ENV[protocol].incoming(connection)
      server.handle_response(connection, response)
    end
  end

  garbage_collection_countdown = garbage_collection_countdown - 1

  if garbage_collection_countdown == 0 then
    server.clean_connections()
    garbage_collection_countdown = server.config.garbage_collection_cycle
  end

end