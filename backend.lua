-- take request input handled + parsed by frontend
-- get element requested by GET request
-- implement specific type, at least html, css, js, png, flac
-- return with 200 else 404

-- must implement accept-ranges
-- useful links:
-- https://developer.mozilla.org/en-US/docs/Web/HTTP/Configuring_servers_for_Ogg_media

local RESPONSE_TEMPLATE <const> = {["field"] = {}}

luattp_backend = {}

luattp_backend.get_mime_type = function(relative_uri)
    local _, _, extension = relative_uri:find(".*%.([^%.]*)")

    local mime_types = {
        ["txt"] = "text/plain",
        ["css"] = "text/css",
        ["html"] = "text/html",
        ["js"] = "text/js",
        ["apng"] = "image/apng",
        ["avif"] = "image/avif",
        ["gif"] = "image/gif",
        ["jpeg"] = "image/jpeg",
        ["jpg"] = "image/jpeg",
        ["png"] = "image/png",
        ["svg"] = "image/svg+xml",
        ["webp"] = "image/webp",
        ["wav"] = "audio/wav",
        ["ogg"] = "audio/ogg"
    }

    local mime_type = mime_types[extension]
    if not mime_type then 
        print("[?] WRN in luattp_backend.get_mime_type: no matching mime_type found, defaulting to octet-stream")
        mime_type = "application/octet-stream"
    end
    return mime_type
end

luattp_backend.parse_conf = function(conf_path)
    local conf, err = io.open(conf_path, "r")
    if err then return nil, "[?] WRN in luattp_backend.parse_conf: " .. err end
    local line = conf:read("*line")
    local config = {}
    while line do
        local key, value = line:match("([^%:]*)%:(.*)")
        if key and value then
            config[key] = value
        else return nil, "[?] WRN in luattp_backend.parse_conf: invalid configuration line read" end
        line = conf:read("*line")
    end
    return config
end

luattp_backend.GET = function(relative_uri)
    local response = RESPONSE_TEMPLATE
    file = io.open(luattp_backend.config["server_path"] .. relative_uri,"r")
    if file then
        response["code"] = 200
        response["field"]["Content-Type"] = luattp_backend.get_mime_type(relative_uri)
        response["body"] = file:read("a")
    else
        response["code"] = 404
        return response
    end
    return response
end

-- initialize
luattp_backend.conf_path = "/home/sk/Documents/1-lua/soulradio/luattp.conf"
print("starting backend serving path " .. luattp_backend.conf_path)
local err
luattp_backend.config, err = luattp_backend.parse_conf(luattp_backend.conf_path)
if err then console.log(err) end
print("------- config ------- ")
for k, v in pairs(luattp_backend.config) do
    print(k .. ": " .. v)
end