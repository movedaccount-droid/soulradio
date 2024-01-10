-- take request input handled + parsed by frontend
-- get element requested by GET request
-- implement specific type, at least html, css, js, png, flac
-- return with 200 else 404

-- must implement accept-ranges
-- useful links:
-- https://developer.mozilla.org/en-US/docs/Web/HTTP/Configuring_servers_for_Ogg_media

require "utils"

-- defaults:
-- . server accepts range requests
local BACKEND_RESPONSE_TEMPLATE <const> = {["body"] = nil, ["code"] = nil, ["field"] = {["Accept-Ranges"] = "bytes"}}

luattp_backend = {}

luattp_backend.get_range_indexes = function(range_string, file_length)
    -- TODO: should include precondition check (3.1)
    -- provided a file and a Range header field,
    -- returns the list of valid (satisfiable) byte ranges

    -- remove bytes= if exists
    range_string = range_string:gsub("^.*%=", "")

    local i = 1
    local ranges = nil
    local satisfiable = false
    for range in range_string:gmatch("([^,]+)") do
        -- parse range
        local range_start = range:match("^([%d]+)%-")
        local range_end = range:match("%-([%d]+)$")

        -- parse to numbers
        if range_start ~= nil then range_start = tonumber(range_start) end
        if range_end ~= nil then range_end = tonumber(range_end) end

        -- add to table if satisfiable
        if range_start ~= nil and range_start <= file_length or range_start == nil and range_end ~= nil and range_end > 0 then
            -- fill values for single-value ranges and restrict to file length
            if range_start == nil and range_end ~= nil then range_start = 0 end
            if range_end == nil and range_start ~= nil or range_end > file_length then range_end = file_length end
            if ranges == nil then ranges = {} end
            ranges[i] = {}
            ranges[i]["start"] = range_start
            ranges[i]["end"] = range_end
            i = i + 1
        end
    end
    return ranges
end

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
        ["ogg"] = "audio/ogg",
        ["mp3"] = "audio/mpeg"
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

luattp_backend.get_file_size = function(relative_uri)
    local file, err = io.open(luattp_backend.config["server_path"] .. relative_uri, "r")
    if file == nil or err then return nil, err end
    return file:seek("end")
end

luattp_backend.GET = function(relative_uri, HEAD, range)
    -- get clean response template. do Not ask i don't know either
    local get_response = luattp_utils.copy_table(BACKEND_RESPONSE_TEMPLATE)

    if get_response["body"] ~= nil then print("FISRT BODY:: ", get_response["body"]:sub(1, 1024)) end
    local file = io.open(luattp_backend.config["server_path"] .. relative_uri,"r")
    if file then
        local file_length = luattp_backend.get_file_size(relative_uri)
        local file_mime = luattp_backend.get_mime_type(relative_uri)
        -- handle range requests (rfc7233)
        -- TODO: implement if-range (3.2)
        if range ~= nil and not HEAD then
            local parsed_ranges = luattp_backend.get_range_indexes(range, file_length)
            if parsed_ranges == nil then
                -- respond with 416 Range Not Satisifable
                get_response["code"] = 416
                get_response["field"]["Content-Length"] = 0
                get_response["field"]["Content-Range"] = "bytes */" .. file_length
            else
                -- respond with 206 Partial Content
                get_response["code"] = 206
                get_response["field"]["Content-Type"] = "multipart/byteranges; boundary=BYTE_BOUNDARY_C00TTON_BULL0CK"
                -- construct multipart/byteranges
                get_response["body"] = "BYTE_BOUNDARY_C00TTON_BULL0CK"
                for _, range in ipairs(parsed_ranges) do
                    -- get data for range
                    file:seek(set, range["start"])
                    local range_payload = file:read(range["end"] - range["start"])
                    get_response["body"] = get_response["body"] .. "\nContent-Type: " .. file_mime
                    get_response["body"] = get_response["body"] .. "\nContent-Range: bytes " .. range["start"] .. "-" .. range["end"] .. "/" .. file_length .. ""
                    get_response["body"] = get_response["body"] .. "\n\n"
                    get_response["body"] = get_response["body"] .. range_payload
                    get_response["body"] = get_response["body"] .. "\nBYTE_BOUNDARY_C00TTON_BULL0CK"
                end
                get_response["field"]["Content-Length"] = string.len(get_response["body"])
            end
        else
            -- respond with 200 Ok
            get_response["code"] = 200
            get_response["field"]["Content-Type"] = file_mime
            if not HEAD then get_response["body"] = file:read("a") end
            get_response["field"]["Content-Length"] = file_length
        end
    else
        -- if file not found, respond with 404 Not Found
        get_response["code"] = 404
        get_response["field"]["Content-Length"] = 0
    end
    return get_response
end

luattp_backend.HEAD = function(relative_uri)
    return luattp_backend.GET(relative_uri, true)
end

luattp_backend.POST = function(relative_uri)

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