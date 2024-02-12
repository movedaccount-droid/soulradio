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
local BYTE_BOUNDARY <const> = "BYTE_BOUNDARY_C00TTON_BULL0CK"

http_backend = {}

http_backend.get_path_from_relative = function(relative_uri)
    return http_backend.config.server_path .. relative_uri
end

http_backend.get_range_indexes = function(range_string, file_length)
    -- TODO: should include precondition check (3.1)
    -- provided a file and a Range header field,
    -- returns the list of valid (satisfiable) byte ranges

    -- remove bytes= if exists
    range_string = range_string:gsub("^.*%=", "")

    local i = 1
    local ranges = {}
    for range in range_string:gmatch("([^,]+)") do
        -- parse range
        local range = {["head"] = range:match("^([%d]+)%-"), ["tail"] = range:match("%-([%d]+)$")}

        -- parse to numbers
        if range.head ~= nil then range.head = tonumber(range.head) end
        if range.tail ~= nil then range.tail = tonumber(range.tail) end

        local satisfiable = false
        -- check if start is satisfiable and clamp appropriate end
        if range.head ~= nil and range.head <= file_length then
            if range.tail == nil or range.tail > file_length then range.tail = file_length end
            satisfiable = true
        end

        -- check if end is satisfiable and clamp appropriate start
        if range.tail ~= nil and range.tail > 0 then
            if range.head == nil then range.head = 0 end
            satisfiable = true
        end


        if satisfiable then table.insert(ranges, range) end
    end
    return ranges
end

http_backend.get_mime_type = function(relative_uri)
    local _, _, extension = relative_uri:find(".*%.([^%.]*)")

    local mime_types = {
        ["txt"] = "text/plain",
        ["css"] = "text/css",
        ["html"] = "text/html",
        ["js"] = "text/javascript",
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
        ["mp3"] = "audio/mpeg",
        ["m3u"] = "audio/mpegURL",
        ["m3u8"] = "vnd.apple.mpegURL",
        ["ts"] = "video/MP2T",
    }

    local mime_type = mime_types[extension]
    if not mime_type then 
        print("[?] WRN in http_backend.get_mime_type: no matching mime_type found, defaulting to octet-stream")
        mime_type = "application/octet-stream"
    end
    return mime_type
end

http_backend.parse_conf = function(conf_path)

    local number_confs = {
        ["timeout"] = true,
        ["garbage_collection_cycle"] = true
    }

    local conf, err = io.open(conf_path, "r")
    if err then return nil, "[?] WRN in http_backend.parse_conf: " .. err end
    local config = {}
    for line in conf:lines() do
        print(line)
        local key, value = line:match("([^%:]*)%:(.*)")
        if key and value then
            if number_confs[key] then value = tonumber(value) end
            config[key] = value
        else print("[?] WRN in http_backend.parse_conf: invalid configuration line read, key " .. key or "nil" .. ", value " .. value or "nil") end
    end
    return config
end

http_backend.get_file_size = function(file)
    if file == nil or err then return nil, err end
    local current = file:seek()
    local size = file:seek("end")
    file:seek("set", current)
    return size
end

http_backend.build_get_response = function(file, mime_type, request_headers)

    if not file then
        return {["code"] = 404, ["field"] = {["Content-Length"] = 0}}
    end

    local file_length = http_backend.get_file_size(file)
    -- handle range requests (rfc7233)
    -- TODO: implement if-range (3.2)
    if request_headers["range"] ~= nil then
        local parsed_ranges = http_backend.get_range_indexes(request_headers["range"], file_length)
        if parsed_ranges == {} then
            -- respond with 416 Range Not Satisifable on no matches
            return {
                ["code"] = 416,
                ["field"] = {
                    ["Content-Length"] = 0,
                    ["Content-Range"] = "bytes */" .. file_length
                }
            }
        elseif #parsed_ranges == 1 then
            -- respond with 206 Partial Content on one match
            local range = parsed_ranges[1]
            local body = file:read(range.tail - range.head)
            file:seek(set, range.head - 1)
            return {
                ["code"] = 206,
                ["field"] = {
                    ["Content-Type"] = mime_type,
                    ["Content-Length"] = string.len(body), 
                    ["Content-Range"] = "bytes " .. range.head .. "-" .. range.tail .. "/" .. file_length
                },
                ["body"] = body
            }
        else
            -- respond with 206 Partial Content multipart on two or more matches
            local body = http_backend.build_range_multiline_body(file, parsed_ranges)
            return {
                ["code"] = 206,
                ["field"] = {
                    ["Content-Type"] = "multipart/byteranges; boundary=" .. BYTE_BOUNDARY,
                    ["Content-Length"] = string.len(body)
                },
                ["body"] = file:read(range.tail - range.head)
            }
        end
    else
        return {
            ["code"] = 200,
            ["field"] = {
                ["Content-Type"] = mime_type,
                ["Content-Length"] = file_length
            },
            ["body"] = file:read("a")
        }
    end
end

http_backend.build_range_body = function(file, range)
    local current = file:seek()
    file:seek(set, range.head - 1)
    local range_payload = file:read(range.tail - range.head)
    file:seek("set", current)
    return range_payload
end

http_backend.build_range_multiline_body = function(file, ranges)
    local body = {}
    for _, range in ipairs(parsed_ranges) do
        table.insert(body, "--" .. BYTE_BOUNDARY)
        table.insert(body, "Content-Type: " .. file_mime)
        table.insert(body, "Content-Range: bytes " .. range.head .. "-" .. range.tail .. "/" .. file_length)
        table.insert(body, "")
        table.insert(body, http_backend.build_range_body(file, range))
    end
    table.insert(body, "--" .. BYTE_BOUNDARY .. "--")
    return table.concat(body, "\n")
end

http_backend.GET = function(relative_uri, request_headers)
    local path = http_backend.get_path_from_relative(relative_uri)
    local file = io.open(path, "r")
    local mime_type = http_backend.get_mime_type(relative_uri)
    return http_backend.build_get_response(file, mime_type, request_headers)
end

http_backend.HEAD = function(relative_uri, request_headers)
    local response = http_backend.GET(relative_uri, request_headers)
    response["body"] = nil
    return response
end

http_backend.POST = function(relative_uri)

end

-- initialize
http_backend.conf_path = "./luattp.conf"
local err
http_backend.config, err = http_backend.parse_conf(http_backend.conf_path)
if err then print(err) end
print("------- config ------- ")
for k, v in pairs(http_backend.config) do
    print(k .. ": " .. v)
end
