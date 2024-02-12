-- http_backend: http backend handler for lua-server-lplp

http_backend = {}

-- http_backend.consts: universal constants
http_backend.consts.implemented = {
    ["range_requests"] = true
}

http_backend.consts.BYTE_BOUNDARY = "BYTE_BOUNDARY_C00TTON_BULL0CK"

-- main code
http_backend.get_path_from_relative = function(relative_uri)
    return http.config.server_path .. relative_uri
end

http_backend.get_range_indexes = function(range_string, file_length)
    -- TODO: should include precondition check (3.1)

    local BYTES_EQUALS_HEADER <const> = "^.*%="
    range_string = string.gsub(range_string, BYTES_EQUALS_HEADER, "")

    local ranges = {}
    local ITEMS_BETWEEN_COMMAS <const> = "([^,]+)"
    for range in string.gmatch(range_string, ITEMS_BETWEEN_COMMAS) do

        local RANGE_HEAD = "^([%d]+)%-"
        local RANGE_TAIL = "%-([%d]+)$"
        local range = {
            ["head"] = string.match(range, RANGE_HEAD),
            ["tail"] = string.match(range, RANGE_TAIL)
        }

        local err
        range.head = tonumber(range.head)
        range.tail = tonumber(range.tail)
        if not range.head or not range.tail then return nil, "[?] WRN in http_backend.get_range_indexes: could not convert head/tail to numbers" end

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

http_backend.get_file_size = function(file)
    local current = file:seek()
    local size = file:seek("end")
    file:seek("set", current)
    return size
end

http_backend.build_get_response = function(file, mime_type, request)

    local file_length = http_backend.get_file_size(file)
    -- TODO: implement if-range (3.2)
    if request:get("Range") ~= nil then

        local parsed_ranges, err = http_backend.get_range_indexes(request:get("Range"), file_length)
        if not parsed_ranges or err then return http.response:new_400()

        elseif parsed_ranges == {} then

            -- 416 Range Not Satisifable
            return http.response:new(416, http.field_lines:new({
                ["Content-Range"] = "bytes */" .. file_length,
            }))

        elseif #parsed_ranges == 1 then

            -- 206 Partial Content
            local range = parsed_ranges[1]
            file:seek("set", range.head - 1)
            local body = http_backend.build_range_body(file, range)

            return http.response:new(206, http.field_lines:new({
                ["Content-Type"] = mime_type,
                ["Content-Range"] = "bytes " .. range.head .. "-" .. range.tail .. "/" .. file_length
            }), body)

        else

            -- 206 Partial Content [multipart]
            local body = http_backend.build_range_multiline_body(file, parsed_ranges, mime_type, file_length)

            return http.response:new(206, http.field_lines:new({
                ["Content-Type"] = "multipart/byteranges; boundary=" .. http_backend.consts.BYTE_BOUNDARY
            }), body)

        end
    else
        return http.response:new(200, http.field_lines:new({
            ["Content-Type"] = mime_type
        }), file:read("a"))
    end
end

http_backend.build_range_body = function(file, range)
    local current = file:seek()
    file:seek("set", range.head - 1)
    local range_payload = file:read(range.tail - range.head)
    file:seek("set", current)
    return range_payload
end

http_backend.build_range_multiline_body = function(file, ranges, file_mime, file_length)
    local body = {}
    for _, range in ipairs(ranges) do
        table.insert(body, "--" .. http_backend.consts.BYTE_BOUNDARY)
        table.insert(body, "Content-Type: " .. file_mime)
        table.insert(body, "Content-Range: bytes " .. range.head .. "-" .. range.tail .. "/" .. file_length)
        table.insert(body, "")
        table.insert(body, http_backend.build_range_body(file, range))
    end
    table.insert(body, "--" .. http_backend.consts.BYTE_BOUNDARY .. "--")
    return table.concat(body, "\n")
end

http_backend.GET = function(request)

    local path = http_backend.get_path_from_relative(request.request_target.path)
    local file, err = io.open(path, "r")
    if not file or err then return http.response:new(404) end

    local mime_type = http_backend.get_mime_type(path)
    return http_backend.build_get_response(file, mime_type, request)

end

http_backend.HEAD = function(request)
    local response = http_backend.GET(request)
    response.body = nil
    return response
end