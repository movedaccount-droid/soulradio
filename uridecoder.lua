local uridecoder = {}

local SCHEME <const> = "%a[%a%d%+%-%.]*"
local UNRESERVED <const> = "a-zA-Z0-9%-%.%_%~"
local SUB_DELIMS <const> = "%!%$%&%'%(%)%*%+%,%;%="
local PCT_ENCODED <const> = "%%[0-9a-fA-F][0-9a-fA-F]"
local PCHAR <const> = UNRESERVED .. SUB_DELIMS .. "%:%@"
local IPVFUTURE <const> = "v%x+%.[" .. UNRESERVED .. SUB_DELIMS .. "%:]+"
local H16 <const> = "%x%x?%x?%x?"
local PORT <const> = "%d*"

local SEGMENT <const> = "[" .. PCHAR .. "]*"
local SEGMENT_NZ <const> = "[" .. PCHAR .. "]+"
local PATH_EMPTY <const> = ""
local QUERY <const> = "[" .. PCHAR .. "%/%?]*"
local FRAGMENT <const> = "[" .. PCHAR .. "%/%?]*"

function match_group_or_group(string, pattern_array)
    for _, pattern in ipairs(pattern_array) do
        string = string:gsub(pattern, "")
    end
    return string == ""
end

function match_dec_octet(dec_octet)
    if dec_octet:find("^%d$") then return true
    elseif dec_octet:find("^[1-9]%d$") then return true
    elseif dec_octet:find("^1%d%d$") then return true
    elseif dec_octet:find("^2[0-4]%d$") then return true
    elseif dec_octet:find("^25[0-5]$") then return true
    else return false end
end

function match_ipv4address(ipv4address)
    local dec_octet_count = 0
    for dec_octet in ipv4address:gmatch("[^%.]+") do
        dec_octet_count = dec_octet_count + 1
        if dec_octet_count > 4 or not match_dec_octet(dec_octet) then return false end
    end
    if dec_octet_count < 4 then return false end
    return true
end

function match_ls32(ls32)
    if ls32:find("^" .. H16 .. "%:" .. H16 .. "$") ~= nil then return true
    else return match_ipv4address(ls32) end
end

function match_ipv6address(ipv6address)
    if ipv6address == nil then return false end
    -- assign each component a "score" to determine maximum components
    local score = 8
    -- split in half
    local found, _, left_half, right_half = ipv6address:find("^(.*)::(.*)$")
    -- handle case where everything is on right and remove score value for ::
    if found == nil then right_half = ipv6address else score = score - 1 end
    -- calculate score from definite-length right side
    if right_half ~= nil then
        local final_piece_start, _, final_piece = right_half:find("%:?(%x*)$")
        if final_piece == nil then return false
        elseif final_piece:find("^" .. H16 .. "$") then score = score - 1
        elseif match_ls32(final_piece) then score = score - 2
        else return false end
        if final_piece_start ~= 1 then
            -- right half contains further octets that need checking
            local further_octets = right_half:sub(1, final_piece_start)
            local remaining_octets, octet_count = further_octets:gsub(H16 .. "%:", "")
            if remaining_octets ~= "" then return false end
            score = score - octet_count
        end
    end
    if left_half ~= nil then
        local final_piece_start, _, final_piece = right_half:find("%:?(%x*)$")
        if final_piece == nil then return false
        elseif final_piece:find("^" .. H16 .. "$") then score = score - 1
        else return false end
        if final_piece_start ~= 1 then
            -- left half contains further octets that need checking
            local further_octets = left_half:sub(1, final_piece_start)
            local remaining_octets, octet_count = further_octets:gsub(H16 .. "%:", "")
            if remaining_octets ~= "" then return false end
            score = score - octet_count
        end
    end
    if score < 0 then return false else return true end
end

function match_ip_literal(ip_literal)
    if not (ip_literal:len() > 2) then return false end -- hacky 
    if ip_literal:sub(1,1) == "[" and
       ip_literal:sub(-1,-1) == "]" and
       (match_ipv6address(ip_literal:sub(2,-2)) or ip_literal:sub(2,-2):find("^" .. IPVFUTURE .. "$") ~= nil) then
        return true
    else return false end
end

function match_reg_name(reg_name)
    return match_group_or_group(reg_name, { "[" .. UNRESERVED .. SUB_DELIMS .. "]", PCT_ENCODED })
end

function match_host(host)
    return match_reg_name(host) or match_ip_literal(host) or match_ipv4address(host)
end

function match_segment_nz_nc(segment_nz_nc)
    if segment_nz_nc:len() == 0 then return false end
    return match_group_or_group(segment_nz_nc, { "[" .. UNRESERVED .. SUB_DELIMS .. "%@]", PCT_ENCODED })
end

function match_path_abempty(path_abempty)
    return path_abempty:gsub("%/" .. SEGMENT, "") == ""
end

function match_path_absolute(path_absolute)
    if path_absolute == "%/" then return true end
    local segment_nz, segment_nz_end
    _, segment_nz_end, segment_nz = path_absolute:find("^(/" .. SEGMENT_NZ .. ")")
    if segment_nz == nil then return false end
    path_absolute = path_absolute:sub(segment_nz_end + 1, -1)
    return match_path_abempty(path_absolute)
end

function match_path_noscheme(path_noscheme)
    local segment_nz_nc, segment_nz_nc_end
    _, segment_nz_nc_end, segment_nz_nc = path_noscheme:find("^([^%/]*)/")
    if segment_nz_nc == nil then return false end
    path_noscheme = path_noscheme:sub(segment_nz_nc_end + 1, -1)
    return match_path_abempty(path_noscheme)
end

function match_path_rootless(path_rootless)
    local segment_nz, segment_nz_end
    _, segment_nz_end, segment_nz = path_absolute:find("^(" .. SEGMENT_NZ .. ")")
    if segment_nz == nil then return false end
    path_absolute = path_absolute:sub(segment_nz_end + 1, -1)
    return match_path_abempty(path_absolute)
end

function match_path(path)
    return match_path_abempty(path) or
           match_path_absolute(path) or
           match_path_noscheme(path) or
           match_path_rootless(path) or
           path:find("^" .. PATH_EMPTY .. "$")
end

function match_authority(authority)
    local userinfo_end
    _, userinfo_end = authority:find("%@")
    if userinfo_end ~= nil then
        userinfo_end = userinfo_end - 1
        if not match_userinfo(authority:sub(1, userinfo_end)) then return false end
        authority = authority:sub(userinfo_end + 2, -1)
    end
    local port_start = authority:find("%:" .. PORT .. "$")
    if port_start ~= nil then
        if match_host(authority:sub(1, port_start - 1)) then return true end
    end
    -- port match could match ipv6 and then fail. so do both on failure of port check
    return match_host(authority)
end

function match_userinfo(userinfo)
    return match_group_or_group(userinfo, { "[" .. UNRESERVED .. SUB_DELIMS .. "%:]", PCT_ENCODED })
end

function match_relative_part(relative_part)
    if relative_part:sub(1,2) == "//" then
        relative_part = relative_part:sub(3,-1)
        local authority, authority_end
        _, authority_end, authority = relative_part:find("([^%/]*)")
        if not match_authority(authority) then return false end
        return match_path_abempty(relative_part:sub(authority_end + 1, -1))
    else return match_path_absolute(relative_part) or match_path_noscheme(relative_part) or relative_part:find("^" .. PATH_EMPTY .. "$") ~= nil end
end

function match_hier_part(hier_part)
    if hier_part:sub(1,2) == "//" then
        hier_part = hier_part:sub(3,-1)
        local authority, authority_end
        _, authority_end, authority = hier_part:find("([^%/]*)")
        if not match_authority(authority) then return false end
        return match_path_abempty(hier_part:sub(authority_end + 1, -1))
    else return match_path_absolute(hier_part) or match_path_rootless(hier_part) or hier_part:find("^" .. PATH_EMPTY .. "$") ~= nil end
end

function match_uri(uri)

end

function match_relative_ref(relative_ref)
    local fragment_start = relative_ref:find("%#" .. FRAGMENT .. "$")
    if fragment_start ~= nil then relative_ref = relative_ref:sub(1, fragment_start - 1) end
    local query_start = relative_ref:find("%?" .. QUERY .. "$")
    if query_start ~= nil then relative_ref = relative_ref:sub(1, query_start - 1) end
    return match_relative_part(relative_ref)
end

function match_uri(uri)
    local scheme_end
    _, scheme_end = uri:find("^" .. SCHEME .. "%:")
    if scheme_end == nil then return false end
    uri = uri:sub(scheme_end + 1, -1)
    local fragment_start = uri:find("%#" .. FRAGMENT .. "$")
    if fragment_start ~= nil then uri = uri:sub(1, fragment_start - 1) end
    local query_start = uri:find("%?" .. QUERY .. "$")
    if query_start ~= nil then uri = uri:sub(1, query_start - 1) end
    return match_hier_part(uri)
end

function match_absolute_uri(absolute_uri)
    local scheme_end
    _, scheme_end = absolute_uri:find("^" .. SCHEME .. "%:")
    if scheme_end == nil then return false end
    absolute_uri = absolute_uri:sub(scheme_end + 1, -1)
    local query_start = absolute_uri:find("%?" .. QUERY .. "$")
    if query_start ~= nil then absolute_uri = absolute_uri:sub(1, query_start - 1) end
    return match_hier_part(absolute_uri)
end

function match_http_absolute_path(http_absolute_path)
    local segment_count
    http_absolute_path, segment_count = http_absolute_path:gsub("%/" .. SEGMENT,"")
    return segment_count > 1 and http_absolute_path == ""
end

function match_http_origin_form(http_origin_form)
    local query_start = http_origin_form:find("%?" .. QUERY .. "$")
    if query_start ~= nil then http_origin_form = http_origin_form:sub(1, query_start - 1) end
    return match_http_absolute_path(http_origin_form)
end

function match_http_authority_form(http_authority_form)
    local port_found
    http_authority_form, port_found = http_authority_form:gsub("%:" .. PORT .. "$", "")
    if port_found == 0 then return false end
    return match_host(http_authority_form)
end

function match_http_absolute_form(http_absolute_form)
    return match_absolute_uri(http_absolute_form)
end

function match_http_asterisk_form(http_asterisk_form)
    return http_asterisk_form == "*"
end

while 1 do
    io.write("enter uri")
    io.flush()
    answer=io.read()
    print(match_uri(answer))
end