if not uridecoder then uridecoder = {} end

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

uridecoder.match_group_or_group = function(string, pattern_array)
    for _, pattern in ipairs(pattern_array) do
        string = string:gsub(pattern, "")
    end
    return string == ""
end

uridecoder.match_dec_octet = function(dec_octet)
    if dec_octet:find("^%d$") then return true
    elseif dec_octet:find("^[1-9]%d$") then return true
    elseif dec_octet:find("^1%d%d$") then return true
    elseif dec_octet:find("^2[0-4]%d$") then return true
    elseif dec_octet:find("^25[0-5]$") then return true
    else return false end
end

uridecoder.match_ipv4address = function(ipv4address)
    local dec_octet_count = 0
    for dec_octet in ipv4address:gmatch("[^%.]+") do
        dec_octet_count = dec_octet_count + 1
        if dec_octet_count > 4 or not uridecoder.match_dec_octet(dec_octet) then return false end
    end
    if dec_octet_count < 4 then return false end
    return true
end

uridecoder.match_ls32 = function(ls32)
    if ls32:find("^" .. H16 .. "%:" .. H16 .. "$") ~= nil then return true
    else return uridecoder.match_ipv4address(ls32) end
end

uridecoder.match_ipv6address = function(ipv6address)
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
        elseif uridecoder.match_ls32(final_piece) then score = score - 2
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

uridecoder.match_ip_literal = function(ip_literal)
    if not (ip_literal:len() > 2) then return false end -- hacky 
    if ip_literal:sub(1,1) == "[" and
       ip_literal:sub(-1,-1) == "]" and
       (uridecoder.match_ipv6address(ip_literal:sub(2,-2)) or ip_literal:sub(2,-2):find("^" .. IPVFUTURE .. "$") ~= nil) then
        return true
    else return false end
end

uridecoder.match_reg_name = function(reg_name)
    return uridecoder.match_group_or_group(reg_name, { "[" .. UNRESERVED .. SUB_DELIMS .. "]", PCT_ENCODED })
end

uridecoder.match_host = function(host)
    return uridecoder.match_reg_name(host) or uridecoder.match_ip_literal(host) or uridecoder.match_ipv4address(host)
end

uridecoder.match_segment_nz_nc = function(segment_nz_nc)
    if segment_nz_nc:len() == 0 then return false end
    return uridecoder.match_group_or_group(segment_nz_nc, { "[" .. UNRESERVED .. SUB_DELIMS .. "%@]", PCT_ENCODED })
end

uridecoder.match_path_abempty = function(path_abempty)
    return path_abempty:gsub("%/" .. SEGMENT, "") == ""
end

uridecoder.match_path_absolute = function(path_absolute)
    if path_absolute == "%/" then return true end
    local segment_nz, segment_nz_end
    _, segment_nz_end, segment_nz = path_absolute:find("^(/" .. SEGMENT_NZ .. ")")
    if segment_nz == nil then return false end
    path_absolute = path_absolute:sub(segment_nz_end + 1, -1)
    return uridecoder.match_path_abempty(path_absolute)
end

uridecoder.match_path_noscheme = function(path_noscheme)
    local segment_nz_nc, segment_nz_nc_end
    _, segment_nz_nc_end, segment_nz_nc = path_noscheme:find("^([^%/]*)/")
    if segment_nz_nc == nil then return false end
    path_noscheme = path_noscheme:sub(segment_nz_nc_end + 1, -1)
    return uridecoder.match_path_abempty(path_noscheme)
end

uridecoder.match_path_rootless = function(path_rootless)
    local segment_nz, segment_nz_end
    _, segment_nz_end, segment_nz = path_rootless:find("^(" .. SEGMENT_NZ .. ")")
    if segment_nz == nil then return false end
    path_rootless = path_rootless:sub(segment_nz_end + 1, -1)
    return uridecoder.match_path_abempty(path_rootless)
end

uridecoder.match_path = function(path)
    return uridecoder.match_path_abempty(path) or
           uridecoder.match_path_absolute(path) or
           uridecoder.match_path_noscheme(path) or
           uridecoder.match_path_rootless(path) or
           path:find("^" .. PATH_EMPTY .. "$")
end

uridecoder.match_authority = function(authority)
    local userinfo_end
    _, userinfo_end = authority:find("%@")
    if userinfo_end ~= nil then
        userinfo_end = userinfo_end - 1
        if not uridecoder.match_userinfo(authority:sub(1, userinfo_end)) then return false end
        authority = authority:sub(userinfo_end + 2, -1)
    end
    local port_start = authority:find("%:" .. PORT .. "$")
    if port_start ~= nil then
        if uridecoder.match_host(authority:sub(1, port_start - 1)) then return true end
    end
    -- port match could match ipv6 and then fail. so do both on failure of port check
    return uridecoder.match_host(authority)
end

uridecoder.match_userinfo = function(userinfo)
    return uridecoder.match_group_or_group(userinfo, { "[" .. UNRESERVED .. SUB_DELIMS .. "%:]", PCT_ENCODED })
end

uridecoder.match_relative_part = function(relative_part)
    if relative_part:sub(1,2) == "//" then
        relative_part = relative_part:sub(3,-1)
        local authority, authority_end
        _, authority_end, authority = relative_part:find("([^%/]*)")
        if not uridecoder.match_authority(authority) then return false end
        return uridecoder.match_path_abempty(relative_part:sub(authority_end + 1, -1))
    else return uridecoder.match_path_absolute(relative_part) or uridecoder.match_path_noscheme(relative_part) or relative_part:find("^" .. PATH_EMPTY .. "$") ~= nil end
end

uridecoder.match_hier_part = function(hier_part)
    if hier_part:sub(1,2) == "//" then
        hier_part = hier_part:sub(3,-1)
        local authority, authority_end
        _, authority_end, authority = hier_part:find("([^%/]*)")
        if not uridecoder.match_authority(authority) then return false end
        hier_part = hier_part:sub(authority_end + 1, -1)
        return uridecoder.match_path_abempty(hier_part), hier_part, authority
    else return uridecoder.match_path_absolute(hier_part) or uridecoder.match_path_rootless(hier_part) or hier_part:find("^" .. PATH_EMPTY .. "$") ~= nil, hier_part end
end

uridecoder.match_relative_ref = function(relative_ref)
    local fragment_start, _, fragment = relative_ref:find("%#(" .. FRAGMENT .. ")$")
    if fragment_start ~= nil then relative_ref = relative_ref:sub(1, fragment_start - 1) end
    local query_start, _, query = relative_ref:find("%?(" .. QUERY .. ")$")
    if query_start ~= nil then relative_ref = relative_ref:sub(1, query_start - 1) end
    return uridecoder.match_relative_part(relative_ref), relative_ref, query, fragment
end

uridecoder.match_uri = function(uri)
    local _, scheme_end, scheme = uri:find("^(" .. SCHEME .. ")%:")
    if scheme_end == nil then return false end
    uri = uri:sub(scheme_end + 1, -1)
    local fragment_start, _, fragment = uri:find("%#(" .. FRAGMENT .. ")$")
    if fragment_start ~= nil then uri = uri:sub(1, fragment_start - 1) end
    local query_start, _, query = uri:find("%?(" .. QUERY .. ")$")
    if query_start ~= nil then uri = uri:sub(1, query_start - 1) end
    local is_hier_part, hier_part, authority = uridecoder.match_hier_part(uri)
    return is_hier_part, scheme, authority, hier_part, query, fragment
end

uridecoder.match_absolute_uri = function(absolute_uri)
    local _, scheme_end, scheme = absolute_uri:find("^(" .. SCHEME .. ")%:")
    if scheme_end == nil then return false end
    absolute_uri = absolute_uri:sub(scheme_end - 1, -1)
    local query_start, _, query = absolute_uri:find("%?(" .. QUERY .. ")$")
    if query_start ~= nil then absolute_uri = absolute_uri:sub(1, query_start - 1) end
    local is_hier_part, hier_part, authority = uridecoder.match_hier_part(absolute_uri)
    return is_hier_part, authority, scheme, hier_part, query
end

uridecoder.match_http_absolute_path = function(http_absolute_path)
    local segment_count
    http_absolute_path, segment_count = http_absolute_path:gsub("%/" .. SEGMENT, "")
    return segment_count > 0 and http_absolute_path == ""
end

uridecoder.match_http_origin_form = function(http_origin_form)
    local query_start, _, query = http_origin_form:find("%?(" .. QUERY .. ")$")
    if query_start ~= nil then http_origin_form = http_origin_form:sub(1, query_start - 1) end
    return uridecoder.match_http_absolute_path(http_origin_form), http_origin_form, query
end

uridecoder.match_http_authority_form = function(http_authority_form)
    local port_found
    http_authority_form, port_found = http_authority_form:gsub("%:" .. PORT .. "$", "")
    if port_found == 0 then return false end
    return uridecoder.match_host(http_authority_form)
end

uridecoder.match_http_absolute_form = function(http_absolute_form)
    return uridecoder.match_absolute_uri(http_absolute_form)
end

uridecoder.match_http_asterisk_form = function(http_asterisk_form)
    return http_asterisk_form == "*"
end

uridecoder.match_http_uri_host = function(http_uri_host)
    http_uri_host = http_uri_host:gsub("%:" .. PORT .. "$", "")
    return uridecoder.match_host(http_uri_host)
end

uridecoder.match_http_request_target = function(http_request_target)
    return uridecoder.match_http_origin_form(http_request_target)
        or uridecoder.match_http_absolute_form(http_request_target)
        or uridecoder.match_http_authority_form(http_request_target)
        or uridecoder.match_http_asterisk_form(http_request_target)
end