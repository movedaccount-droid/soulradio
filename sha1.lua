sha1 = {}

-- referenced:
-- this existing much faster implementation [for string -> u32 conversion particularly]
-- https://github.com/mpeterv/sha1/blob/master/src/sha1/init.lua 
-- wikipedia pseudocode
-- https://en.wikipedia.org/wiki/SHA-1
-- this for debugging, since it uses 512 chunks instead of the 64 by peter
-- https://github.com/thomas-barthelemy/sha1-explained/blob/master/javascript/main.js

sha1.calculate = function(message)

    local h0 = 0x67452301
    local h1 = 0xEFCDAB89
    local h2 = 0x98BADCFE
    local h3 = 0x10325476
    local h4 = 0xC3D2E1F0

    local ml = string.len(message) * 8

    -- appending bit 1
    local pre_processing = { message }
    table.insert(pre_processing, string.char(0x80))

    -- bringing to -64 ≡ 448 (mod 512)
    local k = (512 - (ml + 8 + 64) % 512) / 8
    table.insert(pre_processing, string.rep(string.char(0), k))

    -- append length as big-endian integer
    table.insert(pre_processing, string.char((ml & 0xFF00000000000000) >> 56))
    table.insert(pre_processing, string.char((ml & 0xFF000000000000) >> 48))
    table.insert(pre_processing, string.char((ml & 0xFF0000000000) >> 40))
    table.insert(pre_processing, string.char((ml & 0xFF00000000) >> 32))
    table.insert(pre_processing, string.char((ml & 0xFF000000) >> 24))
    table.insert(pre_processing, string.char((ml & 0xFF0000) >> 16))
    table.insert(pre_processing, string.char((ml & 0xFF00) >> 8))
    table.insert(pre_processing, string.char(ml & 0xFF))

    local message = table.concat(pre_processing)

    local CHARS_PER_CHUNK <const> = 512 / 8
    local final_chunk_index = string.len(message) - CHARS_PER_CHUNK + 1

    for i=1,final_chunk_index,CHARS_PER_CHUNK do
        
        local chunk = string.sub(message, i, i + CHARS_PER_CHUNK - 1)

        local a = h0
        local b = h1
        local c = h2
        local d = h3
        local e = h4

        local f, k

        for i=1,80 do

            if i <= 20 then
                f = (b & c) | ((0xFFFFFFFF ~ b) & d)
                k = 0x5A827999
            elseif i <= 40 then
                f = b ~ c ~ d
                k = 0x6ED9EBA1
            elseif i <= 60 then
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else
                f = b ~ c ~ d
                k = 0xCA62C1D6
            end

            local temp = (sha1.left_rotate(a, 5) + f + e + k + sha1.get_word(chunk, i)) % 4294967296
            e = d
            d = c
            c = sha1.left_rotate(b, 30)
            b = a
            a = temp

            -- print(string.format("temp: %x", temp))
            -- print(string.format("e: %x", e))
            -- print(string.format("d: %x", d))
            -- print(string.format("c: %x", c))
            -- print(string.format("b: %x", b))
            -- print(string.format("a: %x", a))

        end

        h0 = (h0 + a) % 4294967296
        h1 = (h1 + b) % 4294967296
        h2 = (h2 + c) % 4294967296
        h3 = (h3 + d) % 4294967296
        h4 = (h4 + e) % 4294967296

    end

    local output = {}

    for _, u32 in ipairs({h0, h1, h2, h3, h4}) do
        local chars = sha1.u32_to_four_chars(u32)
        table.insert(output, chars)
    end

    -- return string.format("%08x%08x%08x%08x%08x", h0, h1, h2, h3, h4)
    return table.concat(output)

end

-- we do this dynamically so we don't have to make copies
sha1.get_word = function(chunk, i)
    if i <= 16 then
        -- this can be string data, so we need to force it to u32
        local b1, b2, b3, b4 = string.byte(chunk, i * 4 - 3, i * 4)
        return b1 * 0x1000000 + b2 * 0x10000 + b3 * 0x100 + b4
    else
        return sha1.left_rotate(
            sha1.get_word(chunk, i - 3)
            ~ sha1.get_word(chunk, i - 8)
            ~ sha1.get_word(chunk, i - 14)
            ~ sha1.get_word(chunk, i - 16), 1)
    end
end

sha1.left_rotate = function(message, n)
    return ((message << n) & 0xFFFFFFFF) | message >> 32 - n
end

sha1.u32_to_four_chars = function(u32)

    local c1 = (u32 & 0xFF000000) >> 24
    local c2 = (u32 & 0xFF0000) >> 16
    local c3 = (u32 & 0xFF00) >> 8
    local c4 = (u32 & 0xFF)

    return string.char(c1, c2, c3, c4)
end

-- tests = {}

-- tests["wikipedia_example_1"] = function()
--     assert(sha1.calculate("The quick brown fox jumps over the lazy dog") == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")
--     return true
-- end

-- tests["wikipedia_example_2"] = function()
--     assert(sha1.calculate("The quick brown fox jumps over the lazy cog") == "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3")
--     return true
-- end

-- tests["wikipedia_example_2_long"] = function()
--     local sha = sha1.calculate("The quick brown fox jumps over the lazy cogThe quick brown fox ju")
--     return sha == "726d10a72f4e7dbb59578e930fa4ff7630cb9163"
-- end

-- tests["python_sha1_comparison"] = function()
--     local sha = sha1.calculate("dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
--     print(sha)
--     return sha == "b37a4f2cc0624f1690f64606cf385945b2bec4ea"
-- end

-- local successes, failures = 0, 0

-- for n, test in pairs(tests) do
--     io.write(n .. "... ")
--     if not test() then
--         io.write("FAILED.\n")
--         failures = failures + 1
--     else
--         io.write("passed.\n")
--         successes = successes + 1
--     end
-- end

-- print("")
-- print(successes .. " passed. " .. failures .. " failed.")