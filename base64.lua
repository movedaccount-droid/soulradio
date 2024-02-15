if not base64 then base64 = {} end

base64.get_char = function(code)
    if code < 26 then return string.char(code + 65)
    elseif code < 52 then return string.char(code + 71)
    elseif code < 62 then return string.char(code - 4)
    elseif code == 62 then return '+'
    else return '/' end
end

base64.get_code = function(char)

    if 64 < char and char < 91 then return char - 65
    elseif 96 < char and char < 123 then return char - 71
    elseif 47 < char and char < 58 then return char + 4
    elseif char == 43 then return 62
    else return 63 end

end

base64.three_chars_to_four_ints = function(str_slice)

    local c1, c2, c3 = string.byte(str_slice, 1, 3)

    local i1 = c1 >> 2
    local i2 = ((c1 << 4) & 0x3F) | (c2 >> 4)
    local i3 = ((c2 << 2) & 0x3F) | (c3 >> 6)
    local i4 = c3 & 0x3F

    return i1, i2, i3, i4

end

base64.four_ints_to_three_chars = function(i1, i2, i3, i4)

    return string.char(
        (i1 << 2) | (i2 >> 4),
        ((i2 << 4) & 0xF0) | (i3 >> 2),
        ((i3 << 6) & 0xC0) | i4)

end

base64.encode = function(input)

    -- perform 0 padding
    local padding_bits = 24 - ((string.len(input) * 8) % 24)
    if padding_bits == 24 then padding_bits = 0 end
    local padding_char_count = padding_bits / 8

    local padded_input = input .. string.rep(string.char(0), padding_char_count)

    local group_count = string.len(padded_input) / 3

    local encoded_input = {}
    for i=1, group_count * 3, 3 do
        
        local group_chars = string.sub(padded_input, i, i + 2)

        local i1, i2, i3, i4 = base64.three_chars_to_four_ints(group_chars)

        table.insert(encoded_input, base64.get_char(i1))
        table.insert(encoded_input, base64.get_char(i2))
        table.insert(encoded_input, base64.get_char(i3))
        table.insert(encoded_input, base64.get_char(i4))

    end

    -- convert padding to =
    if padding_char_count > 0 then encoded_input[#encoded_input] = "=" end
    if padding_char_count > 1 then encoded_input[#encoded_input - 1] = "=" end

    return table.concat(encoded_input)

end

base64.decode = function(input)

    -- calculate padding
    local padding = string.sub(input, -2, -1)
    local padding_count = 2 - string.len(string.gsub(padding, "=", ""))

    local group_count = string.len(input) / 4
    local message = {}

    for i=1, group_count * 4, 4 do

        local i1, i2, i3, i4 = string.byte(string.sub(input, i, i + 3), 1, 4)

        i1 = base64.get_code(i1)
        i2 = base64.get_code(i2)
        i3 = base64.get_code(i3)
        i4 = base64.get_code(i4)

        table.insert(message, base64.four_ints_to_three_chars(i1, i2, i3, i4))

    end

    -- remove padding
    if padding_count == 2 then message[#message] = string.sub(message[#message], 1, 1)
    elseif padding_count == 1 then message[#message] = string.sub(message[#message], 1, 2) end

    return table.concat(message)

end

-- tests = {}

-- tests["wikipedia_example_1"] = function()
--     assert(base64.encode("Many hands make light work.") == "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu")
--     return true
-- end

-- tests["wikipedia_example_2"] = function()
--     assert(base64.encode("light work.") == "bGlnaHQgd29yay4=")
--     return true
-- end

-- tests["wikipedia_example_3"] = function()
--     assert(base64.encode("light work") == "bGlnaHQgd29yaw==")
--     return true
-- end

-- tests["wikipedia_example_4"] = function()
--     assert(base64.encode("light wor") == "bGlnaHQgd29y")
--     return true
-- end

-- tests["wikipedia_example_5"] = function()
--     assert(base64.encode("light wo") == "bGlnaHQgd28=")
--     return true
-- end

-- tests["wikipedia_example_6"] = function()
--     assert(base64.encode("light w") == "bGlnaHQgdw==")
--     return true
-- end

-- tests["wikipedia_example_1_dec"] = function()
--     assert(base64.decode("TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu") == "Many hands make light work.")
--     return true
-- end

-- tests["wikipedia_example_2_dec"] = function()
--     assert(base64.decode("bGlnaHQgd29yay4=") == "light work.")
--     return true
-- end

-- tests["wikipedia_example_3_dec"] = function()
--     assert(base64.decode("bGlnaHQgd29yaw==") == "light work")
--     return true
-- end

-- tests["wikipedia_example_4_dec"] = function()
--     assert(base64.decode("bGlnaHQgd29y") == "light wor")
--     return true
-- end

-- tests["wikipedia_example_5_dec"] = function()
--     assert(base64.decode("bGlnaHQgd28=") == "light wo")
--     return true
-- end

-- tests["wikipedia_example_6_dec"] = function()
--     assert(base64.decode("bGlnaHQgdw==") == "light w")
--     return true
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