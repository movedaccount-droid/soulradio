luattp_utils = {}

luattp_utils.copy_table = function(table_to_copy)
    -- recursively copy table, since lua defaults to copy by reference
    if type(table_to_copy) == "table" then
        -- recurse and copy
        local recursive_table = {}
        for k, v in pairs(table_to_copy) do
            recursive_table[k] = luattp_utils.copy_table(v)
        end
        return recursive_table
    else
        -- halt recursion and return
        return table_to_copy
    end
end