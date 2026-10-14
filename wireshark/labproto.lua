-- labproto.lua - Wireshark dissectors for the C09 lab protocols
--   labproto  : master protocol (UDP 9999)
--   labgame   : game protocol   (UDP 10000)
-- Shared header: version(1) | msg_type(1) | body_length(2, big-endian) | body

local p = Proto("labproto", "Lab Master Protocol")

local types = {
    [1] = "HELLO",        [2] = "HELLO_ACK",
    [3] = "AUTH",         [4] = "AUTH_ACK",
    [5] = "LIST_LOBBIES", [6] = "LOBBY_LIST",
    [7] = "CREATE_LOBBY",
    [8] = "JOIN",         [9] = "JOIN_ACK",
}

local f_ver    = ProtoField.uint8 ("labproto.version",     "Version",          base.DEC)
local f_type   = ProtoField.uint8 ("labproto.type",        "Msg Type",         base.DEC, types)
local f_len    = ProtoField.uint16("labproto.length",      "Body Length",      base.DEC)
local f_cid    = ProtoField.uint32("labproto.client_id",   "Client ID",        base.DEC)
local f_user   = ProtoField.string("labproto.username",    "Username")
local f_pass   = ProtoField.string("labproto.password",    "Password")
local f_status = ProtoField.uint8 ("labproto.status",      "Auth Status",      base.DEC, { [0] = "OK", [1] = "FAIL" })
local f_count  = ProtoField.uint8 ("labproto.lobby_count", "Lobby Count",      base.DEC)
local f_lid    = ProtoField.uint32("labproto.lobby_id",    "Lobby ID",         base.DEC)
local f_lname  = ProtoField.string("labproto.lobby_name",  "Lobby Name")
local f_ghost  = ProtoField.string("labproto.game_host",   "Game Server Host")
local f_gport  = ProtoField.uint16("labproto.game_port",   "Game Server Port", base.DEC)

p.fields = { f_ver, f_type, f_len, f_cid, f_user, f_pass, f_status,
             f_count, f_lid, f_lname, f_ghost, f_gport }

-- Read one length-prefixed string. Returns (range or nil, next_offset).
local function lp(buf, off)
    if off >= buf:len() then return nil, off end
    local n = buf(off, 1):uint()
    if n == 0 then return nil, off + 1 end
    if off + 1 + n > buf:len() then return nil, buf:len() end
    return buf(off + 1, n), off + 1 + n
end

function p.dissector(buf, pinfo, tree)
    if buf:len() < 4 then return 0 end

    local mtype = buf(1, 1):uint()
    local blen  = buf(2, 2):uint()
    local name  = types[mtype] or ("type " .. mtype)
    local info  = name

    pinfo.cols.protocol = "LABPROTO"
    local t = tree:add(p, buf(), "Lab Master Protocol, " .. name)
    t:add(f_ver,  buf(0, 1))
    t:add(f_type, buf(1, 1))
    t:add(f_len,  buf(2, 2))

    if buf:len() < 4 + blen then
        t:append_text(" [truncated]")
        pinfo.cols.info = info .. " [truncated]"
        return buf:len()
    end

    local b = 4

    if mtype == 2 and blen >= 4 then                      -- HELLO_ACK
        t:add(f_cid, buf(b, 4))
        info = info .. " client_id=" .. buf(b, 4):uint()

    elseif mtype == 3 then                                -- AUTH
        local u, o = lp(buf, b)
        if u then
            t:add(f_user, u)
            info = info .. " user=" .. u:string()
        end
        local pw = lp(buf, o)
        if pw then t:add(f_pass, pw) end

    elseif mtype == 4 and blen >= 1 then                  -- AUTH_ACK
        t:add(f_status, buf(b, 1))
        info = info .. (buf(b, 1):uint() == 0 and " OK" or " FAIL")

    elseif mtype == 6 and blen >= 1 then                  -- LOBBY_LIST
        local cnt = buf(b, 1):uint()
        t:add(f_count, buf(b, 1))
        local o = b + 1
        for _ = 1, cnt do
            if o + 4 > buf:len() then break end
            local lid = buf(o, 4)
            local lname, no = lp(buf, o + 4)
            local sub = t:add(p, buf(o, no - o), "Lobby " .. lid:uint())
            sub:add(f_lid, lid)
            if lname then sub:add(f_lname, lname) end
            o = no
        end
        info = info .. " count=" .. cnt

    elseif mtype == 7 then                                -- CREATE_LOBBY
        local lname = lp(buf, b)
        if lname then
            t:add(f_lname, lname)
            info = info .. " name=" .. lname:string()
        end

    elseif mtype == 8 and blen >= 4 then                  -- JOIN
        t:add(f_lid, buf(b, 4))
        info = info .. " lobby=" .. buf(b, 4):uint()

    elseif mtype == 9 then                                -- JOIN_ACK
        local host, o = lp(buf, b)
        if host then t:add(f_ghost, host) end
        if o + 2 <= buf:len() then
            t:add(f_gport, buf(o, 2))
            if host then
                info = info .. " -> " .. host:string() .. ":" .. buf(o, 2):uint()
            end
        end
    end

    pinfo.cols.info = info
    return buf:len()
end

DissectorTable.get("udp.port"):add(9999, p)


-- =====================================================================
-- Game protocol (UDP 10000)
-- =====================================================================

local g = Proto("labgame", "Lab Game Protocol")

local gtypes = {
    [1] = "G_JOIN", [2] = "G_JOIN_ACK",
    [3] = "G_STATE", [4] = "G_SNAPSHOT",
}

local g_ver   = ProtoField.uint8 ("labgame.version",   "Version",      base.DEC)
local g_type  = ProtoField.uint8 ("labgame.type",      "Msg Type",     base.DEC, gtypes)
local g_len   = ProtoField.uint16("labgame.length",    "Body Length",  base.DEC)
local g_pid   = ProtoField.uint32("labgame.player_id", "Player ID",    base.DEC)
local g_x     = ProtoField.int16 ("labgame.x",         "X",            base.DEC)
local g_y     = ProtoField.int16 ("labgame.y",         "Y",            base.DEC)
local g_count = ProtoField.uint8 ("labgame.player_count", "Player Count", base.DEC)

g.fields = { g_ver, g_type, g_len, g_pid, g_x, g_y, g_count }

function g.dissector(buf, pinfo, tree)
    if buf:len() < 4 then return 0 end

    local mtype = buf(1, 1):uint()
    local blen  = buf(2, 2):uint()
    local name  = gtypes[mtype] or ("type " .. mtype)
    local info  = name

    pinfo.cols.protocol = "LABGAME"
    local t = tree:add(g, buf(), "Lab Game Protocol, " .. name)
    t:add(g_ver,  buf(0, 1))
    t:add(g_type, buf(1, 1))
    t:add(g_len,  buf(2, 2))

    if buf:len() < 4 + blen then
        t:append_text(" [truncated]")
        pinfo.cols.info = info .. " [truncated]"
        return buf:len()
    end

    local b = 4

    if mtype == 2 and blen >= 4 then                      -- G_JOIN_ACK
        t:add(g_pid, buf(b, 4))
        info = info .. " player_id=" .. buf(b, 4):uint()

    elseif mtype == 3 and blen >= 4 then                  -- G_STATE
        t:add(g_x, buf(b, 2))
        t:add(g_y, buf(b + 2, 2))
        info = info .. " (" .. buf(b, 2):int() .. "," .. buf(b + 2, 2):int() .. ")"

    elseif mtype == 4 and blen >= 1 then                  -- G_SNAPSHOT
        local cnt = buf(b, 1):uint()
        t:add(g_count, buf(b, 1))
        local parts = {}
        local o = b + 1
        for _ = 1, cnt do
            if o + 8 > buf:len() then break end
            local pid = buf(o, 4):uint()
            local px, py = buf(o + 4, 2):int(), buf(o + 6, 2):int()
            local sub = t:add(g, buf(o, 8), "Player " .. pid .. " @ (" .. px .. "," .. py .. ")")
            sub:add(g_pid, buf(o, 4))
            sub:add(g_x,   buf(o + 4, 2))
            sub:add(g_y,   buf(o + 6, 2))
            parts[#parts + 1] = "p" .. pid .. "(" .. px .. "," .. py .. ")"
            o = o + 8
        end
        info = info .. " count=" .. cnt
        if #parts > 0 then info = info .. " " .. table.concat(parts, " ") end
    end

    pinfo.cols.info = info
    return buf:len()
end

DissectorTable.get("udp.port"):add(10000, g)
