-- ═══════════════════════════════════════════════════════════════════════════
-- XDP DDoS Integration - Lua client for XDP daemon
-- ═══════════════════════════════════════════════════════════════════════════
--
-- Connects ddos.lua to XDP kernel-level blocking daemon
-- Uses ngx.socket.tcp() for non-blocking socket communication
--
-- Usage:
--   local xdp = require("anti-ddos.xdp.xdp_integration")
--   xdp.ban("1.2.3.4", 300, 2)  -- Ban for 300s at level 2
--   xdp.unban("1.2.3.4")        -- Remove ban
--   local stats = xdp.stats()   -- Get daemon stats
--
-- Author: Honeypot WAF Team
-- ═══════════════════════════════════════════════════════════════════════════

local _M = {
    _VERSION = "2.0.0",
    _DESCRIPTION = "XDP DDoS kernel-level blocking integration"
}

local cjson = require("cjson.safe")

-- ═══════════════════════════════════════════════════════════════════════════
-- CONFIGURATION
-- ═══════════════════════════════════════════════════════════════════════════

local config = {
    socket_path = os.getenv("HONEYBAN_SOCKET_PATH") or os.getenv("XDP_SOCKET_PATH") or "/run/honeyban.sock",
    enabled = (os.getenv("HONEYBAN_ENABLED") or os.getenv("XDP_ENABLED") or "1") ~= "0",
    timeout_ms = tonumber(os.getenv("HONEYBAN_TIMEOUT_MS") or os.getenv("XDP_TIMEOUT_MS")) or 100,
    retry_delay_sec = 30,  -- Retry after this many seconds on connection failure
}

-- State
local last_error = nil
local disabled_until = 0

-- ═══════════════════════════════════════════════════════════════════════════
-- SOCKET COMMUNICATION
-- ═══════════════════════════════════════════════════════════════════════════

local function send_command(payload)
    if not config.enabled then
        return nil, "xdp_disabled"
    end
    
    local now = ngx.now()
    if disabled_until > 0 and now < disabled_until then
        return nil, "cooldown"
    end
    
    -- Create socket
    local sock = ngx.socket.tcp()
    if not sock then
        last_error = "socket_create_failed"
        disabled_until = now + config.retry_delay_sec
        return nil, last_error
    end
    
    sock:settimeout(config.timeout_ms)
    
    -- Connect to Unix socket
    local ok, err = sock:connect("unix:" .. config.socket_path)
    if not ok then
        sock:close()
        last_error = "connect:" .. tostring(err)
        disabled_until = now + config.retry_delay_sec
        return nil, last_error
    end
    
    -- Send JSON payload
    local json = cjson.encode(payload)
    if not json then
        sock:close()
        return nil, "json_encode_failed"
    end
    
    local bytes, send_err = sock:send(json .. "\n")
    if not bytes then
        sock:close()
        last_error = "send:" .. tostring(send_err)
        disabled_until = now + config.retry_delay_sec
        return nil, last_error
    end
    
    -- Receive response
    local line, recv_err = sock:receive("*l")
    sock:close()
    
    if not line then
        last_error = "recv:" .. tostring(recv_err)
        disabled_until = now + config.retry_delay_sec
        return nil, last_error
    end
    
    -- Reset error state on success
    disabled_until = 0
    last_error = nil
    
    return line
end

-- ═══════════════════════════════════════════════════════════════════════════
-- PUBLIC API
-- ═══════════════════════════════════════════════════════════════════════════

--- Ban an IP address at kernel level (XDP)
-- @param ip IP address (IPv4 or IPv6)
-- @param ttl TTL in seconds (optional, uses level default if 0)
-- @param level Ban level 1-5 (optional, default 1)
-- @return true on success, nil + error on failure
function _M.ban(ip, ttl, level)
    if not ip or ip == "" then
        return nil, "invalid_ip"
    end
    
    local payload = {
        action = "add",
        ip = ip,
        ttl = tonumber(ttl) or 0,
        level = tonumber(level) or 1
    }
    
    local resp, err = send_command(payload)
    if not resp then
        return nil, err
    end
    
    if resp == "ok" then
        return true
    end
    
    return nil, resp
end

--- Remove ban from an IP address
-- @param ip IP address
-- @return true on success, nil + error on failure
function _M.unban(ip)
    if not ip or ip == "" then
        return nil, "invalid_ip"
    end
    
    local payload = {
        action = "del",
        ip = ip
    }
    
    local resp, err = send_command(payload)
    if not resp then
        return nil, err
    end
    
    if resp == "ok" then
        return true
    end
    
    return nil, resp
end

--- Get daemon statistics
-- @return stats table on success, nil + error on failure
function _M.stats()
    local payload = {
        action = "stats"
    }
    
    local resp, err = send_command(payload)
    if not resp then
        return nil, err
    end
    
    local stats = cjson.decode(resp)
    if not stats then
        return nil, "json_decode_failed"
    end
    
    return stats
end

--- Trigger expired ban cleanup
-- @return true on success, nil + error on failure
function _M.flush()
    local payload = {
        action = "flush"
    }
    
    local resp, err = send_command(payload)
    if not resp then
        return nil, err
    end
    
    return resp == "ok", resp
end

--- Check if XDP daemon is available
-- @return true if available
function _M.is_available()
    if not config.enabled then
        return false
    end
    
    local stats, err = _M.stats()
    return stats ~= nil
end

--- Get last error message
-- @return error string or nil
function _M.get_last_error()
    return last_error
end

--- Check if XDP is enabled in configuration
-- @return boolean
function _M.is_enabled()
    return config.enabled
end

--- Get socket path
-- @return socket path string
function _M.get_socket_path()
    return config.socket_path
end

-- ═══════════════════════════════════════════════════════════════════════════
-- ALIASES (for compatibility with ddos.lua)
-- ═══════════════════════════════════════════════════════════════════════════

-- These match the old hpddosd/send_xdp_ban API
_M.send_ban = _M.ban
_M.send_unban = _M.unban

return _M
