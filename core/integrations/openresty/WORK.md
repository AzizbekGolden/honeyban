# OpenResty integration (optional)

HoneyBan does not require Nginx/OpenResty. This folder contains an optional Lua client that can call the HoneyBan daemon over a Unix socket.

Defaults:

- Socket: `/run/honeyban.sock`

Example (Lua):

```lua
local hb = require("honeyban.xdp_integration")
hb.ban("1.2.3.4", 300, 3)
```

