#!/usr/bin/lua

-- ARP Spoofing Detector using P10 Percentile
-- =========================================

local tcpdump_path = "/usr/bin/tcpdump"
local iface = "br-lan"

-- config
local WINDOW_SIZE = 50
local P10_THRESHOLD = 2

-- storage
local log_monitor_ip_mac = {}
local captured_macs = {}
local sender_macs = {}

-- utility: split string
local function split(str, sep)
    local t = {}
    for s in string.gmatch(str, "([^"..sep.."]+)") do
        table.insert(t, s)
    end
    return t
end

-- percentile function
local function compute_p10(freq_list)
    table.sort(freq_list)
    local n = #freq_list
    if n == 0 then return 0 end

    local index = math.floor(0.10 * n)
    if index < 1 then index = 1 end
    return freq_list[index]
end

-- frequency counter
local function count_frequencies(mac_list)
    local freq = {}
    for _, mac in ipairs(mac_list) do
        freq[mac] = (freq[mac] or 0) + 1
    end

    local values = {}
    for _, v in pairs(freq) do
        table.insert(values, v)
    end
    return values
end

-- check IP-MAC match
local function matchMacToIp(ip, mac)
    return log_monitor_ip_mac[ip] == mac
end

-- filter attacker traffic
local function filterAttackerTraffic(mac)
    captured_macs[mac] = true
end

-- main logic
print("[*] Starting ARP Detector (P10 mode)...")

local handle = io.popen(tcpdump_path ..
    " -l -n -e -i " .. iface .. " arp")

local count = 0

for line in handle:lines() do
    print("[TCPDUMP]", line)
    -- extract MAC address
    local mac = string.match(line, "([%x:][%x:]:[%x:][%x:]:[%x:][%x:]:[%x:][%x:]:[%x:][%x:]:[%x:][%x:])")
    local ip = string.match(line, "Reply (%d+%.%d+%.%d+%.%d+)")
              or string.match(line, "Request who%-has (%d+%.%d+%.%d+%.%d+)")

    if mac then
        table.insert(sender_macs, mac)
        count = count + 1
    end

    if count >= WINDOW_SIZE then
        -- compute P10
        local freq_list = count_frequencies(sender_macs)
        local p10 = compute_p10(freq_list)

        print("[*] P10 value:", p10)

        if p10 < P10_THRESHOLD then
            print("[!] Possible ARP Spoofing Detected (P10 anomaly)")

            if ip and mac then
                if not matchMacToIp(ip, mac) then
                    print("[!!] IP-MAC mismatch:", ip, mac)
                    filterAttackerTraffic(mac)
                end
            end
        end

        -- reset window
        sender_macs = {}
        count = 0
    end
end
