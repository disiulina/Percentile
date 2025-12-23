#!/usr/bin/lua

local tcpdump_path = "/usr/bin/tcpdump"    -- lokasi tcpdump kamu
local iface = "br-lan"                     -- sesuaikan interface routermu
local sample_size = 20                     -- jumlah ARP sample untuk hitung entropy
local last_entropy = 0

-- Fungsi hitung entropy
local function calculate_entropy(counts)
    local total = 0
    for _,c in pairs(counts) do
        total = total + c
    end

    local entropy = 0
    for _,c in pairs(counts) do
        local p = c / total
        entropy = entropy - p * math.log(p, 2)
    end
    return entropy
end

print("[*] ARP Spoof Detector Running...")
print("[*] Sniffing on interface: " .. iface)
print("[*] Using tcpdump: " .. tcpdump_path)

while true do
    -- jalankan tcpdump 20 ARP packet
    local cmd = tcpdump_path .. " -nn -e -c " .. sample_size .. " -i " .. iface .. " arp"
    local handle = io.popen(cmd)
    local output = handle:read("*all")
    handle:close()

    -- hitung MAC frequency
    local mac_counts = {}
    for mac in output:gmatch("([0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f])") do
        mac = mac:lower()
        mac_counts[mac] = (mac_counts[mac] or 0) + 1
    end

    -- minimal butuh data
    if next(mac_counts) ~= nil then
        local entropy = calculate_entropy(mac_counts)

        if math.abs(entropy - last_entropy) > 0.2 then
            print(string.format("[ALERT] Entropy changed: %.3f -> %.3f", last_entropy, entropy))
            print("[+] Possible ARP Spoofing Activity Detected!")
        else
            print(string.format("[OK] Entropy: %.3f (stable)", entropy))
        end

        last_entropy = entropy
    else
        print("[!] No ARP packets captured, waiting...")
    end

    os.execute("sleep 2")
end
