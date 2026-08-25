```bash
# verify config changes
sudo bpftool map dump name config_map

# for tcp floods (for lo)
hping3 -S -p 8080 --flood 192.168.10.1

# for upd flood test
iperf3 -s -D
iperf3 -c 127.0.0.1 -u -b 100M -l 64 -t 10
pkill iperf3

# unsolicited packets
sudo hping3 -2 -p 9999 127.0.0.1 -c 1
```
