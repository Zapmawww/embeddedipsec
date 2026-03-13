PCAP Manual Check Guide
=======================

This document describes what the packet dump tool writes into the PCAP file, what the companion labels file means, and what to check manually in Wireshark.

Files produced by the tool

- `<file.pcap>` is a classic PCAP capture with link type `RAW` (value `101`). Each frame starts directly with an IPv4 or IPv6 header. There is no Ethernet header.
- `<file.pcap>.labels.txt` is a sidecar manifest because classic PCAP cannot store per-packet comments. Each line maps one frame number to a test case label and the packet length written into the PCAP.

How the tool builds the capture

- The generator uses `ipsec_output()` for IPv4 and `ipsec_output_ipv6()` for IPv6.
- Each input packet is a minimal TCP packet with no payload. The plaintext packet is either `20 + 20 = 40` bytes for IPv4 or `40 + 20 = 60` bytes for IPv6.
- The capture currently contains 10 frames. Their order is fixed and verification expects the same order.
- The verifier reads the PCAP back, feeds each protected packet into `ipsec_input()`, and checks that the recovered plaintext packet exactly matches the original packet template for that case.

Expected frame order

1. `ipv4-ah-transport-md5`
2. `ipv4-ah-tunnel-sha1`
3. `ipv6-ah-transport-sha1`
4. `ipv6-ah-tunnel-md5`
5. `ipv4-esp-transport-aes`
6. `ipv4-esp-transport-aes-sha1`
7. `ipv4-esp-tunnel-3des`
8. `ipv6-esp-transport-aes-sha1`
9. `ipv6-esp-tunnel-3des`
10. `ipv6-esp-tunnel-aes-sha1`

Expected packet lengths

These lengths are deterministic for the current test matrix and are a quick sanity check that the transform layout is stable.

1. `ipv4-ah-transport-md5`: 64 bytes
2. `ipv4-ah-tunnel-sha1`: 84 bytes
3. `ipv6-ah-transport-sha1`: 84 bytes
4. `ipv6-ah-tunnel-md5`: 124 bytes
5. `ipv4-esp-transport-aes`: 76 bytes
6. `ipv4-esp-transport-aes-sha1`: 88 bytes
7. `ipv4-esp-tunnel-3des`: 84 bytes
8. `ipv6-esp-transport-aes-sha1`: 108 bytes
9. `ipv6-esp-tunnel-3des`: 120 bytes
10. `ipv6-esp-tunnel-aes-sha1`: 140 bytes

Expected protocol content

AH transport cases

- The IP version and source and destination addresses stay the same as the original packet.
- The IP `Protocol` field for IPv4 or `Next Header` field for IPv6 is `AH`.
- Wireshark should decode an Authentication Header between the IP header and the TCP header.
- The SPI values are:
  - frame 1: `0x00006101`
  - frame 3: `0x00006103`
- The TCP ports in the decapsulated payload are:
  - frame 1: `1101 -> 2101`
  - frame 3: `1103 -> 2103`

AH tunnel cases

- The outer packet uses different IP addresses than the inner packet.
- The outer IP `Protocol` or `Next Header` is `AH`.
- After AH, Wireshark should show a complete inner IP packet.
- The SPI values are:
  - frame 2: `0x00006102`
  - frame 4: `0x00006104`
- Inner TCP ports are:
  - frame 2: `1102 -> 2102`
  - frame 4: `1104 -> 2104`

ESP transport cases

- The IP version and addresses stay the same as the original packet.
- The IP `Protocol` or `Next Header` is `ESP`.
- Wireshark should show an ESP header with the expected SPI, but it will not decrypt the payload unless manual ESP decryption is configured.
- The SPI values are:
  - frame 5: `0x00006201`
  - frame 6: `0x00006202`
  - frame 8: `0x00006204`

ESP tunnel cases

- The outer IP addresses are the tunnel endpoints.
- The IP `Protocol` or `Next Header` is `ESP`.
- After decryption, the payload should be a full inner IPv4 or IPv6 packet.
- The SPI values are:
  - frame 7: `0x00006203`
  - frame 9: `0x00006205`
  - frame 10: `0x00006206`

Addresses used by the cases

IPv4 transport addresses

- frame 1 outer and inner: `192.168.1.10 -> 192.168.1.20`
- frame 5 outer and inner: `192.168.2.10 -> 192.168.2.20`
- frame 6 outer and inner: `192.168.3.10 -> 192.168.3.20`

IPv4 tunnel addresses

- frame 2 inner: `10.0.0.10 -> 10.0.0.20`
- frame 2 outer: `192.168.10.1 -> 192.168.20.1`
- frame 7 inner: `10.1.0.10 -> 10.1.0.20`
- frame 7 outer: `192.168.30.1 -> 192.168.40.1`

IPv6 addresses

- transport inner and outer: `2001:db8:11::10 -> 2001:db8:22::20`
- tunnel outer: `2001:db8:aa::1 -> 2001:db8:bb::2`

How to generate the files

Run the generator from the repository root:

```powershell
.\build\Debug\embeddedipsec_packet_dump_tool.exe generate .\build\embeddedipsec-manual-check.pcap
```

This should create:

- `build\embeddedipsec-manual-check.pcap`
- `build\embeddedipsec-manual-check.pcap.labels.txt`

How to check in Wireshark

1. Open the PCAP file in Wireshark.
2. Open the labels text file next to it so you can map each frame number to the intended test case.
3. Confirm there are exactly 10 frames.
4. Confirm each frame length matches the value in the labels file.
5. For frames 1 to 4, verify that Wireshark decodes AH and that the SPI matches the expected value above.
6. For frames 5 to 10, verify that Wireshark decodes ESP and that the SPI matches the expected value above.
7. For transport cases, verify that the outer source and destination addresses are the same as the protected flow addresses.
8. For tunnel cases, verify that the outer addresses are tunnel endpoints and that the payload represents a full inner IP packet after AH or ESP.
9. For AH cases, verify that the header immediately after AH is TCP for transport mode or IPv4 or IPv6 for tunnel mode.
10. For ESP cases without decryption configured, verify at least the outer IP version, outer addresses, next-header value of ESP, SPI, and packet length.

Optional ESP decryption in Wireshark

If you want Wireshark to decode the inner ESP payload, add the corresponding SAs in Wireshark's ESP preferences.

Encryption and authentication material used by the tool

- AES-CBC key: `2b7e151628aed2a6abf7158809cf4f3c`
- 3DES-CBC key: `012345670123456701234567012345670123456701234567`
- HMAC key: `0123456701234567012345670123456789abcdef`

Per-case algorithms

- frame 5: AES-CBC, no authentication
- frame 6: AES-CBC with HMAC-SHA1-96
- frame 7: 3DES-CBC, no authentication
- frame 8: AES-CBC with HMAC-SHA1-96
- frame 9: 3DES-CBC, no authentication
- frame 10: AES-CBC with HMAC-SHA1-96

How to check with the built-in verifier

Run:

```powershell
.\build\Debug\embeddedipsec_packet_dump_tool.exe verify .\build\embeddedipsec-manual-check.pcap
```

The verification succeeds only if all of the following are true:

- the file is a classic PCAP with link type `RAW`
- all 10 expected records are present in the expected order
- every protected packet can be decapsulated by `ipsec_input()`
- every recovered plaintext packet exactly matches the original IPv4 or IPv6 TCP template for that case

Common manual-check failures

- If Wireshark does not recognize the frames as IP, the capture was not written as link type `RAW`.
- If the frame count is not 10, the capture is incomplete or from a different tool revision.
- If an AH packet length changes unexpectedly, header construction or integrity data size changed.
- If an ESP packet length changes unexpectedly, IV size, padding, integrity data, or tunnel encapsulation changed.
- If transport mode shows different outer and inner addresses, the packet was built as tunnel mode or was modified incorrectly.
- If tunnel mode does not show different outer and inner addresses, outer encapsulation is wrong.
