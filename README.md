embedded IPsec
==============

 - [./src/](src/) - embedded IPsec library
 - [./doc/html/](https://cdn.rawgit.com/tinytux/embeddedipsec/master/doc/html/index.html) - source code documentation

Build-time feature switches

 - `EMBEDDEDIPSEC_ENABLE_AH` and `EMBEDDEDIPSEC_ENABLE_ESP` control protocol support.
 - `EMBEDDEDIPSEC_ENABLE_TUNNEL_MODE` and `EMBEDDEDIPSEC_ENABLE_TRANSPORT_MODE` control mode support.
 - Defaults keep all four enabled.
 - The build rejects configurations that disable both protocols or both modes.

ESP encryption backends

 - ESP now supports `IPSEC_AES_CBC` with an internal wrapper in `src/core/aes_cbc.c`.
 - The current AES-CBC implementation is backed by the vendored `tiny-aes` sources and is compiled with CBC enabled and ECB/CTR disabled.
 - The wrapper isolates the AES backend so it can be replaced later with an ASIC or hardware-accelerated implementation without changing the ESP packet logic.

Modern lwIP porting

 - `src/include/netif/ipsec_lwip_adapter.h` and `src/netif/ipsec_lwip_adapter.c` provide a direct-hook lwIP adapter skeleton based on a fixed-size work buffer.
 - `doc/lwip-porting.md` documents the intended hook points in lwIP 2.1.x and the multiple-netif integration model.
 - The legacy fake-netif adapter in `src/netif/ipsecdev.c` remains for reference, but it is not the recommended path for a modern lwIP port.

Packet dump tool

 - `embeddedipsec_packet_dump_tool generate <file.pcap>` writes protected raw IP packets to a PCAP file that can be opened directly in Wireshark.
 - `embeddedipsec_packet_dump_tool verify <file.pcap>` reads the same capture back through `ipsec_input()` and checks that decapsulation recovers the expected plaintext packets.
 - `embeddedipsec_packet_dump_tool roundtrip <file.pcap>` runs both steps and is also registered as a CTest test.
 - The generator also writes `<file.pcap>.labels.txt` with per-frame labels because classic PCAP cannot store packet comments.
 - `doc/packet-dump-manual-check.md` documents the expected PCAP contents and a manual Wireshark verification workflow.

Copyright (c) 2003-2004 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne
All rights reserved.

