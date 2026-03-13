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

Copyright (c) 2003-2004 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne
All rights reserved.

