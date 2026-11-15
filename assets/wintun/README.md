# Wintun for Windows x64

Official signed Wintun 0.14.1 AMD64 DLL, distributed unmodified under the included license.
Source: https://www.wintun.net/builds/wintun-0.14.1.zip
Archive SHA256: `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`

The Windows installer places the DLL beside Billow.exe. TUN uses Windows UAC when
the application is not elevated; cancelling consent keeps the existing connection.
The adapter probe and kernel startup still must succeed before TUN is shown as enabled.
