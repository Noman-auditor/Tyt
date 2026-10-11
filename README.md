# NORA TUNNEL — Phase 4 (VPN core)

Android VPN client (Kotlin, Compose, Material 3). Package `com.nora.tunnel`.

## Phase 1
Gradle setup, manifest, resources (EN + partial BN), adaptive icon, theme, navigation,
Room + DataStore, link parser (vless/vmess/trojan/ss), Splash, Onboarding, Home (UI-only).

## Phase 2 (this zip)
MainViewModel, Profiles list, Profile Details, Server Location (TCP ping), Import (link, file, clipboard, subscription URL), Routing mode (saved).

## Phase 3
Network Lab (ping, traceroute via TTL pings, DNS, speed), Logs (filter, export), Security, Settings, Statistics (chart), About.

## Phase 4
VpnService (foreground, retry x3, kill switch, IPv6 block, network callbacks), Xray config generator and reflection engine, hev tunnel binding, Home on real state, Quick Settings tile, widget, boot auto-connect, traffic stats and logs fed from the service.

## Needs you
Native libs: see NATIVE.md. Not compiled or run in the authoring sandbox.

## Not built
WireGuard, QR scan, per-app routing, split tunnel and custom rules, light theme, language switching.
# Tyt
