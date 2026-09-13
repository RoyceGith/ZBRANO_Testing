# ZBRANO access security

Starting with v0.13.251, open ZBRANO from the Home Assistant sidebar or the
add-on's **Open Web UI** button. Direct browser access on port 8099 is blocked,
including on installations that retained an older port mapping.

## Optional Assist connection

1. Open ZBRANO through Home Assistant and create a pairing key in the Assist setup.
2. In the add-on Configuration, enable **Allow paired Assist connections** and restart.
3. If your integration connects using the Home Assistant host address on port 8099,
   map `8099/tcp` to `8099` in the add-on Network settings and restart. New
   installations have no host port mapped by default.
4. Configure the ZBRANO Assist integration with that local address and pairing key.
   The key permits only Assist health and conversation requests; it cannot open
   the UI, create pairing keys, download backups, or change plugin settings.

The existing `enable_direct_port` configuration key now controls this limited
Assist access. Turning it on never enables direct browser access. Existing
installations retaining `true` continue to require a valid pairing key.

## Gmail and GitHub connections

Start Connect from ZBRANO inside Home Assistant. Use the callback URL displayed
in the plugin setup guide opened there. If a provider was configured using a
direct port URL, replace it with this Ingress callback URL in the provider's
application settings. OAuth callbacks also require Ingress; state validation
and the existing PKCE flow remain in place.

## Enforced boundary

The application accepts general UI, API and WebSocket traffic only from the
Supervisor Ingress socket peer `172.30.32.2`, following the
[Home Assistant Ingress guidance](https://developers.home-assistant.io/docs/apps/presentation/).
Uvicorn runs with `--no-proxy-headers`; user-supplied forwarding headers cannot
grant access. Missing peers and loopback callers are rejected. Home Assistant
handles login and Ingress authorization; ZBRANO retains its admin-only panel.

Static files must resolve inside the static directory, including after symlink
resolution. Encoded parent traversal and absolute paths cannot read sibling files.

Regression tests cover anonymous reads and writes, header spoofing, Assist key
scope and rotation, OAuth state handling, traversal and WebSockets. Symlink tests
run on hosts that permit symlink creation, including Linux image builds.

This addresses the reproduced access and file traversal flaws; it is not a
complete penetration test. Live router rules and prior exposure were not tested.
If an older version was exposed to the internet, rotate stored provider credentials
and review access history: updating prevents the identified access paths but cannot
undo an earlier credential disclosure.
