# Security policy

This project is a test-only hostapd/wpa_supplicant driver. It is not suitable
for providing a production wireless network.

The transport is intentionally local and unauthenticated: UNIX socket peers
can inject frames when they can access the socket, and UDP is bound to
127.0.0.1. The driver validates and bounds input, but those checks are for
process robustness, not a production security boundary.

Please report vulnerabilities privately to the repository maintainer before
publishing details. Include the affected release, build configuration, a
minimal reproducer, and whether the issue is reachable without
`CONFIG_DRIVER_TEST=y`.
