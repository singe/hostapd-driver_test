# hostapd user-space driver test

This downstream hostapd/wpa_supplicant fork restores a modernized
`driver=test` transport for protocol testing when Linux wireless kernel access
or `mac80211_hwsim` is unavailable.

It lets a hostapd AP and one or more wpa_supplicant stations exchange 802.11
management frames and EAPOL over local UNIX datagram sockets. Loopback UDP is
also available. The normal hostapd and wpa_supplicant authentication,
association, RSN, EAP, RADIUS, SAE, OWE, FT, FILS, PMF, and MLO state machines
run unchanged above the test-driver layer.

This is complementary to hwsim, not a replacement for it. hwsim exercises the
real nl80211/cfg80211/mac80211 stack and kernel behavior; this project is for
kernel-less CI and userspace protocol testing.

## What it does not emulate

The test driver has no wireless interface, PHY, RF timing, radio scheduling,
real encryption, regulatory state, or IP data plane. It cannot validate DHCP,
ordinary data traffic, channel behavior, DFS/CAC, airtime, signal levels, or
driver-specific nl80211 behavior. It is not suitable for production wireless
service.

## Quick start

Build with the supplied profiles:

```sh
cp tests/build/build-hostapd-driver-test.config hostapd/.config
cp tests/build/build-wpa_supplicant-driver-test.config wpa_supplicant/.config
make -C hostapd -j"$(getconf _NPROCESSORS_ONLN)"
make -C wpa_supplicant -j"$(getconf _NPROCESSORS_ONLN)"
```

The feature is opt-in:

```text
CONFIG_DRIVER_TEST=y
```

Use `driver=test` in hostapd and `-Dtest` in wpa_supplicant. A minimal smoke
test is:

```sh
HOSTAP_SRC="$PWD" pocs/driver-test-wpa2-wpa3.sh --only open
```

The full scenario runner covers WPA2/EAP, WPA3-SAE, FT, FILS, 6 GHz/EHT, MLO,
UDP transport, timeouts, peer loss, and malformed datagrams:

```sh
HOSTAP_SRC="$PWD" pocs/driver-test-wpa2-wpa3.sh
```

## Documentation

- [Detailed driver guide](DRIVER_TEST.md)
- [Doxygen driver documentation](doc/testing_tools.doxygen)
- [Release and maintenance notes](RELEASE-2.12.0.md)
- [Security policy](SECURITY.md)
- [Generated patch](dist/hostapd-driver-test-2.12.0.patch)
- [Original upstream README](UPSTREAM-README.md)

The public `2_12` branch is based on upstream `hostap_2_12`. The project
publishes tags as `driver-test-2.12.N`; source commits are canonical and the
combined patch is provided for downstream packagers.
