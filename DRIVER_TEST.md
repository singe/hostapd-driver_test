# User-space driver test

This branch adds a local, user-space transport for exercising hostapd and
wpa_supplicant protocol code without `mac80211_hwsim`, nl80211, cfg80211, or
wireless hardware.

The implementation is deliberately a test driver. It exchanges management and
EAPOL frames over UNIX datagram sockets (or loopback UDP), but does not model a
PHY, RF timing, encryption, regulatory state, or an IP data plane. The hwsim
tests remain the appropriate tests for the kernel/mac80211/nl80211 path.

## Building

Start from this checkout and use the supplied profiles:

```sh
cp tests/build/build-hostapd-driver-test.config hostapd/.config
cp tests/build/build-wpa_supplicant-driver-test.config wpa_supplicant/.config
make -C hostapd -j"$(getconf _NPROCESSORS_ONLN)"
make -C wpa_supplicant -j"$(getconf _NPROCESSORS_ONLN)"
make -C tests -j"$(getconf _NPROCESSORS_ONLN)"
make -C tests run-tests
```

The feature is opt-in with `CONFIG_DRIVER_TEST=y`. It is selected at runtime
with `driver=test` in hostapd and `-Dtest` in wpa_supplicant. See the generated
driver documentation in `doc/testing_tools.doxygen` for transport parameters,
the `HTD1` version-1 datagram format, and limitations.

## Scenario tests

After building, run a smoke test without a wireless interface:

```sh
HOSTAP_SRC="$PWD" pocs/driver-test-wpa2-wpa3.sh --only open
HOSTAP_SRC="$PWD" pocs/driver-test-wpa2-wpa3.sh --only wpa3-sae
```

The complete matrix is intentionally longer and includes WPA2/EAP, FT, FILS,
6 GHz, EHT, MLO, UDP, timeout, peer-loss, and malformed-input scenarios:

```sh
HOSTAP_SRC="$PWD" pocs/driver-test-wpa2-wpa3.sh
```

The runner resolves authentication fixtures from the existing upstream test
fixture directory `tests/hwsim/auth_serv`; this project adds no credentials or
key material of its own.

## Release and maintenance model

The `2_12` branch is based on upstream `hostap_2_12`. The `upstream` remote
tracks the upstream `2_12` maintenance branch. Downstream releases use tags of
the form `driver-test-2.12.N`; each release records the exact upstream base
commit in its release notes.

The source commits are canonical. `scripts/make-patch.sh` produces a combined
patch for packagers and downstream users. Published maintenance commits are
not rebased; upstream fixes are merged and the test matrix is rerun before a
new release tag is made.

This is an independent downstream project. Upstream hostapd acceptance is not
a prerequisite for its releases.
