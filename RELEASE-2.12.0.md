# driver-test-2.12.0

This release adds the user-space `driver=test` / `-Dtest` transport to
hostapd and wpa_supplicant 2.12.

## Base

- Upstream branch: `2_12`
- Upstream release tag: `hostap_2_12`
- Upstream base commit: `831364bf02710ad09c2f27d3efa92abeeb5634c0`
- Downstream commit: `bbe34d7fb` (project tooling and release metadata)

## Artifacts

`hostapd-driver-test-2.12.0.patch` is a generated combined patch against the
upstream base. Its SHA-256 is recorded in `SHA256SUMS`. The source commits in
the `2_12` branch are canonical; the patch is supplied for packagers and users
who maintain a separate upstream checkout.

## Validation

The source patch applies cleanly and reproduces the original 18-file feature
change. Linux CI builds the supplied profiles, runs the upstream unit tests,
and executes open and WPA3-SAE socket-driver smoke tests. The complete matrix,
sanitizer, Valgrind, and fuzzing commands are documented in `DRIVER_TEST.md`
and `pocs/`.
