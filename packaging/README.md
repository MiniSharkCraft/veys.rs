# VeySRS v0.6.0 Packaging

The packaging files describe the native Linux installation layout:

```text
/usr/bin/veysrs
/etc/veysrs/veysrs.veysrule
/var/lib/veysrs/www
/var/lib/veysrs
/var/log/veysrs
/usr/lib/systemd/system/veysrs.service
/usr/share/doc/veysrs
```

Run the service as a dedicated `veysrs` user and group. The unit is hardened
with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
restricted address families, and explicit writable paths.

## Source release archive

From the repository root, create a clean source archive without `target/`,
`.git/`, credentials, temporary files, or previous package outputs:

```bash
git archive --format=tar.gz --prefix=veysrs-0.6.0/ \
  -o release/veysrs-0.6.0.tar.gz HEAD
```

The archive contains source, documentation, packaging metadata, and the
systemd unit. It does not contain a compiled binary.

## Debian

The Debian metadata is in `debian/`; the mirrored release metadata under
`packaging/debian/` is used by source-package workflows. When `dpkg-buildpackage`
and debhelper are available:

```bash
dpkg-buildpackage -us -uc
```

For a local package build without signing:

```bash
debuild -us -uc
```

The package installs `/usr/bin/veysrs` and the systemd unit. Create the service
user and writable directories before enabling the unit. Package installation
and runtime validation are environment-dependent and are not implied by the
presence of these metadata files.

## Arch Linux

`packaging/arch/PKGBUILD` builds `veysrs-0.6.0`. Place the clean
`veysrs-0.6.0.tar.gz` beside the PKGBUILD, then run in an Arch build
environment:

```bash
makepkg -sf
sudo pacman -U ./veysrs-0.6.0-1-*.pkg.tar.zst
```

The PKGBUILD uses `cargo build --release --locked` and installs the binary and
unit. Arch installation has not been claimed unless an Arch environment is
available.

## Manual/systemd installation

```bash
install -d -o veysrs -g veysrs /etc/veysrs /var/lib/veysrs/www /var/log/veysrs
install -m 0644 packaging/systemd/veysrs.service /usr/lib/systemd/system/veysrs.service
install -m 0755 target/release/veysrs /usr/bin/veysrs
install -m 0644 .veysrule /etc/veysrs/veysrs.veysrule
systemctl daemon-reload
systemctl enable --now veysrs
```

Use `systemctl reload veysrs` or `veysrs config reload` for validated atomic
reloads. HTTP/3 and QUIC are not packaged or supported in v0.6.0.

## Docker

`packaging/Dockerfile` is a build/runtime artifact description only. A Docker
daemon and registry are required to build and run it; no Docker runtime result
is claimed when those services are unavailable.
