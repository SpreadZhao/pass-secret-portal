# pass-secret-portal

A C11 Secret portal backend that uses an existing
`org.freedesktop.secrets` service. It is intended for pass-secret-service and
requires a default collection and support for the `plain` session algorithm.
It uses libsystemd, with no direct GTK, GLib or Rust dependency.

Applications call `org.freedesktop.portal.Secret` through xdg-desktop-portal.
This backend implements `org.freedesktop.impl.portal.Secret` version 1 at
`/org/freedesktop/portal/desktop`, under
`org.freedesktop.impl.portal.desktop.passsecret`.

## Storage

Each application gets a stable 64-byte key from the operating system's random
number generator. The backend stores it as 128 lowercase hexadecimal characters
in the default collection, so services that accept only UTF-8 secrets can store
it. Applications receive the original binary key through a file descriptor.

Records use these attributes:

```text
xdg:schema=org.freedesktop.portal.Secret
app_id=<ID supplied by xdg-desktop-portal>
pass-secret-portal-format=hex-v1
```

The schema and application ID identify candidate records. Duplicate candidates,
missing format tags and malformed keys cause the request to fail. The backend
does not replace incompatible records or regenerate keys after a lookup or
decryption failure. Back up the password store and its item metadata together;
losing a portal key can make an application's encrypted data unreadable.

Only the current owner of `org.freedesktop.portal.Desktop` may retrieve keys or
cancel requests. Application identity comes from that frontend. Requests with an
empty application ID share one record. This does not add isolation between
unsandboxed programs running as the same user.

Store operations run asynchronously in one serialized queue. Cancelling a
request stops delivery to its file descriptor. An outstanding store operation
may finish, and the next request reuses any key it saved. Cancellation does not
stop the shared GPG agent or its prompts. Requests time out after two minutes.
Keys are never written to logs or plaintext temporary files.

## Home Manager

Add `github:SpreadZhao/pass-secret-portal/main` as a flake input, make its nixpkgs
input follow yours, and import `inputs.pass-secret-portal.homeManagerModules.default`:

```nix
services.pass-secret-portal.enable = true;
```

The module installs the backend and selects it for the Secret interface. It
does not provide a Secret Service or initialize a password store. Keep the
existing pass-secret-service configuration and GPG identity.

The package includes D-Bus activation and a systemd user service tied to
`graphical-session.target`. On NixOS with `home-manager.useUserPackages`, expose
`/share/xdg-desktop-portal` and `/share/applications` with
`environment.pathsToLink`, as required by Home Manager's portal module.

```sh
systemctl --user status pass-secret-portal.service
journalctl --user -u pass-secret-portal.service
```

## Build

```sh
nix build --no-link "path:$PWD"
nix develop "path:$PWD"
```

The flake exports packages, an app, a Home Manager module, a build check, a
formatter and a development shell for `x86_64-linux` and `aarch64-linux`.
