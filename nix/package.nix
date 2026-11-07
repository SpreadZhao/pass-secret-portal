{
  lib,
  stdenv,
  pkg-config,
  systemdLibs,
}:

stdenv.mkDerivation {
  pname = "pass-secret-portal";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src
      ../data
      ../LICENSE
    ];
  };

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ systemdLibs ];

  buildPhase = ''
    runHook preBuild
    $CC -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
      $(pkg-config --cflags libsystemd) \
      -o pass-secret-portal src/pass-secret-portal.c \
      $(pkg-config --libs libsystemd)
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -Dm755 pass-secret-portal "$out/bin/pass-secret-portal"
    install -Dm644 data/pass-secret-portal.portal \
      "$out/share/xdg-desktop-portal/portals/pass-secret-portal.portal"
    mkdir -p "$out/share/systemd/user" "$out/share/dbus-1/services"
    substitute data/pass-secret-portal.service.in \
      "$out/share/systemd/user/pass-secret-portal.service" \
      --replace-fail '@executable@' "$out/bin/pass-secret-portal"
    substitute data/org.freedesktop.impl.portal.desktop.passsecret.service.in \
      "$out/share/dbus-1/services/org.freedesktop.impl.portal.desktop.passsecret.service" \
      --replace-fail '@executable@' "$out/bin/pass-secret-portal"
    install -Dm644 LICENSE "$out/share/licenses/pass-secret-portal/LICENSE"
    runHook postInstall
  '';

  meta = {
    description = "Secret portal backed by an existing Secret Service";
    homepage = "https://github.com/SpreadZhao/pass-secret-portal";
    license = lib.licenses.mit;
    mainProgram = "pass-secret-portal";
    platforms = lib.platforms.linux;
  };
}
