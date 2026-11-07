{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.pass-secret-portal;
in
{
  options.services.pass-secret-portal = {
    enable = lib.mkEnableOption "Secret portal backed by Secret Service";
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      description = "pass-secret-portal package to run.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      (lib.hm.assertions.assertPlatform "services.pass-secret-portal" pkgs lib.platforms.linux)
    ];

    xdg.portal = {
      enable = true;
      extraPortals = [ cfg.package ];
      config.common."org.freedesktop.impl.portal.Secret" = [ "pass-secret-portal" ];
    };
  };
}
