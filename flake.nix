{
  description = "Minimal Secret portal for an existing Secret Service";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      eachSystem = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      packages = eachSystem (
        system:
        let
          package = (pkgsFor system).callPackage ./nix/package.nix { };
        in
        {
          default = package;
          pass-secret-portal = package;
        }
      );

      apps = eachSystem (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/pass-secret-portal";
          meta.description = "Run the Secret portal backend";
        };
      });

      homeManagerModules.default = import ./nix/home-manager.nix;
      checks = eachSystem (system: {
        default = self.packages.${system}.default;
      });
      formatter = eachSystem (system: (pkgsFor system).nixfmt);
      devShells = eachSystem (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              gcc
              clang-tools
              pkg-config
              systemdLibs
              nixfmt
            ];
          };
        }
      );
    };
}
