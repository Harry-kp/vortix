{
  description = "vortix Rust TUI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, flake-utils, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        craneLib = crane.mkLib pkgs;

        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        vortix = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          # Tests exercise local user state and can fail in Nix build sandboxes.
          doCheck = false;

          meta = with pkgs.lib; {
            description = "Terminal UI for WireGuard and OpenVPN with real-time telemetry and leak guarding";
            homepage = "https://github.com/Harry-kp/vortix";
            license = licenses.mit;
            mainProgram = "vortix";
            platforms = platforms.unix;
          };
        });
      in
      {
        packages.default = vortix;
        packages.vortix = vortix;

        apps.default = flake-utils.lib.mkApp { drv = vortix; };

        checks = {
          # `nix flake check` builds the package; if it builds, the flake is sound.
          inherit vortix;

          vortix-fmt = craneLib.cargoFmt { inherit (commonArgs) src; };
        };

        formatter = pkgs.nixpkgs-fmt;

        devShells.default = pkgs.mkShell {
          inputsFrom = [ vortix ];
          packages = with pkgs; [
            cargo
            clippy
            rustc
            rustfmt
          ];
        };
      }
    );
}
