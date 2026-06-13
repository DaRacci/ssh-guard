{
  description = "ssh-guard: restricted SSH command guard daemon and NixOS module";

  inputs = {
    devenv-root = {
      url = "file+file:///dev/null";
      flake = false;
    };
    nixpkgs.url = "github:cachix/devenv-nixpkgs/rolling";
    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    devenv.url = "github:cachix/devenv";
    treefmt.url = "github:numtide/treefmt-nix";
    treefmt.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  nixConfig = {
    extra-trusted-public-keys = "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw=";
    extra-substituters = "https://devenv.cachix.org";
  };

  outputs =
    inputs@{ flake-parts, self, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      debug = true;
      imports = [
        inputs.devenv.flakeModule
        inputs.treefmt.flakeModule
      ];

      flake.nixosModules = {
        default = import ./nix/modules/nixos/ssh-guard.nix { inherit self; };
        ssh-guard = import ./nix/modules/nixos/ssh-guard.nix { inherit self; };
      };

      systems = [
        "x86_64-linux"
        "i686-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem =
        { pkgs, ... }:
        rec {
          packages.default = pkgs.callPackage ./nix/package.nix { inherit self inputs pkgs; };

          devenv.shells.default = {
            containers = pkgs.lib.mkForce { };
            packages = with pkgs; [
              cargo-deny
              cargo-llvm-cov
              cargo-nextest
              cargo-vet
            ];

            languages.rust = {
              enable = true;
              # Only reason to use nightly is for llvm-tools & the no_coverage attribute, so we can get coverage reports working.
              # All code should be compatible with stable, and we should be able to switch to stable once possible.
              channel = "nightly";
              components = [
                "rustc"
                "cargo"
                "clippy"
                "rustfmt"
                "rust-analyzer"
                "llvm-tools"
              ];
              wild.enable = true;
            };
          };

          treefmt = {
            projectRootFile = ".git/config";

            programs = {
              nixfmt.enable = true;
              statix.enable = true;
              mdformat.enable = true;
              rustfmt = {
                enable = true;
                package = devenv.shells.default.languages.rust.packages.rustfmt;
              };
            };
          };

          packages.ssh-guard-vm = import ./nix/tests/ssh-guard-vm.nix { inherit self pkgs; };
          checks.ssh-guard-vm = packages.ssh-guard-vm;
        };
    };
}
