{
  description = "Description for the project";

  inputs = {
    devenv-root = {
      url = "file+file:///dev/null";
      flake = false;
    };
    nixpkgs.url = "github:cachix/devenv-nixpkgs/rolling";
    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    devenv.url = "github:cachix/devenv";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  nixConfig = {
    extra-trusted-public-keys = "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw=";
    extra-substituters = "https://devenv.cachix.org";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.devenv.flakeModule
      ];

      systems = [
        "x86_64-linux"
        "i686-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem =
        { pkgs, ... }:
        {
          packages.default = pkgs.rustPlatform.buildRustPackage {
            pname = "ssh-guard";
            version = "0.1.0";
            src = ./.;

            cargoHash = "sha256-7vkwNmtwvgTs2wt+lF8smjtg1Huke54WZJ9UvLy48tU=";

            meta = {
              description = "Restricted SSH command guard";
              license = pkgs.lib.licenses.agpl3Only;
              mainProgram = "ssh-guard";
            };
          };

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
        };
    };
}
