{
  inputs,
  pkgs,
  lib,
  ...
}:
let
  fs = lib.fileset;

  rustToolchain = (pkgs.extend inputs.rust-overlay.overlays.default).rust-bin.nightly.latest.default;
  customRustPlatform = pkgs.makeRustPlatform {
    rustc = rustToolchain;
    cargo = rustToolchain;
  };

  cargoToml = fromTOML (builtins.readFile ../Cargo.toml);
  version = cargoToml.package.version;
in
customRustPlatform.buildRustPackage {
  inherit version;
  pname = "ssh-guard";

  src = fs.toSource {
    root = ../.;
    fileset = fs.unions [
      ../src
      ../Cargo.toml
      ../Cargo.lock
      ../tests
    ];
  };

  cargoHash = "sha256-XvgFyA1I8qfG1WU2ELRZ2Dn1ZXsoafBSu1uCMlw0Nwo=";

  meta = {
    description = "Restricted SSH command guard";
    license = lib.licenses.agpl3Only;
    mainProgram = "ssh-guard";
  };
}
