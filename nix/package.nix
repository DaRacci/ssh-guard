{
  self,
  inputs,
  pkgs
}: let
  rustToolchain = (pkgs.extend inputs.rust-overlay.overlays.default).rust-bin.nightly.latest.default;
  customRustPlatform = pkgs.makeRustPlatform {
    rustc = rustToolchain;
    cargo = rustToolchain;
  };
in customRustPlatform.buildRustPackage {
  pname = "ssh-guard";
  version = "0.1.0";
  src = "${self}";

  cargoHash = "sha256-4XvLZgUw2RA4LWFjy3coskNn1bZIYOlYsZFZKH4ygHI=";

  meta = {
    description = "Restricted SSH command guard";
    license = pkgs.lib.licenses.agpl3Only;
    mainProgram = "ssh-guard";
  };
}
