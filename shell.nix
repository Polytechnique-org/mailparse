let
  pkgs = import ./common.nix {};
in
pkgs.stdenv.mkDerivation {
  name = "mailparse";
  buildInputs = (
    (with pkgs; [
      cargo
      rust-analyzer
      rustc
    ])
  );
}
