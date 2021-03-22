with import ./common.nix;

pkgs.stdenv.mkDerivation {
  name = "kannader";
  buildInputs = (
    (with pkgs; [
      rust-analyzer
    ]) ++
    (with rustNightlyChannel; [
      cargo
      rust
    ])
  );
}
