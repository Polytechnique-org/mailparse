{}:

let
  pkgs = import ./common.nix {};
in
pkgs.rustPlatform.buildRustPackage {
  name = "mailparse";

  src = pkgs.lib.sourceFilesBySuffices ./. [".rs" ".toml" ".lock"];

  cargoSha256 = "1v0y258miz3kqfg062j4h4114r92wvps9agcnn7qx6rshqx2ycpp";
}
