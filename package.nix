{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  name = "mailparse";

  src = lib.sourceFilesBySuffices ./. [".rs" ".toml" ".lock"];

  cargoSha256 = "1hjaq1621q44sp9hcarp1agjm4hnp4xj2dwm1q4q6k7hc62y9zrh";
}
