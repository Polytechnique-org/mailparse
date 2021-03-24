{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  name = "mailparse";

  src = lib.sourceFilesBySuffices ./. [".rs" ".toml" ".lock"];

  cargoSha256 = "1f6zafls5kc8gnyli3ii8jj3pjby9vvkhamb3bjf1h52ibrxjpxn";
}
