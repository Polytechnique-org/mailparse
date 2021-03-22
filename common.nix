{}:

let
  pkgsSrc = builtins.fetchTarball {
    # The following is for nixos-unstable on 2020-12-13
    url = "https://github.com/NixOS/nixpkgs/archive/e9158eca70ae59e73fae23be5d13d3fa0cfc78b4.tar.gz";
    sha256 = "0cnmvnvin9ixzl98fmlm3g17l6w95gifqfb3rfxs55c0wj2ddy53";
  };
  pkgs = import pkgsSrc {
    overlays = [
      (self: super: {
        xorg-mailparse = self.callPackage ./package.nix {};
      })
    ];
  };
in
  pkgs
