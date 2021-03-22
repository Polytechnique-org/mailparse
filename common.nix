rec {
  pkgsSrc = builtins.fetchTarball {
    # The following is for nixos-unstable on 2020-12-13
    url = "https://github.com/NixOS/nixpkgs/archive/e9158eca70ae59e73fae23be5d13d3fa0cfc78b4.tar.gz";
    sha256 = "0cnmvnvin9ixzl98fmlm3g17l6w95gifqfb3rfxs55c0wj2ddy53";
  };
  rustOverlaySrc = builtins.fetchTarball {
    # The following is the latest version as of 2020-12-13
    url = "https://github.com/mozilla/nixpkgs-mozilla/archive/8c007b60731c07dd7a052cce508de3bb1ae849b4.tar.gz";
    sha256 = "1zybp62zz0h077zm2zmqs2wcg3whg6jqaah9hcl1gv4x8af4zhs6";
  };
  rustOverlay = import rustOverlaySrc;
  pkgs = import pkgsSrc {
    overlays = [
      rustOverlay
    ];
  };
  rustNightlyChannel = pkgs.rustChannelOf {
    date = "2021-01-13";
    channel = "nightly";
    sha256 = "05198jf5ljwy3cxcgsrzhm1l4m6qbci4a1n4yh7mr2ay8cka6wb0";
  };
}
