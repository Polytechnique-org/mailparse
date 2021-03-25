#!/bin/sh

nix-shell -I nixpkgs=./common.nix -p crate2nix --run 'crate2nix generate --all-features'
rm result
nix-build -E '
    ((import ./common.nix {})
        .pkgsStatic.callPackage ./Cargo.nix {
            buildRustCrateForPkgs = pkgs: pkgs.buildRustCrate;
        })
        .rootCrate.build
'
rm Cargo.nix
