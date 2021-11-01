let
  rust-overlay = builtins.fetchTarball {
    url = "https://github.com/oxalica/rust-overlay/archive/master.tar.gz";
  };
  pkgs = import <nixpkgs> { overlays = [ (import (rust-overlay)) ]; };
in with pkgs;
let
  rustChannel = rustChannelOf { channel = "1.56"; };
  rustStable = rustChannel.rust.override { extensions = [ "rust-src" ]; };
  rustPlatform = makeRustPlatform {
    rustc = rustStable;
    cargo = rustStable;
    rustfmt = rustStable;
  };
in mkShell {
  buildInputs = [ clang rustStable openssl pkgconfig cargo-watch ];
  LIBCLANG_PATH = "${llvmPackages.libclang}/lib";
}
