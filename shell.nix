with import <nixpkgs> { };
let
  t = terraform.withPlugins (p: [
    p.libvirt
    p.local
    p.null
    p.random
    p.shell
    p.template
    p.tls
  ]);
in
mkShell {
  buildInputs = [
    cargo
    cargo-watch
    clippy
    entr
    packer
    pkg-config
    rustfmt
    t
    tflint
  ];
}
