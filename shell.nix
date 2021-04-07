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
  buildInputs = [ asciinema jq t tflint cargo cargo-watch rustfmt xz pkg-config openssl entr packer ];
}
