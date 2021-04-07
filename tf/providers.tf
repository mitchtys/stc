# Convention note: DO NOT put in providers that provide systems that are built
# here. That is, vmware, libvirt, etc... should have their provider config
# inside their setup in the providers directory. Not here. This is everything

# Mark that this configuration has only been tested on 0.12.28+ and not 0.14 (0.14 is baad)
terraform {
  required_version = ">= 0.13"
  required_providers {
    local    = "~> 1.4.0"
    null     = "~> 2.1.2"
    random   = "~> 2.2.1"
    tls      = "~> 3.1.0"
    template = "~> 2.2.0"
    # TODO: fixme, why you can't have multiple required_provider blocks is
    # beyond me, hcl/terraform is a dumb templating language.
    libvirt = {
      source = "dmacvicar/libvirt"
      version = "0.6.3"
    }
  }
}
