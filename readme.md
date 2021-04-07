# Standard Template Construct

## What is it?

Ultimately the premise is: I have nothing, how do I have a virtual environment of *something* that I can use? That is the solution space this is trying to solve. A tool for building environments quickly and repeatably/reliably, or at least finding out if the latter is still possible.

It is also a huge Work In Progress. Expect to be elbowed by it in some way for a while this is at best alpha v0 level software, at best.

### Goals

The goal of the tool is to wrap up using terraform and packer and configuration files to provide a testable and repeatable setup.

For now the only provider that functions, is the libvirt provider. One goal of the tool is to have builtin setup for multiple providers. For now, that is a pipe dream but ultimately one of the tools goals.

The intent is to have one tool to rule them all, thats a joke by the way, that will use terraform providers to do all the necessary setup for us but we're defining and building that terraform setup into the tool itself.

## Intended Audience and/or Reason to Exist

For now, people not worried about getting their hands dirty and understand that the current state is incomplete. This is more a POC/MVP for the moment of a world that might be if more effort is put into it.

However, what *should* work is:
- Building opensuse qcow2 images via packer
- Using those images to build vm's

## Current limitations

Right now, this *only* works with terraform libvirt as a provider. Future updates may add more providers but for now kvm/libvirt is the only color car you can get out of this. As such its also restricted to linux only. Though windows/macos are obvious targets that should work too.

Outside of what is in the TODO section at the end current constraints that resulted in this mish-mash of setup scripts/terraform are:
- The libvirt provider requires unique domain (libvirt domain not DNS domain) names, one cannot reuse names
- For now node sizes/sizing is static and defined in terraform

## Prerequisites

- Linux (for now) libvirt on macos/windows to a remote system may work but is untested
- Terraform libvirt provider (tested with 0.6.3)
- libvirt+kvm installed

As of terraform 0.12 terraform init won't download third party providers.

If you happen to use the nix package manager, you can simply run `nix-shell` to
get an environment with everything needed installed.

### TODO (abbreviated)

- Fix all the yolo/yeet code, for the sake of alacrity, working code was prioritzied over code that didn't leave a mess in the kitchen. I `know` the code is at best middling.
- There is a `lot` of work to be done to validate the users environment, for now I'm just making sure binaries of things terraform/packer need are present at runtime
- The terraform setup needs to be brought into a line to prefer convention over configuration
- The usage of the [chef/bento](https://github.com/chef/bento) repo is currently a private fork, need to come up with a less involved method to not have to reinvent the wheel with packer templates, will probably involve pushing fixes to that repo and maybe just using patch files to add local changes to it remains to be seen.

## License

As noted in the license.spdx file, this repo is released under the Blue Oak 1.0 license.

## Alternatives

This isn't intended to be the ultimate or penultimate or antepenultimate or postantepenultimate solution.

- make+terraform = Sure go ahead, thats how this thing started in the first place actually for 3 months all this was was a makefile, but it ultimately falls down when you need to install N packages like xmlstarlet, jq, yq etc... to start modifying files etc... aka: the user experience `sucks` for anyone but a developer, setting up the environment is also not fun. Additionally when your make targes all start to become .PHONY due to them not being serializable to a file, make just ends up being more work than biting the bullet and using a real language.
- (ctlptl)[https://github.com/tilt-dev/ctlptl] Is another option, however it is more k8s constrained. One goal here is to use vm's as the basic building block. That way applications/workloads outside of and inside of k8s could be replicated/setup in one go.
- TODO: What else sits in this space besides tons of custom terraform etc? Note the design space is intended to be: runs on mac/linux/windows, and sets up virtual environments (maybe real at some point) that then run some app or combination of apps be they one or more k8s clusters or additionally some other tool like say a docker registry, and a caching server etc...
