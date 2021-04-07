# All vars here affect things globally and are here mostly for GNUmakefile
# magique.

# The reason for this file actually.
variable qcow_source {
  description = "source qcow2 image used for boot vm's"
  type        = string
  default     = "./kiwi/out/sle15.x86_64-15.2.qcow2"
}

# No pets! I'm assuming /tmp gets nuked on each boot
variable base_dir {
  description = "directory path to use for libvirt pools"
  type        = string
  default     = "/tmp"
}

output "qcow_source" {
  value = var.qcow_source
}
