# https://github.com/dmacvicar/terraform-provider-libvirt#installing
# TODO: the uri *could* be an ssh:... uri to an external libvirt system, make
# this a provider var somehow
provider "libvirt" {
  uri = "qemu:///system"
}

variable node_count {
  description = "count of vm's to build"
  type        = number
  default     = 1
}

output "variables" {
  value = {
    "node_count"  = var.node_count
    "base_dir"    = var.base_dir
  }
}

resource "random_id" "instance" {
  byte_length = 8
}

# total address spaces for a /16 for the /8 we're in.
resource "random_integer" "octets" {
  min  = 1
  max  = 65535
  seed = local.seed
}

output "random_integer" {
  value = {
    "octets" = random_integer.octets.result
  }
}

resource "libvirt_volume" "vm" {
  name   = local.instance
  source = var.qcow_source
  pool   = libvirt_pool.vm.name
  format = "qcow2"
}

resource "libvirt_network" "vm" {
  name      = local.instance
  mode      = "nat"
  domain    = "lan"
  addresses = [local.subnet]

  dns {
    enabled    = true
    local_only = true
  }
}

resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

locals {
  count       = var.node_count
  seed        = "${abspath(path.root)} ${terraform.workspace}"
  subnet      = cidrsubnet("10.0.0.0/8", 16, random_integer.octets.result)
  instance    = random_id.instance.hex
  ssh_key     = "${abspath(path.root)}/ssh-key-${terraform.workspace}"
  ssh_key_pub = "${local.ssh_key}.pub"
  ssh_config  = "${abspath(path.root)}/ssh-config-${terraform.workspace}"
  known_hosts = "${abspath(path.root)}/known-hosts-${terraform.workspace}"
}

resource "local_file" "ssh_private_key" {
  filename        = local.ssh_key
  file_permission = "0600"
  content         = tls_private_key.ssh_key.private_key_pem
}

resource "local_file" "ssh_public_key" {
  filename        = local.ssh_key_pub
  file_permission = "0600"
  content         = tls_private_key.ssh_key.public_key_openssh
}

# To debug other stuff
output "debug" {
  value = {
    seed     = local.seed
    instance = local.instance
    subnet   = local.subnet
    ssh_key  = local.ssh_key
  }
}

resource "libvirt_pool" "vm" {
  name = local.instance
  type = "dir"
  path = abspath("${var.base_dir}/libvirt-${terraform.workspace}-${random_id.instance.hex}")
}

resource "libvirt_volume" "node" {
  name           = "${random_pet.node_petname[count.index].id}.qcow2"
  base_volume_id = libvirt_volume.vm.id
  count          = local.count
  pool           = libvirt_pool.vm.name
}

resource "random_pet" "node_petname" {
  count     = local.count
  separator = "-"
  length    = 3
  prefix    = ""
}

resource "tls_private_key" "host_key_rsa" {
  count     = local.count
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "libvirt_cloudinit_disk" "cloud_init" {
  depends_on = [
    tls_private_key.ssh_key,
    tls_private_key.host_key_rsa
  ]
  name       = "${random_pet.node_petname[count.index].id}-cloud-init.iso"
  pool       = libvirt_pool.vm.name
  count      = local.count
  user_data  = templatefile("${path.root}/cloud-config-v1.template", {
    hostname = random_pet.node_petname[count.index].id,
    authorized_ssh_key = tls_private_key.ssh_key.private_key_pem,
    authorized_ssh_key_pub = tls_private_key.ssh_key.public_key_openssh,
    host_key_rsa = tls_private_key.host_key_rsa[count.index].private_key_pem,
    host_key_rsa_pub = tls_private_key.host_key_rsa[count.index].public_key_openssh
  })
}

resource "libvirt_domain" "node" {
  name   = random_pet.node_petname[count.index].id
  count  = local.count
  memory = "8192"
  vcpu   = 12

  cloudinit = libvirt_cloudinit_disk.cloud_init[count.index].id

  network_interface {
    hostname       = random_pet.node_petname[count.index].id
    network_id     = libvirt_network.vm.id
    bridge         = false
    wait_for_lease = true
  }

  console {
    type        = "pty"
    target_type = "serial"
    target_port = "0"
  }

  console {
    type        = "pty"
    target_type = "virtio"
    target_port = "1"
  }

  disk {
    volume_id = element(libvirt_volume.node.*.id, count.index)
  }

  graphics {
    type        = "vnc"
    listen_type = "address"
  }

  connection {
    host        = self.network_interface[0].addresses[0]
    private_key = tls_private_key.ssh_key.private_key_pem
    type        = "ssh"
    user        = "root"
  }

  # note, cloud-init will setup /etc/hosts with a 127.0.0.1 entry for the host, we need to remove it
  provisioner "remote-exec" {
    inline = [<<-FIN
    set -e
    sed -i '/127[.]0[.]0[.]1.*${self.name}/d' /etc/hosts
    rm -fr /etc/ssh/ssh_host_dsa_key
    rm -fr /etc/ssh/ssh_host_dsa_key.pub
    rm -fr /etc/ssh/ssh_host_ed25519_key
    rm -fr /etc/ssh/ssh_host_ed25519_key.pub
    rm -fr /etc/ssh/ssh_host_ecdsa_key
    rm -fr /etc/ssh/ssh_host_ecdsa_key.pub
    install -m600 --owner root --group root /etc/ssh_host_rsa_key /etc/ssh/ssh_host_rsa_key
    install -m644 --owner root --group root /etc/ssh_host_rsa_key.pub /etc/ssh/ssh_host_rsa_key.pub
    install -dm700 --owner root --group root /root/.ssh
    install -m600 --owner root --group root /etc/id_rsa /root/.ssh/id_rsa
    install -m644 --owner root --group root /etc/id_rsa.pub /root/.ssh/id_rsa.pub
    install -dm700 --owner opensuse --group users /home/opensuse/.ssh
    install -m600 --owner opensuse --group users /etc/id_rsa /home/opensuse/.ssh/id_rsa
    install -m644 --owner opensuse --group users /etc/id_rsa.pub /home/opensuse/.ssh/id_rsa.pub
    systemctl restart sshd.service
    sleep ${count.index}
    until systemctl is-active --quiet sshd.service; do
      sleep 1
    done
    FIN
    ]
  }
}

locals {
  hosts = {
    for x in libvirt_domain.node:
      x.name => x.network_interface[0].addresses[0]
  }
  hostnames = libvirt_domain.node.*.name
  # Hard coded to 1 master for now
  master_hosts = length(local.hosts) > 0 ? zipmap(slice(keys(local.hosts), 0, 1), slice(values(local.hosts), 0, 1)) : {}
  worker_hosts = length(local.hosts) > 0 ? zipmap(slice(keys(local.hosts), 1, length(local.hosts)), slice(values(local.hosts), 1, length(local.hosts))) : {}
  host_keys = {
    for i in range(0, local.count):
      random_pet.node_petname[i].id => tls_private_key.host_key_rsa[i].public_key_openssh
  }
  host_id = {
    for i in range(0, local.count):
      libvirt_domain.node[i].name => i
  }
}

output "hosts" {
  value = local.hosts
}

output "host_keys" {
  value = local.host_keys
}

output "host_id" {
  value = local.host_id
}

output "hostnames" {
  value = local.hostnames
}

output "first" {
  value = libvirt_domain.node[0].network_interface[0].hostname
}

resource "local_file" "ssh_config" {
  depends_on      = [ libvirt_domain.node, tls_private_key.ssh_key ]
  file_permission = "0600"
  filename        = local.ssh_config
  content         = templatefile("${path.root}/ssh-config.template", {
    user = "root",
    ssh_key = local.ssh_key,
    hosts = local.hosts
  })
}

resource "local_file" "known_hosts" {
  depends_on      = [
    libvirt_domain.node,
    tls_private_key.host_key_rsa,
  ]
  file_permission = "0644"
  filename        = local.known_hosts
  content = templatefile("${path.root}/known-hosts.template", {
    host_keys = local.host_keys,
    hosts = local.hosts
  })
}

# Setup passwordless ssh between all the nodes for root and copy over the ssh
# keys we generated note we also allow for local connections aka root@hostname
# when on hostname vm just in case something *cough* ansible needs to connect
# locally via ssh or something silly that doesn't notice there is no need to ssh
resource "null_resource" "ssh_setup_root" {
  count      = local.count
  depends_on = [
    libvirt_domain.node,
    tls_private_key.ssh_key,
    tls_private_key.host_key_rsa,
    local_file.ssh_private_key,
    local_file.ssh_public_key,
    local_file.known_hosts
  ]

  connection {
    host        = libvirt_domain.node[count.index].network_interface[0].addresses[0]
    private_key = tls_private_key.ssh_key.private_key_pem
    type        = "ssh"
    user        = "root"
  }

  provisioner "file" {
    source      = local.known_hosts
    destination = "/etc/known_hosts"
  }

  # Just to know everything we setup is OK, also broken into its own exec so the output is last
  provisioner "remote-exec" {
    inline = [<<-FIN
      set -ex
      install -m644 --owner root --group root /etc/known_hosts /root/.ssh/known_hosts
      echo i am $(uname -n) as $(whoami)
      for host in ${join(" ", keys(local.hosts))}; do
        ssh -o StrictHostKeyChecking=yes $host 'exit 0'
      done
      echo $(uname -n) passwordless ssh via hostname is ok
      for ip in ${join(" ", values(local.hosts))}; do
        ssh -o StrictHostKeyChecking=yes $ip 'exit 0'
      done
      echo $(uname -n) passwordless ssh via ip is ok
    FIN
    ]
  }
}

# And do it for vm too
# TODO: maybe build a module to encompass this ssh setup for multiple users
resource "null_resource" "ssh_setup_user" {
  count      = local.count
  depends_on = [
    libvirt_domain.node,
    tls_private_key.ssh_key,
    tls_private_key.host_key_rsa,
    local_file.ssh_private_key,
    local_file.ssh_public_key,
    local_file.known_hosts
  ]

  connection {
    host        = libvirt_domain.node[count.index].network_interface[0].addresses[0]
    private_key = tls_private_key.ssh_key.private_key_pem
    type        = "ssh"
    user        = "opensuse"
  }

  provisioner "file" {
    source      = local.known_hosts
    destination = "/tmp/known_hosts"
  }

  # Just to know everything we setup is OK, also broken into its own exec so the output is last
  provisioner "remote-exec" {
    inline = [<<-FIN
      set -e
      install -m644 --owner opensuse --group users /tmp/known_hosts /home/opensuse/.ssh/known_hosts
      echo i am $(uname -n) as $(whoami)
      for host in ${join(" ", keys(local.hosts))}; do
        ssh -o StrictHostKeyChecking=yes $host 'exit 0'
      done
      echo $(uname -n) passwordless ssh via hostname is ok
      for ip in ${join(" ", values(local.hosts))}; do
        ssh -o StrictHostKeyChecking=yes $ip 'exit 0'
      done
      echo $(uname -n) passwordless ssh via ip is ok
      rm -fr /tmp/known_hosts
    FIN
    ]
  }
}
