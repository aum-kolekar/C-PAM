Vagrant.configure("2") do |config|

  config.vm.box = "ubuntu/jammy64"

  # ---------------- CLIENT 1 ----------------
  config.vm.define "database1" do |db1|
    db1.vm.hostname = "database1"
    db1.vm.network "private_network", ip: "192.168.56.11"
    db1.vm.boot_timeout = 600

    db1.vm.provider "virtualbox" do |vb|
      vb.memory = 1024
      vb.cpus = 2
    end
  end

end