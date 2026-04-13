Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"

  # Host-only IP range (VirtualBox default). Host can access these IPs.
  CONTROL_IP = "192.168.56.10"
  WORKER_IP  = "192.168.56.11"

  config.vm.define "k8s-master" do |m|
    m.vm.hostname = "k8s-master"
    m.vm.network "private_network", ip: CONTROL_IP
    m.vm.provider "virtualbox" do |vb|
      vb.memory = 4096
      vb.cpus = 2
    end
    m.vm.provision "shell", path: "vagrant/provision/common.sh"
    m.vm.provision "shell", path: "vagrant/provision/master.sh", args: [CONTROL_IP]
  end

  config.vm.define "k8s-worker" do |w|
    w.vm.hostname = "k8s-worker"
    w.vm.network "private_network", ip: WORKER_IP
    w.vm.provider "virtualbox" do |vb|
      vb.memory = 4096
      vb.cpus = 2
    end
    w.vm.provision "shell", path: "vagrant/provision/common.sh"
    w.vm.provision "shell", path: "vagrant/provision/worker.sh"
  end
end
