# conprov

## Installation
ConProv is designed based on the eBPF subsystem, which requires specific environment configurations and package dependencies before execution. We have implemented ConProv and validated it on Ubuntu 22.10. Below, we outline the setup steps for ConProv on Ubuntu 22.10 using a series of shell commands.
```shell
# 1. Verify BTF Capability: Check if your kernel supports the BTF capability by verifying the CONFIG_DEBUG_INFO_BTF kernel compilation option.
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)

# 2. Install Required Packages: Install the necessary packages, including bpftool and bpfcc-tools.
sudo apt-get update
sudo apt-get install linux-tools-$(uname -r)

# 3. Install the toolkit for compilation (note: requires clang 10 or higher).
sudo apt install -y bison flex build-essential git cmake make libelf-dev clang llvm strace libfl-dev libssl-dev libedit-dev zlib1g-dev dwarves libncurses5-dev libcap-dev libbfd-dev zstd gcc libbpf-dev libinih-dev pkgconf gcc-multilib libcurl4-openssl-dev gdb

# 4. Select and install Docker version 20.10.
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg lsb-release zfs-fuse 
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
apt-cache madison docker-ce | awk '{ print $3 }'
VERSION_STRING=5:20.10.22~3-0~ubuntu-focal
sudo apt-get install docker-ce=$VERSION_STRING docker-ce-cli=$VERSION_STRING containerd.io docker-compose-plugin

# 5. Configure cgroup v1: Modify the GRUB configuration to use cgroup v1:
sudo vim /etc/default/grub
# Add the following to GRUB\_CMDLINE\_LINUX:
# GRUB_CMDLINE_LINUX="systemd.unified_cgroup_hierarchy=0"
# Update GRUB and reboot the system:
sudo update-grub
sudo reboot

# 6. Clone Repository: Clone the ConProv repository from GitHub.
git clone https://github.com/XiaoXiaoGuaiXiaShi/conprov.git
cd ConProv
cd conprov
make cjson
make all

# 7. Handling Library Errors: If you encounter an error during the ConProv compilation, such as "ldd conprovd: libbpf.so.1 not found", perform the following steps.
sudo vim /etc/ld.so.conf
# Add the following line:
# /usr/lib64
# Then update the dynamic linker run-time bindings:
sudo ldconfig
```

## Usage
The system consists of conprov and provData. conprov is used to generate the log of the specified container, and provData is responsible for preprocessing the log data and generating the provenance graph. Therefore, we need to run a docker container firstly, and then run conprov to monitor this specified container, and copy the generated log path to provData for processing. The libraries needed to run the system have been installed in the virtual machine. To verify the functionality of the system, follow these steps:

1. docker pull training/webapp
2. docker run --name test -d -P training/webapp python app.py
3. copy the Id : docker inspect (test) |grep Id
4. cd conprov && make all
5. sudo ./conprovd (you need input the Id)
6. Accessing the container's web service or interacting with it through a bash session will trigger the recording of relevant activities. For example, you can use `curl 127.0.0.1:32768` (where the port is a randomly assigned local port for the web container). 
7. To stop monitoring the container, press Ctrl+C. The log file will be saved in the `conprov` directory. You can then copy this log file to the `provData` folder and rename it to `conprov.log`.
6. cd ../provData
7. sudo apt-get install graphviz && python3 -m pip install -r requirements.txt
8. python3 spade_graph.py
