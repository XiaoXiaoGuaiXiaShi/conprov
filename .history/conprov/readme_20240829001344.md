# Readme
kernel-version = 5.19.0-21-generic

## config
- check the CONFIG_DEBUG_INFO_BTF kernel compilation option to confirm whether the system already supports the BTF capability:
    grep CONFIG_DEBUG_INFO_BTF /boot/config-5.11.0-36-generic
    CONFIG_DEBUG_INFO_BTF=y
    CONFIG_DEBUG_INFO_BTF_MODULES=y
- Package dependencies
    sudo apt install linux-tools-5.15.0-75-generic
- Check the bpftool
    bpftool version
- Install the toolkit for compilation (note: requires clang 10 or higher):
    sudo apt install -y bison flex build-essential git cmake make libelf-dev clang llvm strace libfl-dev libssl-dev libedit-dev zlib1g-dev dwarves libncurses5-dev libcap-dev libbfd-dev zstd gcc libbpf-dev libinih-dev pkgconf build-essential gcc-multilib libcurl4-openssl-dev gdb
- install docker
```shell
function install_docker(){
    # Set up the repository
    sudo apt-get update
    sudo apt-get install ca-certificates curl gnupg lsb-release zfs-fuse 
    # Add Docker’s official GPG key
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    # Use the following command to set up the repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    # install docker engine
    sudo apt-get update
    # List the available versions
    apt-cache madison docker-ce | awk '{ print $3 }'
    # Select the desired version and install
    VERSION_STRING=5:20.10.22~3-0~ubuntu-focal
    sudo apt-get install docker-ce=$VERSION_STRING docker-ce-cli=$VERSION_STRING containerd.io docker-compose-plugin
}
```
- use cgroup v1
    sudo vim /etc/default/grub
    add in GRUB_CMDLINE_LINUX：systemd.unified_cgroup_hierarchy=0
    sudo update-grub
    sudo reboot

## StartUP
1、make all
2、ldd conprovd：libbpf.so.1 => not found
vim /etc/ld.so.conf
add /usr/lib64
sudo ldconfig
3、install libdocker：https://github.com/danielsuo/libdocker
git clone https://github.com/danielsuo/libdocker.git
4、make install
5、make start/run
6、rm -rf cJSON
make cjson
7、	dentry_path_raw：
cp /usr/src/linux-headers-$(uname -r)/include/linux/dcache.h /usr/include/linux
cp /usr/src/linux-headers-5.19.0-46-generic/include/linux/atomic.h /usr/include/linux/
cp /usr/src/linux-headers-5.19.0-46-generic/include/asm-generic/atomic.h /usr/include/asm



# activity log
docker pull training/webapp
docker run -d -P training/webapp python app.py