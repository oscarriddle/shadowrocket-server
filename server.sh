#! /bin/bash
# Copyright (c) 2018 flyzy

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

os='ossystem'
password='password'
port='48964'
libsodium_file="libsodium-1.0.16"
libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz"

fly_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

kernel_ubuntu_url="http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.10.2/linux-image-4.10.2-041002-generic_4.10.2-041002.201703120131_amd64.deb"
kernel_ubuntu_file="linux-image-4.10.2-041002-generic_4.10.2-041002.201703120131_amd64.deb"

usage () {
        cat $fly_dir/sshelp
}

DIR=`pwd`

wrong_para_prompt() {
    echo -e "[${red}ERROR${plain}] Argument Wrong!$1"
}

install_ss() {
        if [[ "$#" -lt 1 ]]
        then
          wrong_para_prompt "At least one argument is required for setting password!"
          return 1
        fi
        password=$1
        if [[ "$#" -ge 2 ]]
        then
          port=$2
        fi
        if [[ $port -le 0 || $port -gt 65535 ]]
        then
          wrong_para_prompt "Port format error, range within 1~65535!"
          exit 1
        fi
        check_os
        check_dependency
        download_files
        ps -ef | grep -v grep | grep -i "ssserver" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
                ssserver -c /etc/shadowsocks.json -d stop
        fi
        generate_config $password $port
        if [ ${os} == 'centos' ]
        then
                firewall_set
        fi
        install
        cleanup
}

uninstall_ss() {
        read -p "Do you want to uninstall the shadowsocks？(y/n) :" option
        [ -z ${option} ] && option="n"
        if [ "${option}" == "y" ] || [ "${option}" == "Y" ]
        then
                ps -ef | grep -v grep | grep -i "ssserver" > /dev/null 2>&1
                if [ $? -eq 0 ]; then
                        ssserver -c /etc/shadowsocks.json -d stop
                fi
                case $os in
                        'ubuntu'|'debian')
                                update-rc.d -f server remove
                                ;;
                        'centos')
                                chkconfig --del server
                                ;;
                esac
                rm -f /etc/shadowsocks.json
                rm -f /var/run/shadowsocks.pid
                rm -f /var/log/shadowsocks.log
                if [ -f /usr/local/shadowsocks_install.log ]; then
                        cat /usr/local/shadowsocks_install.log | xargs rm -rf
                fi
                echo "Shadowsocks uninstalled！"
        else
                echo
                echo "Shadowsocks uninstallation cancelled!"
        fi
}

install_bbr() {
	[[ -d "/proc/vz" ]] && echo -e "[${red}ERROR${plain}] Your OS architecture is OpenVZ, won't support BBR." && exit 1
	check_os
	check_bbr_status
	if [ $? -eq 0 ]
	then
		echo -e "[${green}INFO${plain}] TCP BBR acceleration activated!"
		exit 0
	fi
	check_kernel_version
	if [ $? -eq 0 ]
	then
		echo -e "[${green}INFO${plain}] Linux Kernel version higher than 4.9, BBR automatically activated!"
		sysctl_config
		echo -e "[${green}INFO${plain}] TCP BBR acceleration successfully activated!"
		exit 0
	fi
	    
	if [[ x"${os}" == x"centos" ]]; then
        	install_elrepo
        	yum --enablerepo=elrepo-kernel -y install kernel-ml kernel-ml-devel
        	if [ $? -ne 0 ]; then
            		echo -e "[${red}ERROR${plain}] Linux Kernel installation failed, please check it."
            		exit 1
        	fi
    	elif [[ x"${os}" == x"debian" || x"${os}" == x"ubuntu" ]]; then
        	[[ ! -e "/usr/bin/wget" ]] && apt-get -y update && apt-get -y install wget
        	wget ${kernel_ubuntu_url}
		if [ $? -ne 0 ]
		then
			echo -e "[${red}ERROR${plain}] Linux Kernel image failed to download."
			exit 1
		fi
		dpkg -i ${kernel_ubuntu_file}
    	else
       	 	echo -e "[${red}ERROR${plain}] This script doesn't support this OS, please change to CentOS/Debian/Ubuntu."
        	exit 1
    	fi

    	install_config
    	sysctl_config
    	reboot_os
}

install_ssr() {
        check_os
        case $os in
                'ubuntu'|'debian')
		     apt-get -y update
                     apt-get -y install wget
                     ;;
                'centos')
                     yum install -y wget
                     ;;
        esac
	wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR.sh
	chmod +x shadowsocksR.sh
	./shadowsocksR.sh 2>&1 | tee shadowsocksR.log
}

check_os_() {
        source /etc/os-release
	local os_tmp=$(echo $ID | tr [A-Z] [a-z])
        case $os_tmp in
                ubuntu|debian)
                os='ubuntu'
                ;;
                centos)
                os='centos'
                ;;
                *)
                echo -e "[${red}ERROR${plain}] This script doesn't support this OS, please change to CentOS/Debian/Ubuntu."
                exit 1
                ;;
        esac
}

check_os() {
    if [[ -f /etc/redhat-release ]]; then
        os="centos"
    elif cat /etc/issue | grep -Eqi "debian"; then
        os="debian"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        os="ubuntu"
    elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
        os="centos"
    elif cat /proc/version | grep -Eqi "debian"; then
        os="debian"
    elif cat /proc/version | grep -Eqi "ubuntu"; then
        os="ubuntu"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
        os="centos"
    fi
}

check_bbr_status() {
    local param=$(sysctl net.ipv4.tcp_available_congestion_control | awk '{print $3}')
    if [[ x"${param}" == x"bbr" ]]; then
        return 0
    else
        return 1
    fi
}

version_ge(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

check_kernel_version() {
    local kernel_version=$(uname -r | cut -d- -f1)
    if version_ge ${kernel_version} 4.9; then
        return 0
    else
        return 1
    fi
}

sysctl_config() {
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
}

install_elrepo() {
    if centosversion 5; then
        echo -e "[${red}ERROR${plain}] This script doesn't support CentOS5 or lower systems."
        exit 1
    fi

    rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org

    if centosversion 6; then
        rpm -Uvh http://www.elrepo.org/elrepo-release-6-8.el6.elrepo.noarch.rpm
    elif centosversion 7; then
        rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm
    fi

    if [ ! -f /etc/yum.repos.d/elrepo.repo ]; then
        echo -e "[${red}ERROR${plain}] Failed to install elrepo, please check it."
        exit 1
    fi
}

get_latest_version() {

    latest_version=$(wget -qO- http://kernel.ubuntu.com/~kernel-ppa/mainline/ | awk -F'\"v' '/v[4-9]./{print $2}' | cut -d/ -f1 | grep -v -  | sort -V | tail -1)

    [ -z ${latest_version} ] && return 1

    if [[ `getconf WORD_BIT` == "32" && `getconf LONG_BIT` == "64" ]]; then
        deb_name=$(wget -qO- http://kernel.ubuntu.com/~kernel-ppa/mainline/v${latest_version}/ | grep "linux-image" | grep "generic" | awk -F'\">' '/amd64.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_url="http://kernel.ubuntu.com/~kernel-ppa/mainline/v${latest_version}/${deb_name}"
        deb_kernel_name="linux-image-${latest_version}-amd64.deb"
    else
        deb_name=$(wget -qO- http://kernel.ubuntu.com/~kernel-ppa/mainline/v${latest_version}/ | grep "linux-image" | grep "generic" | awk -F'\">' '/i386.deb/{print $2}' | cut -d'<' -f1 | head -1)
        deb_kernel_url="http://kernel.ubuntu.com/~kernel-ppa/mainline/v${latest_version}/${deb_name}"
        deb_kernel_name="linux-image-${latest_version}-i386.deb"
    fi

    [ ! -z ${deb_name} ] && return 0 || return 1
}

get_opsy() {
    [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
    [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

opsy=$( get_opsy )
arch=$( uname -m )
lbit=$( getconf LONG_BIT )
kern=$( uname -r )

check_dependency() {
        case $os in
                'ubuntu'|'debian')
                apt-get -y update
                apt-get -y install python python-dev python-setuptools openssl libssl-dev curl wget unzip gcc automake autoconf make libtool
                ;;
                'centos')
                yum install -y python python-devel python-setuptools openssl openssl-devel curl wget unzip gcc automake autoconf make libtool
        esac
}

install_config() {
    if [[ x"${os}" == x"centos" ]]; then
        if centosversion 6; then
            if [ ! -f "/boot/grub/grub.conf" ]; then
                echo -e "[${red}ERROR${plain}] Can not found /boot/grub/grub.conf."
                exit 1
            fi
            sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
        elif centosversion 7; then
            if [ ! -f "/boot/grub2/grub.cfg" ]; then
                echo -e "[${red}ERROR${plain}] Can not found /boot/grub2/grub.cfg"
                exit 1
            fi
            grub2-set-default 0
        fi
    elif [[ x"${os}" == x"debian" || x"${os}" == x"ubuntu" ]]; then
        /usr/sbin/update-grub
    fi
}

reboot_os() {
    echo
    echo -e "[${green}INFO${plain}] System restart is required to enable BBR."
    read -p "Restart now? [y/n]" is_reboot
    if [[ ${is_reboot} == "y" || ${is_reboot} == "Y" ]]; then
        reboot
    else
        echo -e "[${green}INFO${plain}] Restart canceled. Please restart manually."
        exit 0
    fi
}

download_files() {
        if ! wget --no-check-certificate -O ${libsodium_file}.tar.gz ${libsodium_url}
        then
                echo -e "[${red}ERROR${plain}] Download ${libsodium_file}.tar.gz failed!"
                exit 1
        fi
        if ! wget --no-check-certificate -O shadowsocks-master.zip https://github.com/shadowsocks/shadowsocks/archive/master.zip
        then
                echo -e "[${red}ERROR${plain}] Download shadowsocks package failed!"
                exit 1
        fi
}

generate_config() {
    cat > /etc/shadowsocks.json<<-EOF
{
    "server":"0.0.0.0",
    "server_port":$2,
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"$1",
    "timeout":300,
    "method":"aes-256-cfb",
    "fast_open":false
}
EOF
}

firewall_set(){
    echo -e "[${green}INFO${plain}] Setting the firewall..."
    if centosversion 6; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep -i ${port} > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo -e "[${green}INFO${plain}] Port ${port} is open"
            fi
        else
            echo -e "[${yellow}WARNING${plain}] Firewall (iptables) is stopped or not installed, please manually close firewalls."
        fi
    elif centosversion 7; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            firewall-cmd --permanent --zone=public --add-port=${port}/tcp
            firewall-cmd --permanent --zone=public --add-port=${port}/udp
            firewall-cmd --reload
        else
            echo -e "[${yellow}WARNING${plain}] Firewall (iptables) is stopped or not installed, please manually close firewalls."
        fi
    fi
    echo -e "[${green}INFO${plain}] Firewall setting complete."
}

centosversion(){
    if [ ${os} == 'centos' ]
    then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

getversion(){
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

install() {
        if [ ! -f /usr/lib/libsodium.a ]
        then 
                cd ${DIR}
                tar zxf ${libsodium_file}.tar.gz
                cd ${libsodium_file}
                ./configure --prefix=/usr && make && make install
                if [ $? -ne 0 ] 
                then 
                        echo -e "[${red}ERROR${plain}] Failed to install libsodium!"
                        cleanup
                exit 1  
                fi
        fi      
        ldconfig
        
        cd ${DIR}
        unzip -q shadowsocks-master.zip
        if [ $? -ne 0 ]
        then 
                echo -e "[${red}ERROR${plain}] Extracting failed, please use unzip."
                cleanup
                exit 1
        fi      
        cd ${DIR}/shadowsocks-master
        python setup.py install --record /usr/local/shadowsocks_install.log
        if [ -f /usr/bin/ssserver ] || [ -f /usr/local/bin/ssserver ]
        then 
                cp $fly_dir/server /etc/init.d/
                chmod +x /etc/init.d/server
                case $os in
                        'ubuntu'|'debian')
                                update-rc.d server defaults
                                ;;
                        'centos')
                                chkconfig --add server
                                chkconfig server on
                                ;;
                esac            
                ssserver -c /etc/shadowsocks.json -d start
        else    
                echo -e "[${red}ERROR${plain}] Shadowsocks server creating failed."
                cleanup
                exit 1
        fi      
        echo -e "[${green}Complete${plain}] Shadowsocks server is running!"
        echo -e "Server address  ：\033[41;37m $(get_ip) \033[0m"
        echo -e "Password        ：\033[41;37m ${password} \033[0m"
        echo -e "Port            ：\033[41;37m ${port} \033[0m"
        echo -e "Cryptography    ：\033[41;37m aes-256-cfb \033[0m"
        get_ss_link
}

cleanup() {
        cd ${DIR}
        rm -rf shadowsocks-master.zip shadowsocks-master ${libsodium_file}.tar.gz ${libsodium_file}
}

get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    [ ! -z ${IP} ] && echo ${IP} || echo
}

get_ss_link(){
    if [ ! -f "/etc/shadowsocks.json" ]; then
        echo 'shdowsocks configuration not exist, please check /etc/shadowsocks.json'
        exit 1
    fi
    local tmp=$(echo -n "`get_config_value method`:`get_config_value password`@`get_ip`:`get_config_value server_port`" | base64 -w0)
    echo -e "Config link：\033[41;37m ss://${tmp} \033[0m"
}

get_config_value(){
    cat /etc/shadowsocks.json | grep "\"$1\":"|awk -F ":" '{print $2}'| sed 's/\"//g;s/,//g;s/ //g'
}

if [ "$#" -eq 0 ]; then
	usage
	exit 0
fi

case $1 in
	-h|h|help )
		usage
		exit 0;
		;;
	-v|v|version )
		echo 'Version 1.0'
		exit 0;
		;;
esac

if [ "$EUID" -ne 0 ]; then
	echo -e "[${red}ERROR${plain}] Permission denied."
	exit 1;
fi

case $1 in
	-i|i|install )
        	install_ss $2 $3
		;;
        -bbr )
        	install_bbr
                ;;
        -ssr )
        	install_ssr
                ;;
	-uninstall )
		uninstall_ss
		;;
        -sslink )
                get_ss_link
                ;;
	* )
		usage
		;;
esac
