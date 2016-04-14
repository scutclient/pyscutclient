# pyscutclient

用Python+scapy把[scutclient](https://github.com/7forz/scutclient)重写了，主要是为了方便调试，只带有基本的认证功能，仅供测试使用。

首先下载两个.py文件，保存到同一个目录下。
用法：

`sudo python pyscutclient.py --username [username] --password [password] --iface [iface]`

其中iface如eth0、eth1。省略则默认为eth0。



在使用前需要先[安装scapy的依赖包](http://www.secdev.org/projects/scapy/doc/installation.html#platform-specific-instructions)

再安装scapy：

`sudo apt-get install python-pip`

`sudo pip install scapy`

在Python 2.7 + 64bit Debian/Ubuntu 测试成功。如果不是，则可能需要手动打开pyscutclient.py，修改MY_IP等常量，方可成功认证。
