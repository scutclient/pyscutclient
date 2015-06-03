# pyscutclient

用Python+scapy把[scutclient](https://github.com/7forz/scutclient)重写了，主要是为了方便调试，只带有基本的认证功能，仅供测试使用。

用法：

`sudo python pyscutclient.py --username [username] --password [password] --iface [iface]`

需要[安装scapy](http://www.secdev.org/projects/scapy/doc/installation.html#platform-specific-instructions)

在Python 2.7 + 64bit Debian/Ubuntu/Deepin 测试成功
