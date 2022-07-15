# 专注匿名化的Clash高级版节点优选脚本

- [x] DNS主要用DoH和DoT  
- [x] UDP转发  
- [x] 多跳代理  
- [x] 身份伪装  
- [x] [OpenNIC](https://www.opennic.org/) 服务  
- [x] [Tor](https://gitlab.torproject.org)  
- [x] [I2P](https://github.com/i2p/i2p.i2p)  
- [x] ICMP 存活探测  
- [x] TCP 存活探测  
- [ ] BASE64 解码  
- [ ] 节点链接转Clash配置  
- [ ] TLS 可用验证  
- [x] UDP 存活探测  
- [ ] 站点访问测试
- [ ] 出口ip获取
- [ ] 作者blog里站入口(私货)

例外推荐更改系统时区

## 如何使用
克隆本仓库及安装依赖
```shell
git clone https://github.com/42c73139ae3521cf751b8e654435a94b/Clash-Script
cd Clash-Script
python -m pip install -r requirements.txt  
```
订阅地址一行一条保存到 `urls.txt`

```shell
pyhon clash.py
```
将生成的文件复制到Clash的配置文件夹

略改一下可配合CI服务（如：Github Action）
