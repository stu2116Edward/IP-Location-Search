# IP-Location-Search
离线IP地址查询工具

### 项目结构
<pre>
├── main.go                 # 主程序 - 使用 xdb 二进制数据库
├── beta.go                 # 备选程序 - 使用文本格式数据库
├── go.mod                  # Go模块定义文件
├── ips.txt                 # 输入文件：待查询的IP地址列表
├── result.csv              # 输出文件：查询结果（CSV格式）
├── ip2region_v4.xdb        # IPv4数据库文件（xdb二进制格式）
├── ip2region_v6.xdb        # IPv6数据库文件（xdb二进制格式）
├── ipv4_source.txt         # IPv4文本数据库（txt文本格式）
├── ipv6_source.txt         # IPv6文本数据库（txt文本格式）
</pre>

### 初始化 Go 模块
```
go mod init ipsearch
```

### 运行程序
```
go run main.go
```
