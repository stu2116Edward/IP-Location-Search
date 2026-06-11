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
- 精确匹配
```
go run main.go
```
输出详细匹配过程
```
go run main.go --debug
```
- 模糊匹配
```
go run beta.go
```
输出详细匹配过程
```
go run beta.go --debug
```

### 运行结果
<img width="1333" height="522" alt="ILS1" src="https://github.com/user-attachments/assets/af53a173-d4ec-4ece-a521-f992fd724b64" />  

<img width="1378" height="528" alt="ILS2" src="https://github.com/user-attachments/assets/3401cf7b-03a6-4dfe-8747-439f5d0ad39b" />  
