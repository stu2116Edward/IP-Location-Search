package main

import (
	"bufio"
	"encoding/binary"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ==================== xdb 包代码 ====================

const (
	Structure20      = 2
	Structure30      = 3
	HeaderInfoLength = 256
	VectorIndexRows  = 256
	VectorIndexCols  = 256
	VectorIndexSize  = 8
)

type IndexPolicy int

const (
	VectorIndexPolicy IndexPolicy = 1
	BTreeIndexPolicy  IndexPolicy = 2
)

func (i IndexPolicy) String() string {
	switch i {
	case VectorIndexPolicy:
		return "VectorIndex"
	case BTreeIndexPolicy:
		return "BtreeIndex"
	default:
		return "unknown"
	}
}

// Header xdb文件头结构
type Header struct {
	Version         uint16
	IndexPolicy     IndexPolicy
	CreatedAt       uint32
	StartIndexPtr   uint32
	EndIndexPtr     uint32
	IPVersion       int
	RuntimePtrBytes int
}

// NewHeader 解析xdb文件头
func NewHeader(input []byte) (*Header, error) {
	if len(input) < 16 {
		return nil, fmt.Errorf("invalid input buffer")
	}
	return &Header{
		Version:         binary.LittleEndian.Uint16(input[0:]),
		IndexPolicy:     IndexPolicy(binary.LittleEndian.Uint16(input[2:])),
		CreatedAt:       binary.LittleEndian.Uint32(input[4:]),
		StartIndexPtr:   binary.LittleEndian.Uint32(input[8:]),
		EndIndexPtr:     binary.LittleEndian.Uint32(input[12:]),
		IPVersion:       int(binary.LittleEndian.Uint16(input[16:])),
		RuntimePtrBytes: int(binary.LittleEndian.Uint16(input[18:])),
	}, nil
}

// Version IP版本信息
type Version struct {
	Id               int
	Name             string
	Bytes            int
	SegmentIndexSize int
	IPCompare        func([]byte, []byte) int
}

var (
	// IPv4 IPv4版本定义
	IPv4 = &Version{
		Id:               4,
		Name:             "IPv4",
		Bytes:            4,
		SegmentIndexSize: 14,
		IPCompare: func(ip1, ip2 []byte) int {
			// ip1 - Big endian byte order parsed from input
			// ip2 - Little endian byte order read from xdb index
			ip2[0], ip2[3] = ip2[3], ip2[0]
			ip2[1], ip2[2] = ip2[2], ip2[1]
			for i := 0; i < 4; i++ {
				if ip1[i] < ip2[i] {
					return -1
				}
				if ip1[i] > ip2[i] {
					return 1
				}
			}
			return 0
		},
	}
	// IPv6 IPv6版本定义
	IPv6 = &Version{
		Id:               6,
		Name:             "IPv6",
		Bytes:            16,
		SegmentIndexSize: 38,
		IPCompare: func(ip1, ip2 []byte) int {
			for i := 0; i < 16; i++ {
				if ip1[i] < ip2[i] {
					return -1
				}
				if ip1[i] > ip2[i] {
					return 1
				}
			}
			return 0
		},
	}
)

// Searcher xdb查询器
type Searcher struct {
	version     *Version
	dbReader    io.ReadSeekCloser
	ioCount     int
	vectorIndex []byte
	contentBuff []byte
}

// NewSearcher 创建查询器
func NewSearcher(version *Version, dbFile string, cBuff []byte) (*Searcher, error) {
	// 全内存缓存模式
	if cBuff != nil {
		return &Searcher{
			version:     version,
			vectorIndex: nil,
			contentBuff: cBuff,
		}, nil
	}
	// 文件模式
	handle, err := os.OpenFile(dbFile, os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &Searcher{
		version:  version,
		dbReader: handle,
	}, nil
}

// Close 关闭查询器
func (s *Searcher) Close() {
	if s.dbReader != nil {
		s.dbReader.Close()
	}
}

// Search 查询IP归属地
func (s *Searcher) Search(ip string) (string, error) {
	// 解析IP地址
	ipBytes, err := parseIP(ip)
	if err != nil {
		return "", err
	}
	// 验证IP版本
	if len(ipBytes) != s.version.Bytes {
		return "", fmt.Errorf("invalid ip address(%s expected)", s.version.Name)
	}
	s.ioCount = 0

	// 获取向量索引位置
	il0, il1 := int(ipBytes[0]), int(ipBytes[1])
	idx := il0*VectorIndexCols*VectorIndexSize + il1*VectorIndexSize
	var sPtr, ePtr uint32

	if s.contentBuff != nil {
		// 从内存缓存读取向量索引
		sPtr = binary.LittleEndian.Uint32(s.contentBuff[HeaderInfoLength+idx:])
		ePtr = binary.LittleEndian.Uint32(s.contentBuff[HeaderInfoLength+idx+4:])
	} else {
		// 从文件读取向量索引
		var buff = make([]byte, VectorIndexSize)
		if err := s.read(int64(HeaderInfoLength+idx), buff); err != nil {
			return "", err
		}
		sPtr = binary.LittleEndian.Uint32(buff)
		ePtr = binary.LittleEndian.Uint32(buff[4:])
	}

	// 空指针检查
	if sPtr == 0 || ePtr == 0 {
		return "", nil
	}

	// 二分查找索引区
	bytes, dBytes := len(ipBytes), len(ipBytes)<<1
	segIndexSize := uint32(s.version.SegmentIndexSize)
	buff := make([]byte, segIndexSize)
	l, h := 0, int((ePtr-sPtr)/segIndexSize)

	for l <= h {
		m := (l + h) >> 1
		p := sPtr + uint32(m)*segIndexSize
		if err := s.read(int64(p), buff); err != nil {
			return "", err
		}
		// 比较IP地址
		if s.version.IPCompare(ipBytes, buff[0:bytes]) < 0 {
			h = m - 1
		} else if s.version.IPCompare(ipBytes, buff[bytes:dBytes]) > 0 {
			l = m + 1
		} else {
			// 找到匹配，读取区域数据
			dataLen := int(binary.LittleEndian.Uint16(buff[dBytes:]))
			dataPtr := binary.LittleEndian.Uint32(buff[dBytes+2:])
			if dataLen == 0 {
				return "", nil
			}
			regionBuff := make([]byte, dataLen)
			if err := s.read(int64(dataPtr), regionBuff); err != nil {
				return "", err
			}
			return string(regionBuff), nil
		}
	}
	return "", nil
}

// read 读取数据
func (s *Searcher) read(offset int64, buff []byte) error {
	if s.contentBuff != nil {
		// 从内存缓存读取
		copy(buff, s.contentBuff[offset:])
	} else {
		// 从文件读取
		if _, err := s.dbReader.Seek(offset, 0); err != nil {
			return err
		}
		s.ioCount++
		if _, err := s.dbReader.Read(buff); err != nil {
			return err
		}
	}
	return nil
}

// parseIP 解析IP地址为字节数组
func parseIP(ip string) ([]byte, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid ip address: %s", ip)
	}
	if v4 := parsedIP.To4(); v4 != nil {
		return v4, nil
	}
	if v6 := parsedIP.To16(); v6 != nil {
		return v6, nil
	}
	return nil, fmt.Errorf("invalid ip address: %s", ip)
}

// LoadContentFromFile 从文件加载完整xdb内容
func LoadContentFromFile(dbFile string) ([]byte, error) {
	handle, err := os.OpenFile(dbFile, os.O_RDONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open xdb file `%s`: %w", dbFile, err)
	}
	defer handle.Close()
	return io.ReadAll(handle)
}

// VerifyFromFile 验证xdb文件
func VerifyFromFile(dbFile string) error {
	handle, err := os.OpenFile(dbFile, os.O_RDONLY, 0600)
	if err != nil {
		return fmt.Errorf("open xdb file `%s`: %w", dbFile, err)
	}
	defer handle.Close()
	header, err := loadHeader(handle)
	if err != nil {
		return fmt.Errorf("loading header: %w", err)
	}
	// 获取运行时指针字节数
	runtimePtrBytes := 4
	if header.Version == Structure30 {
		runtimePtrBytes = header.RuntimePtrBytes
	}
	// 确认文件大小不超过最大支持字节数
	stat, err := handle.Stat()
	if err != nil {
		return fmt.Errorf("file stat: %w", err)
	}
	maxFilePtr := int64(1<<(runtimePtrBytes*8) - 1)
	if stat.Size() > maxFilePtr {
		return fmt.Errorf("xdb file exceeds the maximum supported bytes: %d", maxFilePtr)
	}
	return nil
}

// loadHeader 加载xdb文件头
func loadHeader(handle io.ReadSeeker) (*Header, error) {
	if _, err := handle.Seek(0, 0); err != nil {
		return nil, err
	}
	buff := make([]byte, HeaderInfoLength)
	if _, err := handle.Read(buff); err != nil {
		return nil, err
	}
	return NewHeader(buff)
}

// ==================== service 包代码 ====================

// 缓存策略常量
const (
	NoCache     = 0 // 文件模式
	VIndexCache = 1 // 向量索引缓存模式
	BufferCache = 2 // 全内存缓存模式
)

// Config 配置结构
type Config struct {
	cachePolicy int
	ipVersion   *Version
	xdbPath     string
	header      *Header
	cBuffer     []byte
	searchers   int
}

// NewV4Config 创建IPv4配置
func NewV4Config(cachePolicy int, xdbPath string) (*Config, error) {
	return newConfig(cachePolicy, IPv4, xdbPath)
}

// NewV6Config 创建IPv6配置
func NewV6Config(cachePolicy int, xdbPath string) (*Config, error) {
	return newConfig(cachePolicy, IPv6, xdbPath)
}

// newConfig 创建配置
func newConfig(cachePolicy int, ipVersion *Version, xdbPath string) (*Config, error) {
	handle, err := os.OpenFile(xdbPath, os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	// 验证xdb文件
	if err := VerifyFromFile(xdbPath); err != nil {
		return nil, err
	}
	// 加载文件头
	header, err := loadHeader(handle)
	if err != nil {
		return nil, err
	}

	// 根据缓存策略加载数据
	var cBuffer []byte = nil
	if cachePolicy == BufferCache {
		cBuffer, err = LoadContentFromFile(xdbPath)
		if err != nil {
			return nil, err
		}
	}
	return &Config{
		cachePolicy: cachePolicy,
		ipVersion:   ipVersion,
		xdbPath:     xdbPath,
		header:      header,
		cBuffer:     cBuffer,
		searchers:   1,
	}, nil
}

// Ip2Region IP查询服务
type Ip2Region struct {
	v4Searcher      *Searcher
	v6Searcher      *Searcher
	v4InMemSearcher *Searcher
	v6InMemSearcher *Searcher
}

// NewIp2Region 创建Ip2Region服务
func NewIp2Region(v4Config *Config, v6Config *Config) (*Ip2Region, error) {
	var v4Searcher, v4InMemSearcher *Searcher
	var v6Searcher, v6InMemSearcher *Searcher

	// 创建IPv4查询器
	if v4Config != nil {
		if v4Config.cachePolicy == BufferCache {
			// 全内存缓存模式
			searcher, err := NewSearcher(v4Config.ipVersion, "", v4Config.cBuffer)
			if err != nil {
				return nil, fmt.Errorf("failed to create v4 searcher: %w", err)
			}
			v4InMemSearcher = searcher
		} else {
			// 文件模式
			searcher, err := NewSearcher(v4Config.ipVersion, v4Config.xdbPath, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create v4 searcher: %w", err)
			}
			v4Searcher = searcher
		}
	}

	// 创建IPv6查询器
	if v6Config != nil {
		if v6Config.cachePolicy == BufferCache {
			// 全内存缓存模式
			searcher, err := NewSearcher(v6Config.ipVersion, "", v6Config.cBuffer)
			if err != nil {
				return nil, fmt.Errorf("failed to create v6 searcher: %w", err)
			}
			v6InMemSearcher = searcher
		} else {
			// 文件模式
			searcher, err := NewSearcher(v6Config.ipVersion, v6Config.xdbPath, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create v6 searcher: %w", err)
			}
			v6Searcher = searcher
		}
	}

	return &Ip2Region{
		v4Searcher:      v4Searcher,
		v4InMemSearcher: v4InMemSearcher,
		v6Searcher:      v6Searcher,
		v6InMemSearcher: v6InMemSearcher,
	}, nil
}

// Search 查询IP归属地
func (ip2r *Ip2Region) Search(ip string) (string, error) {
	// 判断IP版本
	isIPv4 := strings.Contains(ip, ".")
	if isIPv4 {
		// IPv4查询
		if ip2r.v4InMemSearcher != nil {
			return ip2r.v4InMemSearcher.Search(ip)
		}
		if ip2r.v4Searcher != nil {
			return ip2r.v4Searcher.Search(ip)
		}
		return "", nil
	} else {
		// IPv6查询
		if ip2r.v6InMemSearcher != nil {
			return ip2r.v6InMemSearcher.Search(ip)
		}
		if ip2r.v6Searcher != nil {
			return ip2r.v6Searcher.Search(ip)
		}
		return "", nil
	}
}

// Close 关闭服务
func (ip2r *Ip2Region) Close() {
	if ip2r.v4Searcher != nil {
		ip2r.v4Searcher.Close()
	}
	if ip2r.v6Searcher != nil {
		ip2r.v6Searcher.Close()
	}
}

// ==================== 主程序代码 ====================

// 全局调试标志
var debug bool

func main() {
	// 解析命令行参数
	debugFlag := flag.Bool("debug", false, "输出调试信息")
	v4DB := flag.String("v4db", "ip2region_v4.xdb", "IPv4数据库文件路径")
	v6DB := flag.String("v6db", "ip2region_v6.xdb", "IPv6数据库文件路径")
	inputFile := flag.String("input", "ips.txt", "IP地址输入文件路径")
	outputFile := flag.String("output", "result.csv", "输出CSV文件路径")
	cachePolicy := flag.String("cache", "content", "缓存策略: file/vectorIndex/content")
	flag.Parse()
	debug = *debugFlag

	fmt.Println("🔧 IP地址归属地查询工具")
	fmt.Println("=======================")

	// 创建Ip2Region服务
	ip2region, err := createIp2RegionService(*v4DB, *v6DB, *cachePolicy)
	if err != nil {
		fmt.Printf("❌ 创建查询服务失败: %v\n", err)
		fmt.Println("\n请确保数据库文件存在：")
		fmt.Println("  - ip2region_v4.xdb")
		fmt.Println("  - ip2region_v6.xdb")
		return
	}
	defer ip2region.Close()

	fmt.Println("✅ 查询服务初始化成功\n")

	// 执行查询
	if err := processIPs(*inputFile, *outputFile, ip2region); err != nil {
		fmt.Printf("❌ 处理失败: %v\n", err)
	}
}

// createIp2RegionService 创建Ip2Region服务
func createIp2RegionService(v4Path, v6Path, cachePolicy string) (*Ip2Region, error) {
	// 转换缓存策略
	var policy int
	switch strings.ToLower(cachePolicy) {
	case "content", "buffercache":
		policy = BufferCache
	case "vectorindex", "vindex":
		policy = VIndexCache
	default:
		policy = BufferCache
	}

	// 创建IPv4配置
	var v4Config *Config
	if _, err := os.Stat(v4Path); err == nil {
		// 验证xdb文件
		if err := VerifyFromFile(v4Path); err != nil {
			return nil, fmt.Errorf("IPv4数据库验证失败: %w", err)
		}
		v4Config, err = NewV4Config(policy, v4Path)
		if err != nil {
			return nil, fmt.Errorf("创建IPv4配置失败: %w", err)
		}
		fmt.Printf("📘 IPv4数据库: %s (策略: %s)\n", v4Path, cachePolicy)
	} else {
		fmt.Printf("⚠️  IPv4数据库不存在: %s\n", v4Path)
	}

	// 创建IPv6配置
	var v6Config *Config
	if _, err := os.Stat(v6Path); err == nil {
		// 验证xdb文件
		if err := VerifyFromFile(v6Path); err != nil {
			return nil, fmt.Errorf("IPv6数据库验证失败: %w", err)
		}
		v6Config, err = NewV6Config(policy, v6Path)
		if err != nil {
			return nil, fmt.Errorf("创建IPv6配置失败: %w", err)
		}
		fmt.Printf("📗 IPv6数据库: %s (策略: %s)\n", v6Path, cachePolicy)
	} else {
		fmt.Printf("⚠️  IPv6数据库不存在: %s\n", v6Path)
	}

	// 创建服务
	return NewIp2Region(v4Config, v6Config)
}

// processIPs 处理IP列表
func processIPs(inputFile, outputFile string, ip2region *Ip2Region) error {
	// 读取IP列表
	fmt.Println("📖 读取IP地址文件...")

	ips, err := readIPsFromFile(inputFile)
	if err != nil {
		return fmt.Errorf("读取IP文件失败: %w", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("没有找到任何IP地址")
	}

	// 统计IPv4和IPv6数量
	ipv4Count, ipv6Count := 0, 0
	for _, ip := range ips {
		if strings.Contains(ip, ".") {
			ipv4Count++
		} else {
			ipv6Count++
		}
	}
	fmt.Printf("✅ 找到 %d 个IP地址 (IPv4: %d, IPv6: %d)\n\n", len(ips), ipv4Count, ipv6Count)

	// 创建输出文件
	output, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer output.Close()

	// 创建CSV写入器
	csvWriter := csv.NewWriter(output)
	defer csvWriter.Flush()

	// 写入CSV头部
	headers := []string{"IP地址", "归属地"}
	if debug {
		headers = []string{"IP地址", "归属地", "状态", "错误信息"}
	}
	csvWriter.Write(headers)

	fmt.Println("🔍 开始查询...\n")

	var successCount, failCount int
	startTime := time.Now()

	// 按顺序查询每个IP
	for i, ip := range ips {
		// 显示IP类型图标
		icon := "🌐"
		if strings.Contains(ip, ".") {
			icon = "📘"
		} else {
			icon = "📗"
		}
		fmt.Printf("%s [%d/%d] %s ", icon, i+1, len(ips), ip)

		// 执行查询
		region, err := ip2region.Search(ip)

		var row []string
		if err != nil {
			failCount++
			fmt.Printf("❌ 错误: %v\n", err)
			if debug {
				row = []string{ip, "", "失败", err.Error()}
			} else {
				row = []string{ip, ""}
			}
		} else if region == "" {
			failCount++
			fmt.Printf("❌ 未找到归属地\n")
			if debug {
				row = []string{ip, "", "失败", "未找到归属地"}
			} else {
				row = []string{ip, ""}
			}
		} else {
			successCount++
			// 格式化显示结果
			parts := strings.Split(region, "|")
			if len(parts) >= 5 {
				country, province, city, isp := parts[0], parts[2], parts[3], parts[4]
				if country == "0" {
					country = ""
				}
				if province == "0" {
					province = ""
				}
				if city == "0" {
					city = ""
				}
				if isp == "0" {
					isp = ""
				}
				fmt.Printf("✅ %s%s%s %s\n", country, province, city, isp)
			} else {
				fmt.Printf("✅ %s\n", region)
			}
			if debug {
				row = []string{ip, region, "成功", ""}
			} else {
				row = []string{ip, region}
			}
		}
		csvWriter.Write(row)

		// 每100条刷新一次
		if (i+1)%100 == 0 {
			csvWriter.Flush()
			elapsed := time.Since(startTime)
			fmt.Printf("\n📊 进度: %d/%d (%.1f%%), 耗时: %v\n",
				i+1, len(ips), float64(i+1)/float64(len(ips))*100, elapsed)
		}
	}

	// 打印统计信息
	elapsed := time.Since(startTime)
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("📊 查询统计:")
	fmt.Printf("  总查询数: %d\n", len(ips))
	fmt.Printf("  ✅ 成功: %d\n", successCount)
	fmt.Printf("  ❌ 失败: %d\n", failCount)
	if len(ips) > 0 {
		fmt.Printf("  📈 成功率: %.2f%%\n", float64(successCount)/float64(len(ips))*100)
	}
	fmt.Printf("  ⏱️  总耗时: %v\n", elapsed)
	fmt.Printf("  ⚡ 平均速度: %.2f 个/秒\n", float64(len(ips))/elapsed.Seconds())
	fmt.Printf("  📄 结果保存到: %s\n", outputFile)
	fmt.Println(strings.Repeat("=", 50))

	return nil
}

// readIPsFromFile 从文件中读取所有IP地址（IPv4和IPv6混合）
func readIPsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// IPv4和IPv6正则表达式
	ipv4Regex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Regex := regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b`)

	scanner := bufio.NewScanner(file)
	// 设置更大的缓冲区
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var allIPs []string
	ipSet := make(map[string]bool) // 用于去重，保持第一次出现的顺序

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 按行处理，保持行的顺序
		// 先尝试提取IPv4地址
		ipv4Matches := ipv4Regex.FindAllString(line, -1)
		for _, ip := range ipv4Matches {
			if isValidIPv4(ip) && !ipSet[ip] {
				ipSet[ip] = true
				allIPs = append(allIPs, ip)
			}
		}

		// 提取IPv6地址
		ipv6Matches := ipv6Regex.FindAllString(line, -1)
		for _, ip := range ipv6Matches {
			if !ipSet[ip] {
				ipSet[ip] = true
				allIPs = append(allIPs, ip)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return allIPs, nil
}

// isValidIPv4 验证IPv4地址
func isValidIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}
	return true
}
