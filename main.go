package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// ==================== 常量定义 ====================
const (
	Structure20      = 2
	Structure30      = 3
	HeaderInfoLength = 256
	VectorIndexRows  = 256
	VectorIndexCols  = 256
	VectorIndexSize  = 8

	// 缓存策略常量
	NoCache     = 0 // 文件模式
	VIndexCache = 1 // 向量索引缓存模式
	BufferCache = 2 // 全内存缓存模式

	// 默认配置
	DefaultV4DB       = "ip2region_v4.xdb"
	DefaultV6DB       = "ip2region_v6.xdb"
	DefaultInputFile  = "ips.txt"
	DefaultOutputFile = "result.csv"
	DefaultCacheMode  = "content"

	// CSV 缓冲区大小
	CSVBufferSize = 1 << 20 // 1MB

	// 定期刷新
	FlushInterval = 100

	// 进度显示间隔
	ProgressInterval = 500 * time.Millisecond
)

// ==================== 全局变量 ====================
var debug bool

// ==================== xdb 包代码 ====================

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
	if len(input) < 20 {
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
			// ip1 - 从输入解析的大端字节序
			// ip2 - 从 xdb 索引读取的小端字节序
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
	bytesLen, dBytes := len(ipBytes), len(ipBytes)<<1
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
		if s.version.IPCompare(ipBytes, buff[0:bytesLen]) < 0 {
			h = m - 1
		} else if s.version.IPCompare(ipBytes, buff[bytesLen:dBytes]) > 0 {
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
	parsedIP := net.ParseIP(strings.TrimSpace(ip))
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

// Config 配置结构
type Config struct {
	cachePolicy int
	ipVersion   *Version
	xdbPath     string
	header      *Header
	cBuffer     []byte
	searchers   int
	RecordCount int
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
	recordCount := int((header.EndIndexPtr-header.StartIndexPtr)/uint32(ipVersion.SegmentIndexSize)) + 1
	return &Config{
		cachePolicy: cachePolicy,
		ipVersion:   ipVersion,
		xdbPath:     xdbPath,
		header:      header,
		cBuffer:     cBuffer,
		searchers:   1,
		RecordCount: recordCount,
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
	}
	// IPv6查询
	if ip2r.v6InMemSearcher != nil {
		return ip2r.v6InMemSearcher.Search(ip)
	}
	if ip2r.v6Searcher != nil {
		return ip2r.v6Searcher.Search(ip)
	}
	return "", nil
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
		var configErr error
		v4Config, configErr = NewV4Config(policy, v4Path)
		if configErr != nil {
			return nil, fmt.Errorf("创建IPv4配置失败: %w", configErr)
		}
		fmt.Printf("📘 加载IPv4数据库: %s\n", v4Path)
		fmt.Printf("   ✅ IPv4数据库加载成功，共 %d 条记录\n", v4Config.RecordCount)
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
		var configErr error
		v6Config, configErr = NewV6Config(policy, v6Path)
		if configErr != nil {
			return nil, fmt.Errorf("创建IPv6配置失败: %w", configErr)
		}
		fmt.Printf("📗 加载IPv6数据库: %s\n", v6Path)
		fmt.Printf("   ✅ IPv6数据库加载成功，共 %d 条记录\n", v6Config.RecordCount)
	} else {
		fmt.Printf("⚠️  IPv6数据库不存在: %s\n", v6Path)
	}

	// 创建服务
	return NewIp2Region(v4Config, v6Config)
}

// ==================== 工具函数 ====================

// isDigitByte 判断字节是否为数字字符
func isDigitByte(b byte) bool {
	return b >= '0' && b <= '9'
}

// isHexByte 判断字节是否为十六进制字符
func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'f') ||
		(b >= 'A' && b <= 'F')
}

// validIPv4Bytes 校验一个字节切片是否为合法的 IPv4（不进行 net.ParseIP 分配）
// 要求格式为 N.N.N.N，每段 0-255，且无多余字符
func validIPv4Bytes(b []byte) bool {
	if len(b) < 7 || len(b) > 15 {
		return false
	}
	parts := 0
	n := len(b)
	i := 0
	for i < n {
		// parse number
		if !isDigitByte(b[i]) {
			return false
		}
		val := 0
		start := i
		for i < n && isDigitByte(b[i]) {
			val = val*10 + int(b[i]-'0')
			// early reject large numbers
			if val > 255 {
				return false
			}
			i++
		}
		if i == start {
			return false
		}
		parts++
		// if end, ok
		if i == n {
			break
		}
		// expect '.'
		if b[i] != '.' {
			return false
		}
		i++
		// more parts expected
		if i >= n {
			return false
		}
	}
	return parts == 4
}

// isHeaderLine 判断文本行是否为表头
func isHeaderLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "ip") || strings.Contains(lower, "address") ||
		strings.Contains(lower, "ipaddress") || strings.Contains(lower, "ip地址")
}

// extractIPsFromBytes 从字节切片中提取所有IP（IPv4和IPv6混合）
func extractIPsFromBytes(line []byte) []string {
	var results []string
	l := len(line)
	i := 0
	ipSet := make(map[string]bool) // 本行去重

	for i < l {
		c := line[i]

		// 尝试 IPv4：数字并且下一个在合理长度内包含 '.'
		if isDigitByte(c) && (i == 0 || !isDigitByte(line[i-1])) {
			// 快速检查：向前查看点和数字，最多15个字符
			j := i
			dotCount := 0
			for j < l && j-i <= 15 {
				if isDigitByte(line[j]) {
					j++
					continue
				}
				if line[j] == '.' {
					dotCount++
					j++
					continue
				}
				break
			}
			if dotCount == 3 {
				cand := line[i:j]
				// 验证 IPv4 无分配：解析各段
				if validIPv4Bytes(cand) {
					ipStr := string(cand)
					// 最终的 net.ParseIP 检查以拒绝奇怪的情况（例如，256）
					if net.ParseIP(ipStr) != nil {
						if !ipSet[ipStr] {
							ipSet[ipStr] = true
							results = append(results, ipStr)
							if debug {
								fmt.Printf("DEBUG: 提取到IP: %s\n", ipStr)
							}
						}
						i = j
						continue
					}
				}
			}
		}

		// 尝试 IPv6：十六进制或 ':' 并且在合理长度内（最多 45 个字符）包含 ':'
		if (isHexByte(c) || c == ':') && (i == 0 || !(isHexByte(line[i-1]) || line[i-1] == ':')) {
			j := i
			hasColon := false
			for j < l && j-i <= 45 {
				b := line[j]
				if isHexByte(b) || b == ':' || b == '.' {
					if b == ':' {
						hasColon = true
					}
					j++
				} else {
					break
				}
			}
			if hasColon {
				cand := line[i:j]
				// 使用 net.ParseIP 进行强健的 IPv6 验证
				if ip := net.ParseIP(string(cand)); ip != nil && ip.To16() != nil && ip.To4() == nil {
					ipStr := string(cand)
					if !ipSet[ipStr] {
						ipSet[ipStr] = true
						results = append(results, ipStr)
						if debug {
							fmt.Printf("DEBUG: 提取到IP: %s\n", ipStr)
						}
					}
					i = j
					continue
				}
			}
		}

		i++
	}
	return results
}

// ==================== 处理流程 ====================

// QueryResult 查询结果
type QueryResult struct {
	IP      string
	Region  string
	Success bool
	Error   error
	Unknown bool
	IsIPv4  bool
}

// processQueryResult 处理查询结果并写入CSV
func processQueryResult(result *QueryResult) []string {
	row := make([]string, 0, 4)

	if !result.Success {
		if debug {
			row = append(row, result.IP, "", "失败", result.Error.Error())
		} else {
			row = append(row, result.IP, "")
		}
		return row
	}

	if result.Unknown {
		if debug {
			row = append(row, result.IP, "", "失败", "未找到归属地")
		} else {
			row = append(row, result.IP, "")
		}
		return row
	}

	// 成功的情况
	if debug {
		row = append(row, result.IP, result.Region, "成功", "")
	} else {
		row = append(row, result.IP, result.Region)
	}
	return row
}

// processIPsStreaming 流式处理IP文件
func processIPsStreaming(inputFile, outputFile string, ip2region *Ip2Region) error {
	input, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("打开输入文件失败: %w", err)
	}
	defer input.Close()

	output, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer output.Close()

	// 写入 UTF-8 BOM 头
	if _, err := output.Write([]byte("\uFEFF")); err != nil {
		return fmt.Errorf("写入UTF-8 BOM失败: %w", err)
	}

	bufOut := bufio.NewWriterSize(output, CSVBufferSize)
	csvWriter := csv.NewWriter(bufOut)
	defer func() {
		csvWriter.Flush()
		bufOut.Flush()
	}()

	// 写入 CSV 头部
	headers := []string{"IP地址", "归属地"}
	if debug {
		headers = append(headers, "状态", "错误信息")
	}
	if err := csvWriter.Write(headers); err != nil {
		return fmt.Errorf("写入CSV头部失败: %w", err)
	}

	reader := bufio.NewReader(input)

	var totalRows, totalCount, successCount, failCount, ipv4Count, ipv6Count int64
	startTime := time.Now()

	// 启动进度报告 goroutine
	stopProgress := make(chan bool)
	progressDone := make(chan bool)

	if !debug {
		fmt.Println("🔍 开始查询")
	} else {
		fmt.Println("🔍 开始查询")
	}

	go func() {
		ticker := time.NewTicker(ProgressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				printProgress(atomic.LoadInt64(&totalRows), atomic.LoadInt64(&totalCount),
					atomic.LoadInt64(&successCount), atomic.LoadInt64(&failCount),
					atomic.LoadInt64(&ipv4Count), atomic.LoadInt64(&ipv6Count), startTime)
			case <-stopProgress:
				printProgress(atomic.LoadInt64(&totalRows), atomic.LoadInt64(&totalCount),
					atomic.LoadInt64(&successCount), atomic.LoadInt64(&failCount),
					atomic.LoadInt64(&ipv4Count), atomic.LoadInt64(&ipv6Count), startTime)
				progressDone <- true
				return
			}
		}
	}()

	firstRecord := true
	for {
		lineBytes, err := reader.ReadBytes('\n')
		if err != nil && err != io.EOF {
			close(stopProgress)
			<-progressDone
			return fmt.Errorf("读取文本行失败: %w", err)
		}

		// 去除行尾换行符（兼容 CRLF）
		lineBytes = bytes.TrimRight(lineBytes, "\r\n")
		lineLen := len(lineBytes)

		// 将行计数提前
		atomic.AddInt64(&totalRows, 1)

		// 如果是 EOF 且当前行为空，则退出循环
		if err == io.EOF && lineLen == 0 {
			break
		}

		// 跳过 UTF-8 BOM
		if atomic.LoadInt64(&totalRows) == 1 && lineLen >= 3 {
			if lineBytes[0] == 0xEF && lineBytes[1] == 0xBB && lineBytes[2] == 0xBF {
				lineBytes = lineBytes[3:]
				lineLen = len(lineBytes)
			}
		}

		// 去除首尾空白
		trimmed := bytes.TrimSpace(lineBytes)
		trimmedLen := len(trimmed)

		// 处理首行表头
		if firstRecord {
			if trimmedLen == 0 {
				if err == io.EOF {
					break
				}
				continue
			}
			firstRecord = false
			if isHeaderLine(string(trimmed)) {
				if debug {
					fmt.Println("DEBUG: 跳过CSV/文本头部")
				}
				if err == io.EOF {
					break
				}
				continue
			}
		}

		// 跳过空行
		if trimmedLen == 0 {
			if err == io.EOF {
				break
			}
			continue
		}

		// 提取本行的所有 IP
		ips := extractIPsFromBytes(trimmed)
		if len(ips) == 0 {
			if err == io.EOF {
				break
			}
			continue
		}

		// 处理提取到的 IP
		for _, ip := range ips {
			atomic.AddInt64(&totalCount, 1)

			// 判断IP版本
			isIPv4 := strings.Contains(ip, ".")
			if isIPv4 {
				atomic.AddInt64(&ipv4Count, 1)
			} else {
				atomic.AddInt64(&ipv6Count, 1)
			}

			// 执行查询
			region, queryErr := ip2region.Search(ip)

			result := &QueryResult{IP: ip, Region: region, IsIPv4: isIPv4}

			if queryErr != nil {
				atomic.AddInt64(&failCount, 1)
				result.Success = false
				result.Error = queryErr
				if debug {
					fmt.Printf("❌ %s 错误: %v\n", ip, queryErr)
				}
			} else if region == "" {
				atomic.AddInt64(&failCount, 1)
				result.Success = true
				result.Unknown = true
				if debug {
					fmt.Printf("❌ %s 未找到归属地\n", ip)
				}
			} else {
				atomic.AddInt64(&successCount, 1)
				result.Success = true
				if debug {
					parts := strings.Split(region, "|")
					if len(parts) >= 5 {
						country, province, city, isp := parts[0], parts[2], parts[3], parts[4]
						// 处理"0"值
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
						fmt.Printf("✅ %s %s%s%s %s\n", ip, country, province, city, isp)
					} else {
						fmt.Printf("✅ %s %s\n", ip, region)
					}
				}
			}

			row := processQueryResult(result)
			csvWriter.Write(row)

			// 定期刷新缓冲区
			if atomic.LoadInt64(&totalCount)%FlushInterval == 0 {
				csvWriter.Flush()
				bufOut.Flush()
			}
		}

		if err == io.EOF {
			break
		}
	}

	close(stopProgress)
	<-progressDone

	csvWriter.Flush()
	bufOut.Flush()

	printFinalStats(atomic.LoadInt64(&totalRows), atomic.LoadInt64(&totalCount),
		atomic.LoadInt64(&successCount), atomic.LoadInt64(&failCount),
		atomic.LoadInt64(&ipv4Count), atomic.LoadInt64(&ipv6Count), time.Since(startTime), outputFile)
	return nil
}

// printProgress 打印进度信息
func printProgress(totalRows, totalCount, successCount, failCount, ipv4Count, ipv6Count int64, startTime time.Time) {
	elapsed := time.Since(startTime)
	if totalCount > 0 {
		rate := float64(totalCount) / elapsed.Seconds()
		fmt.Printf("\r📊 进度: 已处理 %d 行, 查询 %d 个IP (%.0f 条/秒): %d 失败: %d IPv4: %d IPv6: %d 耗时: %v",
			totalRows, totalCount, rate, successCount, failCount, ipv4Count, ipv6Count, elapsed.Round(time.Second))
	} else if totalRows > 0 {
		fmt.Printf("\r📊 进度: 已处理 %d 行, 等待发现IP... 耗时: %v",
			totalRows, elapsed.Round(time.Second))
	}
}

// printFinalStats 打印最终统计信息
func printFinalStats(totalRows, totalCount, successCount, failCount, ipv4Count, ipv6Count int64, elapsed time.Duration, outputFile string) {
	fmt.Print("\n")
	fmt.Printf("✅ 处理完成！\n")
	fmt.Printf("   总行数: %d 行\n", totalRows)
	fmt.Printf("   总查询数: %d 个IP\n", totalCount)
	fmt.Printf("   ✅ 成功: %d\n", successCount)
	fmt.Printf("   ❌ 失败: %d\n", failCount)
	fmt.Printf("   📘 IPv4: %d 个\n", ipv4Count)
	fmt.Printf("   📗 IPv6: %d 个\n", ipv6Count)

	if totalCount > 0 {
		rate := float64(totalCount) / elapsed.Seconds()
		fmt.Printf("   ⏱️ 总耗时: %v\n", elapsed.Round(time.Second))
		fmt.Printf("   ⚡ 平均速度: %.0f 个IP/秒\n", rate)
	} else {
		fmt.Printf("   未发现任何有效IP\n")
		fmt.Printf("   总耗时: %v\n", elapsed.Round(time.Second))
	}

	fmt.Printf("   📄 结果已保存到: %s\n", outputFile)
}

// ==================== 主程序代码 ====================

func main() {
	// 解析命令行参数
	debugFlag := flag.Bool("debug", false, "输出调试信息（状态和错误信息）")
	v4DB := flag.String("v4db", DefaultV4DB, "IPv4数据库文件路径")
	v6DB := flag.String("v6db", DefaultV6DB, "IPv6数据库文件路径")
	inputFile := flag.String("input", DefaultInputFile, "IP地址输入文件路径")
	outputFile := flag.String("output", DefaultOutputFile, "输出CSV文件路径")
	cachePolicy := flag.String("cache", DefaultCacheMode, "缓存策略: file/vectorIndex/content")
	flag.Parse()
	debug = *debugFlag

	fmt.Println("🔧 IP地址归属地查询工具")
	fmt.Println("=======================")

	// 创建Ip2Region服务
	ip2region, err := createIp2RegionService(*v4DB, *v6DB, *cachePolicy)
	if err != nil {
		fmt.Printf("❌ 创建查询服务失败: %v\n", err)
		fmt.Println("\n请确保数据库文件存在：")
		fmt.Println("  - " + DefaultV4DB)
		fmt.Println("  - " + DefaultV6DB)
		return
	}
	defer ip2region.Close()

	fmt.Println("✅ 数据库初始化成功")

	// 流式处理
	if err := processIPsStreaming(*inputFile, *outputFile, ip2region); err != nil {
		fmt.Printf("❌ 处理失败: %v\n", err)
	}
}
