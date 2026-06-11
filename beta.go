//go:build ignore
// +build ignore

package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ==================== 常量定义 ====================
const (
	// 数据分隔符
	DataSeparator = "|"
	IPv4Sep       = "."
	IPv6Sep       = ":"

	// 默认值
	DefaultCountry  = "0"
	DefaultArea     = "0"
	DefaultProvince = "0"
	DefaultCity     = "0"
	DefaultISP      = "0"
	DefaultUnknown  = "未知"

	// 缓冲区和刷新
	CSVBufferSize    = 1 << 20 // 1MB
	FlushInterval    = 100
	ProgressInterval = 500 * time.Millisecond

	// 数据库路径
	DefaultV4DB       = "ipv4_source.txt"
	DefaultV6DB       = "ipv6_source.txt"
	DefaultInputFile  = "ips.txt"
	DefaultOutputFile = "result.csv"

	// IPv4/IPv6字段最小数量
	IPv4FieldsMin = 5
	IPv6FieldsMin = 6
	IPv4FieldsMax = 7
	IPv6FieldsMax = 7

	// 验证范围
	IPv4MaxNum = 255
	IPv4Parts  = 4
	IPv6Bytes  = 16
	IPv4Bytes  = 4

	// UTF-8 BOM
	UTF8BOM = "\uFEFF"
)

// ==================== 全局变量 ====================
var debug bool

// ==================== 数据结构 ====================

// IPv6Record IPv6数据库记录
type IPv6Record struct {
	StartIP  *big.Int
	EndIP    *big.Int
	Country  string
	Province string
	City     string
	ISP      string
}

// IPRecord IPv4数据库记录
type IPRecord struct {
	StartIP  uint32
	EndIP    uint32
	Country  string
	Area     string
	Province string
	City     string
	ISP      string
}

// IPDatabase IP数据库
type IPDatabase struct {
	v4Records []IPRecord
	v6Records []IPv6Record
}

// QueryResult 查询结果
type QueryResult struct {
	IP      string
	Region  string
	Success bool
	Error   error
	Unknown bool
	IsIPv4  bool
}

// ==================== IPv4 数据库函数 ====================

// LoadV4Database 加载IPv4文本数据库
func (db *IPDatabase) LoadV4Database(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, CSVBufferSize)
	scanner.Buffer(buf, CSVBufferSize*10)

	lineNum := 0
	successCount := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析格式：起始IP|结束IP|国家|区域|省份|城市|运营商
		parts := strings.Split(line, DataSeparator)
		if len(parts) < IPv4FieldsMin {
			if debug && lineNum <= 10 {
				fmt.Printf("   ⚠️ 第%d行格式错误: %s\n", lineNum, line)
			}
			continue
		}

		record, err := parseIPv4Record(parts, lineNum)
		if err != nil {
			if debug {
				fmt.Printf("   ⚠️ 第%d行解析错误: %v\n", lineNum, err)
			}
			continue
		}

		db.v4Records = append(db.v4Records, record)
		successCount++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	if successCount == 0 {
		return fmt.Errorf("未找到有效数据")
	}

	return nil
}

// parseIPv4Record 解析IPv4记录
func parseIPv4Record(parts []string, lineNum int) (IPRecord, error) {
	record := IPRecord{}

	// 解析起始IP
	startIP, err := ipv4ToUint32(parts[0])
	if err != nil {
		return record, fmt.Errorf("起始IP无效: %s", parts[0])
	}

	// 解析结束IP
	endIP, err := ipv4ToUint32(parts[1])
	if err != nil {
		return record, fmt.Errorf("结束IP无效: %s", parts[1])
	}

	record.StartIP = startIP
	record.EndIP = endIP

	// 根据字段数量解析其他信息
	switch {
	case len(parts) >= IPv4FieldsMax:
		record.Country = parts[2]
		record.Area = parts[3]
		record.Province = parts[4]
		record.City = parts[5]
		record.ISP = parts[6]
	case len(parts) >= 6:
		record.Country = parts[2]
		record.Province = parts[3]
		record.City = parts[4]
		record.ISP = parts[5]
	default:
		record.Country = parts[2]
		record.Province = parts[3]
		record.City = parts[4]
	}

	return record, nil
}

// ==================== IPv6 数据库函数 ====================

// LoadV6Database 加载IPv6文本数据库
func (db *IPDatabase) LoadV6Database(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, CSVBufferSize)
	scanner.Buffer(buf, CSVBufferSize*10)

	lineNum := 0
	successCount := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// IPv6数据库格式：起始IP|结束IP|国家|省份|城市|运营商
		parts := strings.Split(line, DataSeparator)
		if len(parts) < IPv6FieldsMin {
			if debug {
				fmt.Printf("   ⚠️ 第%d行格式错误（字段不足）: %s\n", lineNum, line)
			}
			continue
		}

		record, err := parseIPv6Record(parts, lineNum)
		if err != nil {
			if debug {
				fmt.Printf("   ⚠️ 第%d行解析错误: %v\n", lineNum, err)
			}
			continue
		}

		db.v6Records = append(db.v6Records, record)
		successCount++

		if debug && successCount <= 5 {
			fmt.Printf("   ✅ 加载IPv6记录: %s -> %s\n", parts[0], parts[1])
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	if successCount == 0 {
		return fmt.Errorf("未找到有效IPv6数据")
	}

	return nil
}

// parseIPv6Record 解析IPv6记录
func parseIPv6Record(parts []string, lineNum int) (IPv6Record, error) {
	record := IPv6Record{}

	// 解析起始IP
	startIP, err := parseIPv6ToBigInt(parts[0])
	if err != nil {
		return record, fmt.Errorf("起始IP无效: %v", err)
	}

	// 解析结束IP
	endIP, err := parseIPv6ToBigInt(parts[1])
	if err != nil {
		return record, fmt.Errorf("结束IP无效: %v", err)
	}

	record.StartIP = startIP
	record.EndIP = endIP

	// 解析国家
	record.Country = normalizeField(parts[2])

	// 解析其他字段
	if len(parts) >= IPv6FieldsMax {
		record.Province = normalizeField(parts[3])
		record.City = normalizeField(parts[4])
		record.ISP = normalizeField(parts[6])
	} else {
		record.Province = normalizeField(parts[3])
		record.City = normalizeField(parts[4])
		record.ISP = normalizeField(parts[5])
	}

	return record, nil
}

// ==================== IP 转换函数 ====================

// ipv4ToUint32 将IPv4字符串转为uint32
func ipv4ToUint32(ip string) (uint32, error) {
	parts := strings.Split(ip, IPv4Sep)
	if len(parts) != IPv4Parts {
		return 0, fmt.Errorf("无效的IPv4地址: %s", ip)
	}

	var result uint32
	for i := 0; i < IPv4Parts; i++ {
		num, err := strconv.Atoi(parts[i])
		if err != nil {
			return 0, fmt.Errorf("无效的IPv4段: %s", parts[i])
		}
		if num < 0 || num > IPv4MaxNum {
			return 0, fmt.Errorf("无效的IPv4段: %d", num)
		}
		result = (result << 8) | uint32(num)
	}

	return result, nil
}

// parseIPv6ToBigInt 将IPv6字符串转换为big.Int
func parseIPv6ToBigInt(ipv6 string) (*big.Int, error) {
	ip := net.ParseIP(ipv6)
	if ip == nil {
		return nil, fmt.Errorf("无效的IPv6地址: %s", ipv6)
	}

	ip16 := ip.To16()
	if ip16 == nil {
		return nil, fmt.Errorf("无法转换为16字节: %s", ipv6)
	}

	result := &big.Int{}
	result.SetBytes(ip16)
	return result, nil
}

// ==================== 查询函数 ====================

// Search 查询IP地址
func (db *IPDatabase) Search(ip string) (string, error) {
	if strings.Contains(ip, IPv4Sep) {
		return db.searchIPv4(ip)
	}
	return db.searchIPv6(ip)
}

// searchIPv4 查询IPv4地址
func (db *IPDatabase) searchIPv4(ip string) (string, error) {
	ipNum, err := ipv4ToUint32(ip)
	if err != nil {
		return "", err
	}

	// 二分查找
	left, right := 0, len(db.v4Records)-1

	for left <= right {
		mid := (left + right) / 2
		record := db.v4Records[mid]

		if ipNum < record.StartIP {
			right = mid - 1
		} else if ipNum > record.EndIP {
			left = mid + 1
		} else {
			return formatIPv4Region(record), nil
		}
	}

	return "", fmt.Errorf("未找到IP归属地")
}

// searchIPv6 查询IPv6地址
func (db *IPDatabase) searchIPv6(ip string) (string, error) {
	ipNum, err := parseIPv6ToBigInt(ip)
	if err != nil {
		return "", err
	}

	// 二分查找
	left, right := 0, len(db.v6Records)-1

	for left <= right {
		mid := (left + right) / 2
		record := db.v6Records[mid]

		cmpStart := ipNum.Cmp(record.StartIP)
		cmpEnd := ipNum.Cmp(record.EndIP)

		if cmpStart < 0 {
			right = mid - 1
		} else if cmpEnd > 0 {
			left = mid + 1
		} else {
			return formatIPv6Region(record), nil
		}
	}

	return "", fmt.Errorf("未找到IPv6归属地信息")
}

// ==================== 格式化函数 ====================

// formatIPv4Region 格式化IPv4输出区域信息
func formatIPv4Region(record IPRecord) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s",
		normalizeOutput(record.Country), DataSeparator,
		normalizeOutput(record.Area), DataSeparator,
		normalizeOutput(record.Province), DataSeparator,
		normalizeOutput(record.City), DataSeparator,
		normalizeOutput(record.ISP))
}

// formatIPv6Region 格式化IPv6输出区域信息
func formatIPv6Region(record IPv6Record) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s",
		normalizeOutput(record.Country), DataSeparator, "0", DataSeparator,
		normalizeOutput(record.Province), DataSeparator,
		normalizeOutput(record.City), DataSeparator,
		normalizeOutput(record.ISP))
}

// normalizeField 标准化字段值（处理空值和"0"）
func normalizeField(value string) string {
	if value == DefaultCountry || value == "" {
		return ""
	}
	return value
}

// normalizeOutput 标准化输出值
func normalizeOutput(value string) string {
	if value == "" {
		return DefaultCountry
	}
	return value
}

// ==================== IP 提取函数 ====================

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

// extractIPsFromBytes 从字节切片中提取所有IP（IPv4和IPv6混合，不去重）
func extractIPsFromBytes(line []byte) []string {
	var results []string
	l := len(line)
	i := 0

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
						results = append(results, ipStr)
						if debug {
							fmt.Printf("DEBUG: 提取到IPv4: %s\n", ipStr)
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
					results = append(results, ipStr)
					if debug {
						fmt.Printf("DEBUG: 提取到IPv6: %s\n", ipStr)
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

// ==================== 查询处理函数 ====================

// queryIP 查询单个IP
func queryIP(ip string, db *IPDatabase) *QueryResult {
	result := &QueryResult{IP: ip}

	// 判断IP版本
	result.IsIPv4 = strings.Contains(ip, IPv4Sep)

	region, err := db.Search(ip)

	if err != nil {
		result.Success = false
		result.Error = err
		result.Unknown = false
		result.Region = ""
	} else if region == "" {
		result.Success = true
		result.Unknown = true
		result.Region = ""
	} else {
		result.Success = true
		result.Unknown = false
		result.Region = region
	}

	return result
}

// processQueryResult 处理查询结果并转换为CSV行
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

// printDebugQuery 打印调试查询信息
func printDebugQuery(ip string, result *QueryResult, current, total int64) {
	ipType := "🌐"
	if result.IsIPv4 {
		ipType = "📘"
	} else {
		ipType = "📗"
	}

	fmt.Printf("%s [%d/%d] 查询: %s ", ipType, current, total, ip)

	if !result.Success {
		fmt.Printf("❌ %v\n", result.Error)
	} else if result.Unknown {
		fmt.Printf("❌ 未找到归属地\n")
	} else {
		parts := strings.Split(result.Region, DataSeparator)
		if len(parts) >= 5 {
			country, province, city, isp := parts[0], parts[2], parts[3], parts[4]

			if country == DefaultCountry {
				country = ""
			}
			if province == DefaultProvince {
				province = ""
			}
			if city == DefaultCity {
				city = ""
			}
			if isp == DefaultISP {
				isp = ""
			}

			if country != "" || province != "" || city != "" {
				fmt.Printf("✅ %s%s%s %s\n", country, province, city, isp)
			} else {
				fmt.Printf("✅ %s\n", result.Region)
			}
		} else {
			fmt.Printf("✅ %s\n", result.Region)
		}
	}
}

// ==================== 进度报告函数 ====================

// printProgress 打印进度信息
func printProgress(totalRows, totalCount, successCount, failCount, ipv4Count, ipv6Count int64, startTime time.Time) {
	elapsed := time.Since(startTime)
	if totalCount > 0 {
		rate := float64(totalCount) / elapsed.Seconds()
		fmt.Printf("\r📊 进度: 已处理 %d 行, 查询 %d 个IP (%.0f 条/秒) | ✅ %d ❌ %d | IPv4: %d IPv6: %d | 耗时: %v",
			totalRows, totalCount, rate, successCount, failCount, ipv4Count, ipv6Count, elapsed.Round(time.Second))
	} else if totalRows > 0 {
		fmt.Printf("\r📊 进度: 已处理 %d 行, 等待发现IP... 耗时: %v",
			totalRows, elapsed.Round(time.Second))
	}
}

// printFinalStats 打印最终统计信息
func printFinalStats(totalRows, totalCount, successCount, failCount, ipv4Count, ipv6Count int64, elapsed time.Duration, outputFile string) {
	fmt.Print("\n")
	fmt.Println("📊 查询统计:")
	fmt.Printf("   总行数: %d 行\n", totalRows)
	fmt.Printf("   总查询数: %d 个IP\n", totalCount)
	fmt.Printf("   ✅ 成功: %d\n", successCount)
	fmt.Printf("   ❌ 失败: %d\n", failCount)
	fmt.Printf("   📘 IPv4: %d 个\n", ipv4Count)
	fmt.Printf("   📗 IPv6: %d 个\n", ipv6Count)

	if totalCount > 0 {
		successRate := float64(successCount) / float64(totalCount) * 100
		rate := float64(totalCount) / elapsed.Seconds()
		fmt.Printf("   📈 成功率: %.2f%%\n", successRate)
		fmt.Printf("   ⏱️  总耗时: %v\n", elapsed.Round(time.Second))
		fmt.Printf("   ⚡ 平均速度: %.2f 个IP/秒\n", rate)
	} else {
		fmt.Printf("   未发现任何有效IP\n")
		fmt.Printf("   ⏱️  总耗时: %v\n", elapsed.Round(time.Second))
	}

	fmt.Printf("   📄 结果已保存到: %s\n", outputFile)
}

// ==================== 流式处理函数 ====================

// processIPsStreaming 流式处理IP文件
func processIPsStreaming(inputFile, outputFile string, db *IPDatabase) error {
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
	if _, err := output.Write([]byte(UTF8BOM)); err != nil {
		return fmt.Errorf("写入UTF-8 BOM失败: %w", err)
	}

	bufOut := bufio.NewWriterSize(output, CSVBufferSize)
	csvWriter := csv.NewWriter(bufOut)
	defer func() {
		csvWriter.Flush()
		bufOut.Flush()
	}()

	// 写入CSV头部
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

		// 提取本行的所有 IP（不去重）
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
			isIPv4 := strings.Contains(ip, IPv4Sep)
			if isIPv4 {
				atomic.AddInt64(&ipv4Count, 1)
			} else {
				atomic.AddInt64(&ipv6Count, 1)
			}

			// 执行查询
			result := queryIP(ip, db)

			if result.Success && !result.Unknown {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failCount, 1)
			}

			// 仅在调试模式下输出详细信息
			if debug {
				printDebugQuery(ip, result, atomic.LoadInt64(&totalCount), atomic.LoadInt64(&totalRows))
			}

			// 写入CSV
			row := processQueryResult(result)
			if err := csvWriter.Write(row); err != nil {
				close(stopProgress)
				<-progressDone
				return fmt.Errorf("写入结果失败: %w", err)
			}

			// 定期刷新
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

// ==================== 服务初始化 ====================

// createIPDatabase 创建IP数据库服务
func createIPDatabase(v4Path, v6Path string) (*IPDatabase, error) {
	db := &IPDatabase{
		v4Records: make([]IPRecord, 0),
		v6Records: make([]IPv6Record, 0),
	}

	// 加载IPv4数据库
	if _, err := os.Stat(v4Path); err == nil {
		fmt.Printf("📘 加载IPv4数据库: %s\n", v4Path)
		if err := db.LoadV4Database(v4Path); err != nil {
			return nil, fmt.Errorf("加载IPv4数据库失败: %w", err)
		}
		fmt.Printf("   ✅ IPv4数据库加载成功，共 %d 条记录\n", len(db.v4Records))
	} else {
		fmt.Printf("⚠️  IPv4数据库不存在: %s\n", v4Path)
	}

	// 加载IPv6数据库
	if _, err := os.Stat(v6Path); err == nil {
		fmt.Printf("📗 加载IPv6数据库: %s\n", v6Path)
		if err := db.LoadV6Database(v6Path); err != nil {
			return nil, fmt.Errorf("加载IPv6数据库失败: %w", err)
		}
		fmt.Printf("   ✅ IPv6数据库加载成功，共 %d 条记录\n", len(db.v6Records))
	} else {
		fmt.Printf("⚠️  IPv6数据库不存在: %s\n", v6Path)
	}

	if len(db.v4Records) == 0 && len(db.v6Records) == 0 {
		return nil, fmt.Errorf("没有加载任何数据库记录")
	}

	return db, nil
}

// ==================== 主程序代码 ====================

func main() {
	// 解析命令行参数
	debugFlag := flag.Bool("debug", false, "输出调试信息（状态和错误信息）")
	v4DB := flag.String("v4db", DefaultV4DB, "IPv4数据库文件路径")
	v6DB := flag.String("v6db", DefaultV6DB, "IPv6数据库文件路径")
	inputFile := flag.String("input", DefaultInputFile, "IP地址输入文件路径")
	outputFile := flag.String("output", DefaultOutputFile, "输出CSV文件路径")
	flag.Parse()
	debug = *debugFlag

	fmt.Println("🔧 IP地址归属地查询工具（文本数据库版）")

	// 创建数据库
	db, err := createIPDatabase(*v4DB, *v6DB)
	if err != nil {
		fmt.Printf("❌ 创建数据库失败: %v\n", err)
		fmt.Println("\n请确保数据库文件存在：")
		fmt.Printf("  - %s\n", DefaultV4DB)
		fmt.Printf("  - %s\n", DefaultV6DB)
		return
	}

	fmt.Println("✅ 数据库初始化成功")

	// 流式处理
	if err := processIPsStreaming(*inputFile, *outputFile, db); err != nil {
		fmt.Printf("❌ 处理失败: %v\n", err)
	}
}
