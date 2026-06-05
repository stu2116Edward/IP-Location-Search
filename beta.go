package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 查询结果结构
type IPQueryResult struct {
	IP       string
	Region   string
	Success  bool
	ErrorMsg string
}

// IPv6数据库记录
type IPv6Record struct {
	StartIP  *big.Int
	EndIP    *big.Int
	Country  string
	Province string
	City     string
	ISP      string
}

// IPDatabase IP数据库（基于txt文件）
type IPDatabase struct {
	v4Records []IPRecord   // IPv4记录列表
	v6Records []IPv6Record // IPv6记录列表
}

// IPv4数据库记录
type IPRecord struct {
	StartIP  uint32
	EndIP    uint32
	Country  string
	Area     string
	Province string
	City     string
	ISP      string
}

// 全局调试标志
var debug bool

func main() {
	// 解析命令行参数
	debugFlag := flag.Bool("debug", false, "输出调试信息")
	v4DB := flag.String("v4db", "ipv4_source.txt", "IPv4数据库文件路径（txt格式）")
	v6DB := flag.String("v6db", "ipv6_source.txt", "IPv6数据库文件路径（txt格式）")
	inputFile := flag.String("input", "ips.txt", "IP地址输入文件路径（支持IPv4和IPv6混合）")
	outputFile := flag.String("output", "result.csv", "输出CSV文件路径")
	flag.Parse()
	debug = *debugFlag

	fmt.Println("🔧 IP地址归属地查询工具（文本数据库版）")
	fmt.Println("=======================================")

	// 创建数据库实例
	db := &IPDatabase{
		v4Records: make([]IPRecord, 0),
		v6Records: make([]IPv6Record, 0),
	}

	// 加载IPv4数据库
	if _, err := os.Stat(*v4DB); err == nil {
		fmt.Printf("📘 加载IPv4数据库: %s\n", *v4DB)
		if err := db.LoadV4Database(*v4DB); err != nil {
			fmt.Printf("❌ 加载IPv4数据库失败: %v\n", err)
			return
		}
		fmt.Printf("   ✅ IPv4数据库加载成功，共 %d 条记录\n", len(db.v4Records))
	} else {
		fmt.Printf("⚠️  IPv4数据库不存在: %s\n", *v4DB)
	}

	// 加载IPv6数据库
	if _, err := os.Stat(*v6DB); err == nil {
		fmt.Printf("📗 加载IPv6数据库: %s\n", *v6DB)
		if err := db.LoadV6Database(*v6DB); err != nil {
			fmt.Printf("❌ 加载IPv6数据库失败: %v\n", err)
			return
		}
		fmt.Printf("   ✅ IPv6数据库加载成功，共 %d 条记录\n", len(db.v6Records))
	} else {
		fmt.Printf("⚠️  IPv6数据库不存在: %s\n", *v6DB)
	}

	// 执行查询
	err := processIPsStreaming(*inputFile, *outputFile, db)
	if err != nil {
		fmt.Printf("❌ 处理失败: %v\n", err)
		return
	}
}

// LoadV4Database 加载IPv4文本数据库
func (db *IPDatabase) LoadV4Database(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

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
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			if debug && lineNum <= 10 {
				fmt.Printf("   ⚠️ 第%d行格式错误: %s\n", lineNum, line)
			}
			continue
		}

		record := IPRecord{}

		// 解析起始IP
		startIP, err := ipv4ToUint32(parts[0])
		if err != nil {
			if debug {
				fmt.Printf("   ⚠️ 第%d行起始IP无效: %s\n", lineNum, parts[0])
			}
			continue
		}

		// 解析结束IP
		endIP, err := ipv4ToUint32(parts[1])
		if err != nil {
			if debug {
				fmt.Printf("   ⚠️ 第%d行结束IP无效: %s\n", lineNum, parts[1])
			}
			continue
		}

		record.StartIP = startIP
		record.EndIP = endIP

		// 根据字段数量解析其他信息
		if len(parts) >= 7 {
			record.Country = parts[2]
			record.Area = parts[3]
			record.Province = parts[4]
			record.City = parts[5]
			record.ISP = parts[6]
		} else if len(parts) >= 6 {
			record.Country = parts[2]
			record.Province = parts[3]
			record.City = parts[4]
			record.ISP = parts[5]
		} else {
			record.Country = parts[2]
			record.Province = parts[3]
			record.City = parts[4]
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

// LoadV6Database 加载IPv6文本数据库
func (db *IPDatabase) LoadV6Database(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	lineNum := 0
	successCount := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// IPv6数据库格式：起始IP|结束IP|国家|省份|城市|运营商
		parts := strings.Split(line, "|")
		if len(parts) < 6 {
			if debug {
				fmt.Printf("   ⚠️ 第%d行格式错误（字段不足）: %s\n", lineNum, line)
			}
			continue
		}

		record := IPv6Record{}

		// 解析起始IP和结束IP为big.Int
		startIP := &big.Int{}
		endIP := &big.Int{}

		// 将IPv6字符串转换为big.Int
		startIP, err := parseIPv6ToBigInt(parts[0])
		if err != nil {
			if debug {
				fmt.Printf("   ⚠️ 第%d行起始IP无效: %s, 错误: %v\n", lineNum, parts[0], err)
			}
			continue
		}

		endIP, err = parseIPv6ToBigInt(parts[1])
		if err != nil {
			if debug {
				fmt.Printf("   ⚠️ 第%d行结束IP无效: %s, 错误: %v\n", lineNum, parts[1], err)
			}
			continue
		}

		record.StartIP = startIP
		record.EndIP = endIP

		// 解析其他字段
		record.Country = parts[2]
		if record.Country == "0" {
			record.Country = ""
		}

		if len(parts) >= 7 {
			record.Province = parts[3]
			record.City = parts[4]
			record.ISP = parts[6]
		} else {
			record.Province = parts[3]
			record.City = parts[4]
			record.ISP = parts[5]
		}

		if record.Province == "0" {
			record.Province = ""
		}
		if record.City == "0" {
			record.City = ""
		}
		if record.ISP == "0" {
			record.ISP = ""
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

// parseIPv6ToBigInt 将IPv6字符串转换为big.Int
func parseIPv6ToBigInt(ipv6 string) (*big.Int, error) {
	// 解析IPv6地址
	ip := net.ParseIP(ipv6)
	if ip == nil {
		return nil, fmt.Errorf("无效的IPv6地址: %s", ipv6)
	}

	// 转换为16字节表示
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, fmt.Errorf("无法转换为16字节: %s", ipv6)
	}

	// 转换为big.Int
	result := &big.Int{}
	result.SetBytes(ip16)

	return result, nil
}

// Search 查询IP地址
func (db *IPDatabase) Search(ip string) (string, error) {
	// 判断IP版本
	isIPv4 := strings.Contains(ip, ".")

	if isIPv4 {
		return db.searchIPv4(ip)
	} else {
		return db.searchIPv6(ip)
	}
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
			// 找到匹配
			return formatIPv4Region(record), nil
		}
	}

	return "", fmt.Errorf("未找到IP归属地")
}

// searchIPv6 查询IPv6地址
func (db *IPDatabase) searchIPv6(ip string) (string, error) {
	// 解析IPv6为big.Int
	ipNum, err := parseIPv6ToBigInt(ip)
	if err != nil {
		return "", err
	}

	// 二分查找
	left, right := 0, len(db.v6Records)-1

	for left <= right {
		mid := (left + right) / 2
		record := db.v6Records[mid]

		// 比较IP与起始IP
		cmpStart := ipNum.Cmp(record.StartIP)
		// 比较IP与结束IP
		cmpEnd := ipNum.Cmp(record.EndIP)

		if cmpStart < 0 {
			// IP小于起始IP
			right = mid - 1
		} else if cmpEnd > 0 {
			// IP大于结束IP
			left = mid + 1
		} else {
			// 找到匹配
			return formatIPv6Region(record), nil
		}
	}

	return "", fmt.Errorf("未找到IPv6归属地信息")
}

// formatIPv4Region 格式化IPv4输出区域信息
func formatIPv4Region(record IPRecord) string {
	country := record.Country
	if country == "" || country == "0" {
		country = "0"
	}

	area := record.Area
	if area == "" || area == "0" {
		area = "0"
	}

	province := record.Province
	if province == "" || province == "0" {
		province = "0"
	}

	city := record.City
	if city == "" || city == "0" {
		city = "0"
	}

	isp := record.ISP
	if isp == "" || isp == "0" {
		isp = "0"
	}

	return fmt.Sprintf("%s|%s|%s|%s|%s", country, area, province, city, isp)
}

// formatIPv6Region 格式化IPv6输出区域信息
func formatIPv6Region(record IPv6Record) string {
	country := record.Country
	if country == "" || country == "0" {
		country = "0"
	}

	province := record.Province
	if province == "" || province == "0" {
		province = "0"
	}

	city := record.City
	if city == "" || city == "0" {
		city = "0"
	}

	isp := record.ISP
	if isp == "" || isp == "0" {
		isp = "0"
	}

	return fmt.Sprintf("%s|0|%s|%s|%s", country, province, city, isp)
}

// ipv4ToUint32 将IPv4字符串转为uint32
func ipv4ToUint32(ip string) (uint32, error) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0, fmt.Errorf("无效的IPv4地址: %s", ip)
	}

	var result uint32
	for i := 0; i < 4; i++ {
		num, err := strconv.Atoi(parts[i])
		if err != nil {
			return 0, fmt.Errorf("无效的IPv4段: %s", parts[i])
		}
		if num < 0 || num > 255 {
			return 0, fmt.Errorf("无效的IPv4段: %d", num)
		}
		result = (result << 8) | uint32(num)
	}

	return result, nil
}

// readIPsFromFile 从文件中按顺序读取所有IP地址（IPv4和IPv6混合）
func readIPsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	// IPv4和IPv6正则表达式
	ipv4Regex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Regex := regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b`)

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var allIPs []string
	lineNum := 0
	ipSet := make(map[string]bool) // 用于去重，但保持第一次出现的顺序

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 按行处理，保持行的顺序
		// 先尝试提取IPv4地址
		ipv4Matches := ipv4Regex.FindAllString(line, -1)
		for _, ip := range ipv4Matches {
			if isValidIPv4(ip) {
				// 去重，但保持第一次出现的顺序
				if !ipSet[ip] {
					ipSet[ip] = true
					allIPs = append(allIPs, ip)
				}
			}
		}

		// 提取IPv6地址
		ipv6Matches := ipv6Regex.FindAllString(line, -1)
		for _, ip := range ipv6Matches {
			// 验证IPv6格式
			if net.ParseIP(ip) != nil {
				if !ipSet[ip] {
					ipSet[ip] = true
					allIPs = append(allIPs, ip)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}

	return allIPs, nil
}

// processIPsStreaming 流式处理IP文件（按顺序）
func processIPsStreaming(inputFile, outputFile string, db *IPDatabase) error {
	// 读取所有IP地址（保持顺序）
	fmt.Println("\n📖 读取IP地址文件...")

	if _, err := os.Stat(inputFile); err != nil {
		return fmt.Errorf("输入文件不存在: %s", inputFile)
	}

	fmt.Printf("   读取文件: %s\n", inputFile)
	allIPs, err := readIPsFromFile(inputFile)
	if err != nil {
		return fmt.Errorf("读取IP文件失败: %w", err)
	}

	if len(allIPs) == 0 {
		return fmt.Errorf("没有找到任何IP地址")
	}

	// 统计IPv4和IPv6数量
	ipv4Count := 0
	ipv6Count := 0
	for _, ip := range allIPs {
		if strings.Contains(ip, ".") {
			ipv4Count++
		} else {
			ipv6Count++
		}
	}

	fmt.Printf("   ✅ 找到 %d 个IP地址 (IPv4: %d, IPv6: %d)\n", len(allIPs), ipv4Count, ipv6Count)

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
	if err := csvWriter.Write(headers); err != nil {
		return fmt.Errorf("写入CSV头部失败: %w", err)
	}

	fmt.Println("\n🔍 开始查询...")
	fmt.Println()

	var totalCount, successCount, failCount int
	startTime := time.Now()

	// 按顺序查询每个IP
	for idx, ip := range allIPs {
		totalCount = idx + 1

		// 显示IP类型图标
		ipType := "🌐"
		if strings.Contains(ip, ".") {
			ipType = "📘"
		} else {
			ipType = "📗"
		}

		fmt.Printf("%s [%d/%d] 查询: %s ", ipType, totalCount, len(allIPs), ip)

		result := IPQueryResult{IP: ip}

		region, err := db.Search(ip)
		if err != nil {
			result.Success = false
			result.ErrorMsg = err.Error()
			failCount++
			fmt.Printf("❌ %v\n", err)
		} else if region == "" {
			result.Success = false
			result.ErrorMsg = "未找到归属地信息"
			failCount++
			fmt.Printf("❌ 未找到归属地\n")
		} else {
			result.Success = true
			result.Region = region
			successCount++
			// 格式化显示
			parts := strings.Split(region, "|")
			if len(parts) >= 5 {
				country := parts[0]
				if country == "0" {
					country = ""
				}
				province := parts[2]
				if province == "0" {
					province = ""
				}
				city := parts[3]
				if city == "0" {
					city = ""
				}
				isp := parts[4]
				if isp == "0" {
					isp = ""
				}
				if country != "" || province != "" || city != "" {
					fmt.Printf("✅ %s%s%s %s\n", country, province, city, isp)
				} else {
					fmt.Printf("✅ %s\n", region)
				}
			} else {
				fmt.Printf("✅ %s\n", region)
			}
		}

		// 写入CSV
		var row []string
		if debug {
			status := "失败"
			if result.Success {
				status = "成功"
			}
			row = []string{result.IP, result.Region, status, result.ErrorMsg}
		} else {
			row = []string{result.IP, result.Region}
		}
		if err := csvWriter.Write(row); err != nil {
			return fmt.Errorf("写入结果失败: %w", err)
		}

		// 定期刷新
		if totalCount%100 == 0 {
			csvWriter.Flush()
			elapsed := time.Since(startTime)
			fmt.Printf("📊 进度: %d/%d (%.1f%%), 成功:%d, 失败:%d, 耗时:%v\n",
				totalCount, len(allIPs), float64(totalCount)/float64(len(allIPs))*100,
				successCount, failCount, elapsed)
		}
	}

	// 打印统计信息
	elapsed := time.Since(startTime)
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("📊 查询统计:")
	fmt.Printf("  总查询数: %d\n", totalCount)
	fmt.Printf("  ✅ 成功: %d\n", successCount)
	fmt.Printf("  ❌ 失败: %d\n", failCount)
	if totalCount > 0 {
		fmt.Printf("  📈 成功率: %.2f%%\n", float64(successCount)/float64(totalCount)*100)
	}
	fmt.Printf("  ⏱️  总耗时: %v\n", elapsed)
	fmt.Printf("  ⚡ 平均速度: %.2f 个/秒\n", float64(totalCount)/elapsed.Seconds())
	fmt.Printf("  📄 结果保存到: %s\n", outputFile)
	fmt.Println(strings.Repeat("=", 50))

	return nil
}

// isValidIPv4 验证IPv4地址
func isValidIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
		num, _ := strconv.Atoi(part)
		if num < 0 || num > 255 {
			return false
		}
	}
	return true
}
