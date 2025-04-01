package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"sync"
	"time"
)

// ChromeRequest 请求结构体
type ChromeRequest struct {
	URL          string            `json:"url"`
	APIURL       string            `json:"api_url,omitempty"`
	Method       string            `json:"method"`
	Body         string            `json:"body,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Cookies      map[string]string `json:"cookies,omitempty"`
	CookieDomain string            `json:"cookie_domain,omitempty"`
	PageID       string            `json:"page_id,omitempty"`
	BrowserID    string            `json:"browser_id"`
	Snapshot     bool              `json:"snapshot"`
}

// RequestResult 存储请求结果的结构体
type RequestResult struct {
	Index      int
	PageID     string
	StatusCode int
	Duration   time.Duration
	Success    bool
	ErrorMsg   string
	StartTime  time.Time
	EndTime    time.Time
}

func main() {
	// 命令行参数
	serverURL := flag.String("server", "http://localhost:8889/", "服务器地址")
	targetURL := flag.String("url", "https://www.google.com", "请求目标URL")
	concurrency := flag.Int("n", 10, "并发请求数量")
	browserID := flag.String("browser", "test_browser", "浏览器ID")
	pageIDPrefix := flag.String("prefix", "test_page_", "页面ID前缀")
	timeout := flag.Int("timeout", 60, "请求超时（秒）")
	output := flag.String("output", "", "输出结果到JSON文件")

	flag.Parse()

	fmt.Printf("开始测试，目标服务器: %s\n", *serverURL)
	fmt.Printf("并发请求数: %d, 浏览器ID: %s\n", *concurrency, *browserID)

	// 等待组，用于等待所有goroutine完成
	var wg sync.WaitGroup
	wg.Add(*concurrency)

	// 用于收集结果的通道
	results := make(chan RequestResult, *concurrency)

	// 开始时间
	startTime := time.Now()

	// 并发发送请求
	for i := 0; i < *concurrency; i++ {
		go func(index int) {
			defer wg.Done()

			// 为每个请求生成唯一的page_id
			pageID := fmt.Sprintf("%s%d", *pageIDPrefix, index)

			// 创建请求体
			reqBody := ChromeRequest{
				URL:       *targetURL,
				Method:    "GET",
				Headers:   map[string]string{},
				Cookies:   map[string]string{},
				PageID:    pageID,
				BrowserID: *browserID,
				Snapshot:  false,
			}

			// 转换为JSON
			jsonData, err := json.Marshal(reqBody)
			if err != nil {
				results <- RequestResult{
					Index:     index,
					PageID:    pageID,
					Success:   false,
					ErrorMsg:  fmt.Sprintf("无法序列化JSON: %v", err),
					StartTime: time.Now(),
					EndTime:   time.Now(),
				}
				return
			}

			// 创建HTTP请求
			req, err := http.NewRequest("POST", *serverURL, bytes.NewBuffer(jsonData))
			if err != nil {
				results <- RequestResult{
					Index:     index,
					PageID:    pageID,
					Success:   false,
					ErrorMsg:  fmt.Sprintf("创建请求失败: %v", err),
					StartTime: time.Now(),
					EndTime:   time.Now(),
				}
				return
			}

			// 设置头部
			req.Header.Set("Content-Type", "application/json")

			// 开始请求时间
			requestStart := time.Now()
			fmt.Printf("请求 %d (page_id=%s) 开始发送: %v\n", index, pageID, requestStart.Format("15:04:05.000"))

			// 设置超时时间
			client := &http.Client{
				Timeout: time.Duration(*timeout) * time.Second,
			}

			// 发送请求
			resp, err := client.Do(req)
			requestEnd := time.Now()

			if err != nil {
				results <- RequestResult{
					Index:     index,
					PageID:    pageID,
					Success:   false,
					ErrorMsg:  fmt.Sprintf("请求失败: %v", err),
					StartTime: requestStart,
					EndTime:   requestEnd,
					Duration:  requestEnd.Sub(requestStart),
				}
				return
			}
			defer resp.Body.Close()

			// 读取响应
			respBody, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				results <- RequestResult{
					Index:      index,
					PageID:     pageID,
					StatusCode: resp.StatusCode,
					Success:    false,
					ErrorMsg:   fmt.Sprintf("无法读取响应: %v", err),
					StartTime:  requestStart,
					EndTime:    requestEnd,
					Duration:   requestEnd.Sub(requestStart),
				}
				return
			}

			// 请求结束时间
			duration := requestEnd.Sub(requestStart)

			// 输出结果
			fmt.Printf("请求 %d (page_id=%s) 完成: HTTP状态码=%d, 耗时=%v\n",
				index, pageID, resp.StatusCode, duration)

			// 输出响应内容的前100个字符（如果响应较长）
			respString := string(respBody)
			if len(respString) > 100 {
				respString = respString[:100] + "..."
			}
			fmt.Printf("请求 %d 响应: %s\n", index, respString)

			// 发送结果到通道
			results <- RequestResult{
				Index:      index,
				PageID:     pageID,
				StatusCode: resp.StatusCode,
				Success:    resp.StatusCode >= 200 && resp.StatusCode < 300,
				StartTime:  requestStart,
				EndTime:    requestEnd,
				Duration:   duration,
			}
		}(i)
	}

	// 关闭结果通道的goroutine
	go func() {
		wg.Wait()
		close(results)
	}()

	// 收集所有结果
	var allResults []RequestResult
	for result := range results {
		allResults = append(allResults, result)
	}

	// 对结果进行排序（按开始时间）
	sort.Slice(allResults, func(i, j int) bool {
		return allResults[i].StartTime.Before(allResults[j].StartTime)
	})

	// 计算总耗时
	totalDuration := time.Since(startTime)

	// 统计成功/失败数量
	successCount := 0
	failureCount := 0
	var totalResponseTime time.Duration
	var minResponseTime time.Duration = -1
	var maxResponseTime time.Duration

	for _, result := range allResults {
		if result.Success {
			successCount++
		} else {
			failureCount++
		}

		totalResponseTime += result.Duration
		if minResponseTime == -1 || result.Duration < minResponseTime {
			minResponseTime = result.Duration
		}
		if result.Duration > maxResponseTime {
			maxResponseTime = result.Duration
		}
	}

	avgResponseTime := totalResponseTime / time.Duration(len(allResults))

	// 打印统计信息
	fmt.Printf("\n========= 测试统计 =========\n")
	fmt.Printf("总请求数: %d\n", *concurrency)
	fmt.Printf("成功请求: %d (%.1f%%)\n", successCount, float64(successCount)*100/float64(*concurrency))
	fmt.Printf("失败请求: %d (%.1f%%)\n", failureCount, float64(failureCount)*100/float64(*concurrency))
	fmt.Printf("总耗时: %v\n", totalDuration)
	fmt.Printf("平均响应时间: %v\n", avgResponseTime)
	fmt.Printf("最短响应时间: %v\n", minResponseTime)
	fmt.Printf("最长响应时间: %v\n", maxResponseTime)

	// 输出到文件
	if *output != "" {
		jsonResults, err := json.MarshalIndent(map[string]interface{}{
			"total_requests":       *concurrency,
			"successful_requests":  successCount,
			"failed_requests":      failureCount,
			"total_duration_ms":    totalDuration.Milliseconds(),
			"avg_response_time_ms": avgResponseTime.Milliseconds(),
			"min_response_time_ms": minResponseTime.Milliseconds(),
			"max_response_time_ms": maxResponseTime.Milliseconds(),
			"start_time":           startTime.Format(time.RFC3339),
			"end_time":             time.Now().Format(time.RFC3339),
			"results":              allResults,
		}, "", "  ")

		if err != nil {
			fmt.Printf("无法生成JSON结果: %v\n", err)
		} else {
			err = ioutil.WriteFile(*output, jsonResults, 0644)
			if err != nil {
				fmt.Printf("无法写入结果文件: %v\n", err)
			} else {
				fmt.Printf("结果已保存到文件: %s\n", *output)
			}
		}
	}
}
