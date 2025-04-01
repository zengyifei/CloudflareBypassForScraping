package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
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

func main() {
	// 服务器地址
	serverURL := "http://localhost:8889/"

	// 并发请求数量
	concurrentRequests := 10

	// 等待组，用于等待所有goroutine完成
	var wg sync.WaitGroup
	wg.Add(concurrentRequests)

	// 开始时间
	startTime := time.Now()

	// 并发发送请求
	for i := 0; i < concurrentRequests; i++ {
		go func(index int) {
			defer wg.Done()

			// 为每个请求生成唯一的page_id
			pageID := fmt.Sprintf("test_page_%d", index)

			// 创建请求体
			reqBody := ChromeRequest{
				URL:       "https://www.google.com",
				Method:    "GET",
				Headers:   map[string]string{},
				Cookies:   map[string]string{},
				PageID:    pageID,
				BrowserID: "test_browser",
				Snapshot:  false,
			}

			// 转换为JSON
			jsonData, err := json.Marshal(reqBody)
			if err != nil {
				fmt.Printf("请求 %d 错误: 无法序列化JSON: %v\n", index, err)
				return
			}

			// 创建HTTP请求
			req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(jsonData))
			if err != nil {
				fmt.Printf("请求 %d 错误: 创建请求失败: %v\n", index, err)
				return
			}

			// 设置头部
			req.Header.Set("Content-Type", "application/json")

			// 开始请求时间
			requestStart := time.Now()
			fmt.Printf("请求 %d (page_id=%s) 开始发送: %v\n", index, pageID, requestStart.Format("15:04:05.000"))

			// 发送请求
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				fmt.Printf("请求 %d 错误: %v\n", index, err)
				return
			}
			defer resp.Body.Close()

			// 读取响应
			respBody, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("请求 %d 错误: 无法读取响应: %v\n", index, err)
				return
			}

			// 请求结束时间
			requestEnd := time.Now()
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
		}(i)
	}

	// 等待所有请求完成
	wg.Wait()

	// 计算总耗时
	totalDuration := time.Since(startTime)
	fmt.Printf("\n所有 %d 个请求已完成，总耗时: %v\n", concurrentRequests, totalDuration)
	fmt.Printf("平均每个请求耗时: %v\n", totalDuration/time.Duration(concurrentRequests))
}
