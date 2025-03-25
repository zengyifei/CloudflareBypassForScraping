import json
import re
import os
from urllib.parse import urlparse

from CloudflareBypasser import CloudflareBypasser
from DrissionPage import ChromiumPage, ChromiumOptions
from fastapi import FastAPI, HTTPException, Response, Body
from pydantic import BaseModel, Field
from typing import Dict, Optional, Any
import argparse

from pyvirtualdisplay import Display
import uvicorn
import atexit
import asyncio
import websockets
import json

# Check if running in Docker mode
# 检测操作系统类型，如果是Linux则设置为true，否则为false
import platform
DOCKER_MODE = os.getenv("DOCKERMODE", "true" if platform.system() == "Linux" else "false").lower() == "true"

SERVER_PORT = int(os.getenv("SERVER_PORT", 8889))

# Chromium options arguments
arguments = [
    # "--remote-debugging-port=9222",  # Add this line for remote debugging
    "-no-first-run",
    "-force-color-profile=srgb",
    "-metrics-recording-only",
    "-password-store=basic",
    "-use-mock-keychain",
    "-export-tagged-pdf",
    "-no-default-browser-check",
    "-disable-background-mode",
    "-enable-features=NetworkService,NetworkServiceInProcess,LoadCryptoTokenExtension,PermuteTLSExtensions",
    "-disable-features=FlashDeprecationWarning,EnablePasswordsAccountStorage",
    "-deny-permission-prompts",
    "-disable-gpu",
    "-accept-lang=en-US",
    # "-incognito" # You can add this line to open the browser in incognito mode by default
]

# 在文件顶部添加环境变量设置
BROWSER_TYPE = os.getenv("BROWSER_TYPE", "edge").lower()  # 默认使用 Edge，可以通过环境变量覆盖

# 根据系统查找 Edge 浏览器路径
if BROWSER_TYPE == "edge":
    # 在不同系统上查找 Edge 浏览器路径
    edge_paths = [
        "/usr/bin/microsoft-edge",
        "/usr/bin/microsoft-edge-stable",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
    ]

    browser_path = None
    for path in edge_paths:
        if os.path.exists(path):
            browser_path = path
            break

    if not browser_path:
        print("Warning: Microsoft Edge not found, using default browser")
        browser_path = "/usr/bin/google-chrome"  # 默认路径
else:
    browser_path = "/usr/bin/google-chrome"

# 设置 DrissionPage 使用 Edge 浏览器
if BROWSER_TYPE == "edge":
    # 使用 DrissionPage 的配置方法设置 Edge
    from DrissionPage import ChromiumOptions
    co = ChromiumOptions()
    co.set_browser_path(browser_path)
    co.save()  # 保存配置，这样后续启动都会使用这个设置

app = FastAPI()

# Storage for page and browser instances
page_cache = {}
browser_cache = {}

# Pydantic model for the response


class CookieResponse(BaseModel):
    cookies: Dict[str, str]
    user_agent: str

# New ChromeRequest model


class ChromeRequest(BaseModel):
    url: str = Field(...)            # Which page to enter first
    api_url: Optional[str] = Field(None)       # After entering the url, the api to call
    method: str = Field("GET")       # GET || POST
    body: Optional[str] = Field(None)
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    cookie_domain: Optional[str] = Field(None)  # Specify the domain of the cookie

    page_id: Optional[str] = Field(None)  # Page id, if passed will cache the page, enter resident, faster next visit. If not passed, will close the page
    # browser id, same as page_id, not passed use default window, passed will reuse window, if not exist create a new one
    browser_id: str = Field("default")

    snapshot: bool = Field(False)     # Whether to take a screenshot on failure, for debugging, do not use in production

    class Config:
        schema_extra = {
            "example-req": {
                "url": "https://blur.io/",
                "api_url": "https://core-api.prod.blur.io/v1/buy/0x05da517b1bf9999b7762eaefa8372341a1a47559",
                "headers": {
                    "<header-name>": "<header-value>",
                },
                "method": "POST",
                "body": "<api-url-request-body>",
                "cookies": {
                    "<cookie-name>": "<cookie-value>",
                },
                "page_id": "blur",
                "browser_id": "blur"
            },
        }

# Function to check if the URL is safe


def is_safe_url(url: str) -> bool:
    parsed_url = urlparse(url)
    ip_pattern = re.compile(
        r"^(127\.0\.0\.1|localhost|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|172\.1[6-9]\.\d+\.\d+|172\.2[0-9]\.\d+\.\d+|172\.3[0-1]\.\d+\.\d+|192\.168\.\d+\.\d+)$"
    )
    hostname = parsed_url.hostname
    if (hostname and ip_pattern.match(hostname)) or parsed_url.scheme == "file":
        return False
    return True


# Function to bypass Cloudflare protection
def bypass_cloudflare(url: str, retries: int, log: bool, proxy: str = None) -> ChromiumPage:

    options = ChromiumOptions().auto_port()
    if DOCKER_MODE:
        options.set_argument("--auto-open-devtools-for-tabs", "true")
        options.set_argument("--remote-debugging-port=9222")
        options.set_argument("--no-sandbox")  # Necessary for Docker
        options.set_argument("--disable-gpu")  # Optional, helps in some cases
        options.set_paths(browser_path=browser_path).headless(False)
    else:
        options.set_paths(browser_path=browser_path).headless(False)

    if proxy:
        options.set_proxy(proxy)

    driver = ChromiumPage(addr_or_opts=options)
    try:
        driver.get(url)
        cf_bypasser = CloudflareBypasser(driver, retries, log)
        cf_bypasser.bypass()
        return driver
    except Exception as e:
        driver.quit()
        raise e


# Endpoint to get cookies
@app.get("/cookies", response_model=CookieResponse)
async def get_cookies(url: str, retries: int = 5, proxy: str = None):
    if not is_safe_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL")
    try:
        driver = bypass_cloudflare(url, retries, log, proxy)
        cookies = {cookie.get("name", ""): cookie.get("value", " ") for cookie in driver.cookies()}
        user_agent = driver.user_agent
        driver.quit()
        return CookieResponse(cookies=cookies, user_agent=user_agent)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Endpoint to get HTML content and cookies
@app.get("/html")
async def get_html(url: str, retries: int = 5, proxy: str = None):
    if not is_safe_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL")
    try:
        driver = bypass_cloudflare(url, retries, log, proxy)
        html = driver.html
        cookies_json = {cookie.get("name", ""): cookie.get("value", " ") for cookie in driver.cookies()}
        response = Response(content=html, media_type="text/html")
        response.headers["cookies"] = json.dumps(cookies_json)
        response.headers["user_agent"] = driver.user_agent
        driver.quit()
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Get or create browser instance
def get_or_create_browser(browser_id: str, proxy: str = None) -> ChromiumPage:
    if browser_id in browser_cache:
        return browser_cache[browser_id]

    options = ChromiumOptions().auto_port()
    # options.set_argument("--remote-allow-origins=*")
    if DOCKER_MODE:
        options.set_argument("--auto-open-devtools-for-tabs", "true")  # 打开控制台
        # options.set_argument("--remote-debugging-port=9222")
        options.set_argument("--no-sandbox")  # Docker 中必需
        options.set_argument("--disable-gpu")  # 在某些情况下有帮助
        options.set_paths(browser_path=browser_path).headless(False)
    else:
        options.set_paths(browser_path=browser_path).headless(False)

    if proxy:
        options.set_proxy(proxy)

    driver = ChromiumPage(addr_or_opts=options)
    browser_cache[browser_id] = driver
    return driver


# Solve Cloudflare challenge
async def solve_cloudflare(page: ChromiumPage, retries: int = 5, log: bool = True) -> bool:
    try:
        cf_bypasser = CloudflareBypasser(page, retries, log)
        cf_bypasser.bypass()
        return True
    except Exception as e:
        print(f"Cloudflare bypass error: {str(e)}")
        return False


# 修改关闭页面和清理缓存的辅助函数
def cleanup_page(page, page_key=None, browser_id=None):
    """关闭标签页并清理相关缓存"""
    # 从页面缓存中删除
    if page_key and page_key in page_cache:
        del page_cache[page_key]

    # 关闭标签页
    if page:
        try:
            # 尝试关闭标签页
            try:
                # 尝试使用 close 方法
                page.close()
            except:
                try:
                    # 尝试使用 tab_close 方法
                    page.tab_close()
                except:
                    # 如果都失败，尝试使用 JavaScript 关闭
                    page.run_js('window.close()')
        except Exception as e:
            print(f"关闭标签页时出错: {str(e)}")


# 修改获取或创建页面的函数，处理浏览器连接断开的情况
async def get_or_create_page(page_key: str = None, browser_id: str = "default", url: str = None, cookies: Dict[str, str] = None, cookie_domain: str = None, snapshot: bool = False):
    """
    获取或创建页面，处理页面连接断开等异常情况，自动解决 Cloudflare 挑战
    """
    page = None
    is_new = False
    success = True
    error_msg = None
    browser = None

    # 尝试从缓存获取页面
    if page_key and page_key in page_cache:
        page = page_cache[page_key]

        # 检查页面连接是否正常
        try:
            # 使用一个简单的操作来测试页面连接
            page.run_js('1+1')
        except Exception as e:
            print(f"检测到页面连接已断开，重新创建页面: {str(e)}")
            # 清理旧页面
            cleanup_page(page, page_key, browser_id)
            # 将页面设为 None，下面会重新创建
            page = None
            # 从缓存中移除
            if page_key in page_cache:
                del page_cache[page_key]

    # 如果没有缓存的页面或页面连接已断开，创建新页面
    if page is None and url:
        is_new = True
        try:
            # 检查浏览器是否存在且连接正常
            if browser_id in browser_cache:
                browser = browser_cache[browser_id]
                try:
                    # 测试浏览器连接
                    browser.run_js('1+1')
                except Exception as e:
                    print(f"检测到浏览器连接已断开，重新创建浏览器: {str(e)}")
                    # 从缓存中移除
                    if browser_id in browser_cache:
                        try:
                            browser_cache[browser_id].quit()
                        except:
                            pass
                        del browser_cache[browser_id]
                    browser = None

            # 如果浏览器不存在或连接断开，创建新浏览器
            if browser is None:
                browser = get_or_create_browser(browser_id)

            # 创建新标签页
            page = browser.new_tab()
            # 导航到 URL
            page.get(url)

            # 设置 cookies
            if cookies:
                for name, value in cookies.items():
                    domain = cookie_domain or urlparse(url).netloc
                    page.set_cookies({name: value}, domain=domain)

            # 自动尝试解决 Cloudflare 挑战
            solved = await solve_cloudflare(page)
            if not solved:
                success = False
                error_msg = "绕过cloudflare失败"

                # 如果需要截图
                if snapshot:
                    try:
                        os.makedirs('screenshot', exist_ok=True)
                        page.save_screenshot(f'screenshot/{urlparse(url).netloc}.png')
                        with open(f'screenshot/{urlparse(url).netloc}.html', "w", encoding="utf-8") as f:
                            f.write(page.html)
                    except Exception as e:
                        print(f"截图失败: {str(e)}")

                # 清理资源
                cleanup_page(page, page_key, browser_id)
                page = None
            else:
                # 如果需要缓存页面
                if page_key:
                    page_cache[page_key] = page

        except Exception as e:
            success = False
            error_msg = f"创建页面失败: {str(e)}"
            if page:
                cleanup_page(page, page_key, browser_id)
                page = None

    return page, is_new, success, error_msg


# New POST request endpoint
@app.post("/")
async def chrome_request(req: ChromeRequest):
    if not is_safe_url(req.url):
        raise HTTPException(status_code=400, detail="Invalid URL")

    # 获取页面缓存键
    page_key = f"{req.browser_id}_{req.page_id}" if req.page_id else None

    try:
        # 获取或创建页面
        page, is_new, success, error_msg = await get_or_create_page(
            page_key=page_key,
            browser_id=req.browser_id,
            url=req.url,
            cookies=req.cookies,
            cookie_domain=req.cookie_domain,
            snapshot=req.snapshot
        )

        if not success:
            return {"ok": False, "msg": error_msg}

        if not page:
            return {"ok": False, "msg": "Failed to create page"}

        # 处理请求
        if not req.api_url:
            resp_data = page.html
            resp_obj = resp_data
        else:
            headers = {
                "accept": "*/*",
                "accept-language": "zh-CN,zh;q=0.9",
                "content-type": "application/json",
                "sec-ch-ua": '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"macOS"',
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-site"
            }

            for k, v in req.headers.items():
                headers[k.lower()] = v

            script = """
                async () => {
                    try {
                        let resp = await fetch("%s", {
                            "headers": %s,
                            "method": "%s",
                            "body": %s,
                            "referrer": "%s",
                            "referrerPolicy": "strict-origin-when-cross-origin", 
                            "mode": "cors",
                            "keepalive": true,
                            "credentials": "include"
                        });
                        return await resp.text();
                    } catch (e) {
                        return JSON.stringify({"error": e.toString()});
                    }
                }
            """ % (req.api_url, json.dumps(headers), req.method,
                   json.dumps(req.body) if req.body else "null", req.url)

            # 打印请求信息
            print(f"API Request: {req.method} {req.api_url}")
            print(f"Headers: {json.dumps(headers)[:200]}{'...' if len(json.dumps(headers)) > 200 else ''}")
            if req.body:
                print(f"Body: {req.body[:200]}{'...' if len(req.body) > 200 else ''}")

            resp_data = page.run_js(script)

            # 打印响应数据
            print(f"API Response: {resp_data[:500]}{'...' if len(resp_data) > 500 else ''}")

            resp_obj = resp_data

            if "content-type" in headers and headers["content-type"].lower() == "application/json":
                try:
                    resp_obj = json.loads(resp_data)
                except Exception as e:
                    # 解析 JSON 失败，清理资源
                    cleanup_page(page, page_key, req.browser_id)

                    return {"ok": False, "msg": f"非 JSON 数据: {resp_data}"}

        # 如果不需要缓存页面，则清理
        if not page_key:
            print('关闭页面', req.browser_id, req.browser_id not in browser_cache)
            cleanup_page(page, page_key, req.browser_id)

        return resp_obj

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Error in chrome_request: {error_trace}")

        # 如果需要截图
        if req.snapshot and page:
            try:
                os.makedirs('screenshot', exist_ok=True)
                page.save_screenshot(f'screenshot/error_{urlparse(req.url).netloc}.png')
                with open(f'screenshot/error_{urlparse(req.url).netloc}.html', "w", encoding="utf-8") as f:
                    f.write(page.html)
            except Exception as screenshot_error:
                print(f"Error taking screenshot: {str(screenshot_error)}")

        # 清理资源
        cleanup_page(page, page_key, req.browser_id)

        return {"ok": False, "msg": str(e), "trace": error_trace}


async def setup_breakpoint_and_expose_function(page, chunk_url, line_number=0, column_number=0, target_func_name="targetFunction", export_func_name="exposedFunction"):
    # 初始化 ws 变量为 None，确保在 finally 块中可以安全引用
    ws = None

    # page.run_cdp("Debugger.enable")
    # 获取当前页面的targetId
    target_info = page.run_cdp("Target.getTargetInfo")
    target_id = target_info.get('targetInfo', {}).get('targetId')
    if not target_id:
        print("无法获取目标ID")
        return False

    # 构建WebSocket URL
    ws_url = f"ws://{page.address}/devtools/page/{target_id}"
    print(f"连接DevTools WebSocket: {ws_url}")
    try:
        # 移除 timeout 参数，使其兼容 Python 3.10
        ws = await websockets.connect(ws_url)
        print("WebSocket连接已打开")
        # 启用调试器
        await ws.send(json.dumps({
            "id": 1,
            "method": "Debugger.enable"
        }))
        # 设置断点
        await ws.send(json.dumps({
            "id": 2,
            "method": "Debugger.setBreakpointByUrl",
            "params": {
                "url": chunk_url,
                "lineNumber": line_number,
                "columnNumber": column_number,
            }
        }))

        # print("监听消息")
        # --- 第二阶段：监听消息直到满足条件 ---
        trigger_received = False
        while not trigger_received:
            # 使用 asyncio.wait_for 设置超时，而不是在 connect 中设置
            response = await asyncio.wait_for(ws.recv(), timeout=10)
            # print(f"收到消息: {response}")
            data = json.loads(response)
            # 检查是否为断点暂停事件
            if data.get('method') == 'Debugger.paused':
                params = data.get('params', {})
                hit_breakpoints = params.get('hitBreakpoints', [])
                call_frame_id = params.get('callFrames', [])[0].get('callFrameId')

                if hit_breakpoints:
                    hit_id = hit_breakpoints[0]
                    trigger_received = True
                    # print(f"断点触发")

                    # 注入辅助函数
                    # ----------- 这是关键部分 - 将我们要找的函数暴露到全局作用域 ------------
                    script = """
                            console.log('目标函数', """ + target_func_name + """);
                            window.""" + export_func_name + """ = """ + target_func_name + """; 
                            """
                    await ws.send(json.dumps({
                        "id": 999,
                        "method": "Debugger.evaluateOnCallFrame",
                        "params": {
                            "callFrameId": call_frame_id,
                            "expression": script
                        }
                    }))

                    # 移除断点
                    await ws.send(json.dumps({
                        "id": 1000,
                        "method": "Debugger.removeBreakpoint",
                        "params": {
                            "breakpointId": hit_id
                        }
                    }))

                    # 恢复执行
                    await ws.send(json.dumps({
                        "id": 1001,
                        "method": "Debugger.resume",
                        "params": {}
                    }))

    except asyncio.TimeoutError:
        print("操作超时，强制关闭连接")
    except websockets.exceptions.ConnectionClosed as e:
        print(f"连接异常关闭: {e.code} {e.reason}")
    except Exception as e:
        print(f"未知错误: {str(e)}")
    finally:
        # 安全地关闭 WebSocket 连接
        if ws is not None:
            try:
                await ws.close()
            except Exception as e:
                print(f"关闭 WebSocket 连接时出错: {str(e)}")

    return True


# 修改 Debank API 请求模型


class DebankRequest(BaseModel):
    method: str = Field(...)  # HTTP 方法，如 GET、POST 等
    route: str = Field(...)   # API 路由，如 "/v1/user/profile"
    data: Optional[Dict[str, Any]] = Field(None)  # 请求数据对象

# 修改 Debank API 端点


@app.post("/debank_sign")
async def debank_sign(req: DebankRequest):
    # 设置页面缓存键
    page_key = f"debank_daemon"
    browser_id = "default"
    page = None  # 初始化 page 变量为 None

    try:
        # 获取或创建页面
        page, is_new, success, error_msg = await get_or_create_page(
            page_key=page_key,
            browser_id=browser_id,
            url="https://debank.com/profile/0x3fe861679bd8ec58dd45460ffd38ee39107aaff8/history" if not page_key in page_cache else None
        )

        if not success:
            return {"ok": False, "msg": error_msg}

        if not page:
            return {"ok": False, "msg": "Failed to create page"}

        target_func_name = "x"
        export_func_name = "debank_sign"
        # 检查 window.debank_sign 函数是否存在
        check_script = """typeof window.""" + export_func_name + """ === 'function'"""
        has_debank_sign = page.run_js(check_script, as_expr=True)
        if not has_debank_sign:
            await setup_breakpoint_and_expose_function(page, "https://assets.debank.com/static/js/6129.fbaacfcf.chunk.js", line_number=1, column_number=45827, target_func_name=target_func_name, export_func_name=export_func_name)
            has_debank_sign = page.run_js(check_script, as_expr=True)
            print(has_debank_sign, 'script', check_script)
        if not has_debank_sign:
            raise Exception("window.debank_sign 函数不存在，暂不支持此操作")

        sign_script = """
                try {
                    // 确保参数格式正确
                    const data = %s;
                    const method = "%s";
                    const route = "%s";
                    const options = {"version": "v2"};
                    // 调用函数
                    const result = window.debank_sign(data, method, route, options);
                    return result;
                    // return {...result, "user_agent": navigator.userAgent};
                } catch (e) {
                    console.error("调用 debank_sign 出错:", e);
                    return {"error": e.toString()};
                }
        """ % (json.dumps(req.data) if req.data else "{}", req.method, req.route)
        # print('sign_script', sign_script)

        sign_result = page.run_js(sign_script)
        # print('sign_result', sign_result)

        # 检查结果是否包含错误
        if isinstance(sign_result, dict) and 'error' in sign_result:
            # 清理资源
            if not page_key:
                cleanup_page(page, page_key, browser_id)
            return {"ok": False, "msg": f"调用 window.debank_sign 失败: {sign_result['error']}"}

        # 返回 API 调用结果和签名信息
        return {
            # "user_agent": sign_result.get('user_agent', ''),
            "nonce": sign_result.get('nonce', ''),
            "ts": sign_result.get('ts', 0),
            "signature": sign_result.get('signature', ''),
            "version": sign_result.get('version', '')
        }

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Debank API 错误: {error_trace}")

        # 清理资源（只有当 page 不为 None 时才清理）
        if page:
            cleanup_page(page, page_key, browser_id)

        return {"ok": False, "msg": str(e), "trace": error_trace}


# Main entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cloudflare bypass api")

    parser.add_argument("--nolog", action="store_true", help="Disable logging")
    parser.add_argument("--headless", action="store_true", help="Run in headless mode")

    args = parser.parse_args()
    display = None

    if args.headless or DOCKER_MODE:
        display = Display(visible=0, size=(1920, 1080))
        display.start()

        def cleanup_display():
            if display:
                display.stop()
        atexit.register(cleanup_display)

    if args.nolog:
        log = False
    else:
        log = True

    uvicorn.run(app, host="0.0.0.0", port=SERVER_PORT)
