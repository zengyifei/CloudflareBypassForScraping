import json
import re
import os
import asyncio
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

# Check if running in Docker mode
DOCKER_MODE = os.getenv("DOCKERMODE", "false").lower() == "true"

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
    if DOCKER_MODE:
        options.set_argument("--auto-open-devtools-for-tabs", "true")
        options.set_argument("--remote-debugging-port=9222")
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


# New POST request endpoint
@app.post("/")
async def chrome_request(req: ChromeRequest):
    if not is_safe_url(req.url):
        raise HTTPException(status_code=400, detail="Invalid URL")

    # Check if there is a cached page
    page_key = f"{req.browser_id}_{req.page_id}" if req.page_id else None
    page = None

    try:
        if page_key and page_key in page_cache:
            page = page_cache[page_key]
        else:
            # Get or create browser instance
            browser = get_or_create_browser(req.browser_id)
            page = browser

            # Navigate to URL
            page.get(req.url)

            # Set cookies
            if req.cookies:
                for name, value in req.cookies.items():
                    domain = req.cookie_domain or urlparse(req.url).netloc
                    page.set_cookies({name: value}, domain=domain)

            # If need to cache the page
            if page_key:
                page_cache[page_key] = page

        # Try to solve Cloudflare challenge
        solved = await solve_cloudflare(page)
        if not solved:
            if req.snapshot:
                os.makedirs('screenshot', exist_ok=True)
                page.save_screenshot(f'screenshot/{urlparse(req.url).netloc}.png')
                with open(f'screenshot/{urlparse(req.url).netloc}.html', "w", encoding="utf-8") as f:
                    f.write(page.html)
            return {"ok": False, "msg": "Failed to pass Cloudflare challenge"}

        # Process request
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
                    return {"ok": False, "msg": f"Non-JSON data: {resp_data}"}

        # If don't need to cache the page, close
        if not page_key and page:
            if req.browser_id not in browser_cache:  # If not shared browser, close
                page.quit()

        return resp_obj

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()

        # 如果需要截图
        if req.snapshot and page:
            os.makedirs('screenshot', exist_ok=True)
            page.save_screenshot(f'screenshot/error_{urlparse(req.url).netloc}.png')
            with open(f'screenshot/error_{urlparse(req.url).netloc}.html', "w", encoding="utf-8") as f:
                f.write(page.html)

        # 如果页面被缓存，从缓存中清除
        if page_key and page_key in page_cache:
            del page_cache[page_key]

        # 关闭页面
        if page:
            # 如果不是共享浏览器，则关闭
            if req.browser_id not in browser_cache:
                page.quit()
            # 如果是共享浏览器但出错了，也应该关闭并从缓存中移除
            elif req.browser_id in browser_cache:
                page.quit()
                del browser_cache[req.browser_id]

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
