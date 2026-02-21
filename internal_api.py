import os
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBasicCredentials, HTTPBasic
from typing import List, Dict, Any, Optional
import traceback
import secrets
from models import website_configs, generate_random_api_name
import json
import yaml
import hashlib
# 导入共享模块
from shared import page_cache, cleanup_page, get_page_key
from pydantic import BaseModel

# 定义API路由器 - 移到顶部避免循环导入问题
router = APIRouter(prefix="/internal/api", tags=["internal_api"])

# 基本认证
security = HTTPBasic()

# 验证凭据


def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = "yifei"
    correct_password = "Cd32d5e86e"
    is_correct_username = secrets.compare_digest(credentials.username, correct_username)
    is_correct_password = secrets.compare_digest(credentials.password, correct_password)

    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


# 必填字段列表 - 移除api_name，将由系统自动生成
REQUIRED_FIELDS = ['user_name', 'source_website', 'hijack_js_url', 'breakpoint_line_num', 'breakpoint_col_num', 'target_func']


def validate_required_fields(config: Dict[str, Any]):
    """验证必填字段"""
    missing_fields = []
    for field in REQUIRED_FIELDS:
        if field not in config or config[field] is None or (isinstance(config[field], str) and config[field].strip() == ''):
            missing_fields.append(field)

    if missing_fields:
        raise ValueError(f"缺少必填字段: {', '.join(missing_fields)}")


@router.get("/configs", response_model=List[dict])
async def get_configs(username: str = Depends(verify_credentials)):
    """获取所有配置的接口（从本地文件加载的内存缓存中读取）"""
    try:
        config_list = []
        for c in website_configs.get_all_list():
            config_dict = {
                'id': c.get('id'),
                'user_name': c.get('user_name'),
                'source_website': c.get('source_website'),
                'hijack_js_url': c.get('hijack_js_url'),
                'breakpoint_line_num': c.get('breakpoint_line_num'),
                'breakpoint_col_num': c.get('breakpoint_col_num'),
                'target_func': c.get('target_func'),
                'description': c.get('description'),
                'api_name': c.get('api_name'),
                'params_example': c.get('params_example'),
                'override_funcs': c.get('override_funcs'),
                'trigger_js': c.get('trigger_js'),
                'cookies': c.get('cookies'),
            }
            page_key = get_page_key(c.get('source_website', ''))
            config_dict['is_page_open'] = page_key in page_cache
            config_dict['page_key'] = page_key
            config_list.append(config_dict)
        return config_list
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"获取配置失败: {str(e)}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"获取配置失败: {str(e)}")


@router.post("/configs", response_model=dict)
async def create_config(config: Dict[str, Any], username: str = Depends(verify_credentials)):
    """新增 API 配置，写入内存并持久化到本地文件"""
    try:
        validate_required_fields(config)

        # 自动生成不重复的 api_name
        while True:
            api_name = generate_random_api_name()
            if not website_configs.get_by_api_name(api_name):
                break

        cache_data = {
            'user_name': config['user_name'].strip(),
            'source_website': config['source_website'].strip(),
            'hijack_js_url': config['hijack_js_url'].strip(),
            'breakpoint_line_num': int(config['breakpoint_line_num']),
            'breakpoint_col_num': int(config['breakpoint_col_num']),
            'target_func': config['target_func'].strip(),
            'description': (config.get('description') or '').strip() or None,
            'params_example': config.get('params_example'),
            'override_funcs': config.get('override_funcs', 'all'),
            'trigger_js': config.get('trigger_js'),
            'cookies': config.get('cookies'),
        }
        website_configs.set(api_name, cache_data)
        new_config = website_configs.get_by_api_name(api_name)
        if not website_configs.save_to_file():
            raise HTTPException(status_code=500, detail="配置已创建但写入本地文件失败")

        return {"id": new_config["id"], "api_name": api_name, "message": "配置创建成功"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"创建配置失败: {str(e)}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"创建配置失败: {str(e)}")


@router.put("/configs/{config_id}", response_model=dict)
async def update_config(config_id: int, config: Dict[str, Any], username: str = Depends(verify_credentials)):
    """更新指定 id 的 API 配置，并写回本地文件"""
    try:
        existing = website_configs.get_by_id(config_id)
        if not existing:
            raise HTTPException(status_code=404, detail="配置不存在")

        validate_required_fields(config)
        if "api_name" in config:
            del config["api_name"]

        api_name = existing["api_name"]
        cache_data = {
            "id": config_id,
            "api_name": api_name,
            "user_name": config["user_name"].strip(),
            "source_website": config["source_website"].strip(),
            "hijack_js_url": config["hijack_js_url"].strip(),
            "breakpoint_line_num": int(config["breakpoint_line_num"]),
            "breakpoint_col_num": int(config["breakpoint_col_num"]),
            "target_func": config["target_func"].strip(),
            "description": (config.get("description") or "").strip() or None,
            "params_example": config.get("params_example"),
            "override_funcs": config.get("override_funcs", existing.get("override_funcs", "all")),
            "trigger_js": config.get("trigger_js"),
            "cookies": config.get("cookies"),
        }
        website_configs.set(api_name, cache_data)
        if not website_configs.save_to_file():
            raise HTTPException(status_code=500, detail="配置已更新但写入本地文件失败")
        return {"id": config_id, "api_name": api_name, "message": "配置更新成功"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"更新配置失败: {str(e)}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"更新配置失败: {str(e)}")


@router.delete("/configs/{config_id}", response_model=dict)
async def delete_config(config_id: int, username: str = Depends(verify_credentials)):
    """删除指定 id 的 API 配置，并从本地文件持久化中移除"""
    try:
        existing = website_configs.get_by_id(config_id)
        if not existing:
            raise HTTPException(status_code=404, detail="配置不存在")
        api_name = existing["api_name"]
        website_configs.delete(api_name)
        if not website_configs.save_to_file():
            raise HTTPException(status_code=500, detail="配置已从内存删除但写入本地文件失败")
        return {"id": config_id, "message": "配置删除成功"}
    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"删除配置失败: {str(e)}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"删除配置失败: {str(e)}")


@router.get("/page_status")
async def get_page_status(username: str = Depends(verify_credentials)):
    """获取每个API对应的页面状态"""
    # 直接从内存缓存获取所有配置
    configs = website_configs.get_all()

    # 构造结果字典
    result = {}
    for api_name, config in configs.items():
        # 检查页面是否在缓存中
        page_key = get_page_key(config['source_website'])
        is_page_open = page_key in page_cache
        result[api_name] = {
            "is_page_open": is_page_open,
            "page_key": page_key if is_page_open else None
        }

    return result


@router.post("/close_page/{api_name}")
async def close_page(api_name: str, username: str = Depends(verify_credentials)):
    """关闭指定API名称对应的页面"""
    config = website_configs.get_by_api_name(api_name)
    if not config:
        return {"success": False, "message": "找不到对应的API配置"}

    try:
        browser_id = "default"
        if page_key in page_cache:
            page = page_cache[page_key]
            cleanup_page(page, page_key, browser_id)
            return {"success": True, "message": f"成功关闭 {api_name} 的页面"}
        return {"success": False, "message": "页面未打开或已关闭"}
    except Exception as e:
        error_trace = traceback.format_exc()
        return {"success": False, "message": f"关闭页面时出错: {str(e)}", "error": error_trace}


# 定义执行JS的请求模型
class ExecuteJsRequest(BaseModel):
    javascript: str
    is_async: bool = False


@router.post("/execute_js/{api_name}")
async def execute_js(api_name: str, request: ExecuteJsRequest, username: str = Depends(verify_credentials)):
    """根据API名称在页面中执行JavaScript代码"""
    try:
        # 直接从website_configs中获取配置
        config = website_configs.get_by_api_name(api_name)

        if not config:
            return {"success": False, "message": "找不到对应的API配置"}

        page_key = get_page_key(config['source_website'])
        if page_key not in page_cache:
            return {"success": False, "message": "页面未打开，请先调用API"}

        # 获取页面对象
        page = page_cache[page_key]

        # 执行JavaScript代码
        try:
            if request.is_async:
                # 执行异步JavaScript
                result = page.run_js(f"(async () => {{ {request.javascript} }})()", as_expr=True)
            else:
                # 执行同步JavaScript
                result = page.run_js(request.javascript, as_expr=True)
            return {"success": True, "result": result}
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            return {"success": False, "message": f"执行JavaScript时出错: {str(e)}", "error": error_trace}
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        return {"success": False, "message": f"处理请求时出错: {str(e)}", "error": error_trace}


@router.get("/snapshot")
async def take_snapshot(api_name: str, username: str = Depends(verify_credentials)):
    """对指定 API 对应的已打开标签页截一张图，保存到项目 snapshots 目录并返回访问 URL"""
    config = website_configs.get_by_api_name(api_name)
    if not config:
        raise HTTPException(status_code=404, detail="找不到对应的 API 配置")
    page_key = get_page_key(config["source_website"])
    if page_key not in page_cache:
        raise HTTPException(status_code=404, detail="该页面未打开或已关闭，请先调用接口打开页面")
    page = page_cache[page_key]
    # 使用项目下的 snapshots 目录（与 server 中 SNAPSHOTS_DIR 一致）
    snapshots_dir = os.path.join(os.getcwd(), "snapshots")
    os.makedirs(snapshots_dir, exist_ok=True)
    filename = f"{api_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    filepath = os.path.join(snapshots_dir, filename)
    try:
        # ChromiumTab 使用 get_screenshot(path=...)，无 save_screenshot
        page.get_screenshot(path=filepath)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"截图失败: {str(e)}")
    return {"url": f"/snapshots/{filename}"}
