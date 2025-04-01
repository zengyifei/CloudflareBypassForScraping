from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBasicCredentials, HTTPBasic
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import traceback
import secrets
from models import JsReverseConfig, website_configs, generate_random_api_name
from db import get_db_session, get_redis_client, redis_prefix
import json
import yaml

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


router = APIRouter(prefix="/internal/api", tags=["internal_api"])

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


def validate_expire_time(expire_time_str: str) -> datetime:
    """验证过期时间格式"""
    try:
        expire_time = datetime.strptime(expire_time_str, '%Y-%m-%d %H:%M:%S')
        return expire_time
    except ValueError as e:
        if "does not match format" in str(e):
            raise ValueError("时间格式错误，正确格式为: YYYY-MM-DD HH:MM:SS")
        raise e


@router.get("/configs", response_model=List[dict])
async def get_configs(username: str = Depends(verify_credentials)):
    try:
        db_session = get_db_session()
        redis_client = get_redis_client()

        if db_session:
            try:
                configs = db_session.query(JsReverseConfig).all()
                config_list = []

                for c in configs:
                    config_dict = {
                        'id': c.id,
                        'user_name': c.user_name,
                        'source_website': c.source_website,
                        'hijack_js_url': c.hijack_js_url,
                        'breakpoint_line_num': c.breakpoint_line_num,
                        'breakpoint_col_num': c.breakpoint_col_num,
                        'target_func': c.target_func,
                        'expire_time': c.expire_time.strftime('%Y-%m-%d %H:%M:%S') if c.expire_time else None,
                        'max_calls': c.max_calls,
                        'is_active': c.is_active,
                        'params_len': c.params_len,
                        'description': c.description,
                        'api_name': c.api_name,
                        'params_example': c.params_example,
                        'override_funcs': c.override_funcs,
                        'trigger_js': c.trigger_js,
                        'cookies': c.cookies,
                    }

                    # 如果设置了最大调用次数且Redis可用，获取调用次数信息
                    if c.max_calls is not None and redis_client:
                        redis_key = f"{redis_prefix}call_count:{c.api_name}"
                        current_count = redis_client.get(redis_key)
                        current_count = int(current_count) if current_count else 0
                        config_dict['call_count'] = current_count
                        config_dict['call_percentage'] = round(current_count / c.max_calls * 100, 2) if c.max_calls > 0 else 0

                    config_list.append(config_dict)

                return config_list
            except Exception as e:
                error_trace = traceback.format_exc()
                print(f"数据库查询失败: {str(e)}\n{error_trace}")
                # 如果数据库查询失败，返回内存缓存
                cache_configs = list(website_configs.get_all().values())
                print(f"返回内存缓存: {cache_configs}")
                return cache_configs

        # 如果数据库连接不可用，返回内存缓存
        cache_configs = list(website_configs.get_all().values())
        print(f"数据库连接不可用，返回内存缓存: {cache_configs}")
        return cache_configs
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"获取配置失败: {str(e)}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"获取配置失败: {str(e)}")


@router.post("/configs", response_model=dict)
async def create_config(config: Dict[str, Any], username: str = Depends(verify_credentials)):
    try:
        # 验证必填字段
        validate_required_fields(config)

        # 处理过期时间
        expire_time = None
        if 'expire_time' in config and config['expire_time']:
            expire_time = validate_expire_time(config['expire_time'])

        # 处理最大调用次数
        max_calls = None
        if 'max_calls' in config and config['max_calls']:
            try:
                max_calls = int(config['max_calls'])
                if max_calls <= 0:
                    raise ValueError("最大调用次数必须大于0")
            except (ValueError, TypeError):
                raise ValueError("最大调用次数必须是有效的整数")

        # 处理参数长度
        params_len = None
        if 'params_len' in config and config['params_len']:
            try:
                params_len = int(config['params_len'])
                if params_len < 0:
                    raise ValueError("参数长度不能为负数")
            except (ValueError, TypeError):
                raise ValueError("参数长度必须是有效的整数")

        # 检查数据库连接
        db_session = get_db_session()
        if not db_session:
            raise HTTPException(status_code=500, detail="数据库连接不可用")

        # 自动生成 api_name
        while True:
            api_name = generate_random_api_name()
            # 检查生成的api_name是否已存在
            existing = db_session.query(JsReverseConfig).filter(JsReverseConfig.api_name == api_name).first()
            if not existing:
                break

        # 创建新配置
        new_config = JsReverseConfig(
            user_name=config['user_name'].strip(),
            source_website=config['source_website'].strip(),
            hijack_js_url=config['hijack_js_url'].strip(),
            breakpoint_line_num=int(config['breakpoint_line_num']),
            breakpoint_col_num=int(config['breakpoint_col_num']),
            target_func=config['target_func'].strip(),
            expire_time=expire_time,
            max_calls=max_calls,
            is_active=config.get('is_active', True),
            params_len=params_len,
            description=config.get('description', '').strip() if config.get('description') else None,
            params_example=config.get('params_example'),
            api_name=api_name,
            override_funcs=config.get('override_funcs', 'all'),
            trigger_js=config.get('trigger_js'),
            cookies=config.get('cookies'),
        )

        # 保存到数据库
        try:
            db_session.add(new_config)
            db_session.commit()

            # 直接更新内存缓存
            if new_config.is_active:
                cache_data = {
                    'id': new_config.id,
                    'user_name': new_config.user_name,
                    'source_website': new_config.source_website,
                    'hijack_js_url': new_config.hijack_js_url,
                    'breakpoint_line_num': new_config.breakpoint_line_num,
                    'breakpoint_col_num': new_config.breakpoint_col_num,
                    'target_func': new_config.target_func,
                    'max_calls': new_config.max_calls,
                    'is_active': new_config.is_active,
                    'params_len': new_config.params_len,
                    'description': new_config.description,
                    'api_name': new_config.api_name,
                    'params_example': new_config.params_example,
                    'expire_time': new_config.expire_time.strftime('%Y-%m-%d %H:%M:%S') if new_config.expire_time else None,
                    'override_funcs': new_config.override_funcs,
                    'trigger_js': new_config.trigger_js,
                    'cookies': new_config.cookies,
                }
                website_configs.set(new_config.id, cache_data)

            # 返回创建的配置ID和api_name
            return {"id": new_config.id, "api_name": new_config.api_name, "message": "配置创建成功"}
        except Exception as e:
            db_session.rollback()
            error_trace = traceback.format_exc()
            print(f"保存到数据库失败: {str(e)}\n{error_trace}")
            raise HTTPException(status_code=500, detail=f"保存到数据库失败: {str(e)}")

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"创建配置失败: {str(e)}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"创建配置失败: {str(e)}")


@router.put("/configs/{config_id}", response_model=dict)
async def update_config(config_id: int, config: Dict[str, Any], username: str = Depends(verify_credentials)):
    try:
        # 检查数据库连接
        db_session = get_db_session()
        if not db_session:
            raise HTTPException(status_code=500, detail="数据库连接不可用")

        # 查询要更新的配置
        existing_config = db_session.query(JsReverseConfig).filter(JsReverseConfig.id == config_id).first()
        if not existing_config:
            raise HTTPException(status_code=404, detail="配置不存在")

        # 验证必填字段
        validate_required_fields(config)

        # 检查是否有 api_name 字段，如果有则忽略
        if 'api_name' in config:
            del config['api_name']  # 移除api_name字段，不允许修改

        # 处理过期时间
        if 'expire_time' in config:
            if config['expire_time']:
                expire_time = validate_expire_time(config['expire_time'])
                existing_config.expire_time = expire_time
            else:
                existing_config.expire_time = None

        # 处理最大调用次数
        if 'max_calls' in config:
            if config['max_calls']:
                try:
                    max_calls = int(config['max_calls'])
                    if max_calls <= 0:
                        raise ValueError("最大调用次数必须大于0")
                    existing_config.max_calls = max_calls
                except (ValueError, TypeError):
                    raise ValueError("最大调用次数必须是有效的整数")
            else:
                existing_config.max_calls = None

        # 处理参数长度
        if 'params_len' in config:
            if config['params_len']:
                try:
                    params_len = int(config['params_len'])
                    if params_len < 0:
                        raise ValueError("参数长度不能为负数")
                    existing_config.params_len = params_len
                except (ValueError, TypeError):
                    raise ValueError("参数长度必须是有效的整数")
            else:
                existing_config.params_len = None

        # 更新其他字段
        existing_config.user_name = config['user_name'].strip()
        existing_config.source_website = config['source_website'].strip()
        existing_config.hijack_js_url = config['hijack_js_url'].strip()
        existing_config.breakpoint_line_num = int(config['breakpoint_line_num'])
        existing_config.breakpoint_col_num = int(config['breakpoint_col_num'])
        existing_config.target_func = config['target_func'].strip()

        # 更新参数示例
        if 'params_example' in config:
            existing_config.params_example = config['params_example']

        # 更新活跃状态
        was_active = existing_config.is_active
        if 'is_active' in config:
            existing_config.is_active = bool(config['is_active'])

        # 更新描述
        if 'description' in config:
            existing_config.description = config['description'].strip() if config['description'] else None

        # 更新 override_funcs
        if 'override_funcs' in config:
            existing_config.override_funcs = config['override_funcs']

        # 更新 trigger_js
        if 'trigger_js' in config:
            existing_config.trigger_js = config['trigger_js']

        # 更新 cookies
        if 'cookies' in config:
            existing_config.cookies = config['cookies']

        # 保存更新
        try:
            db_session.commit()

            # 直接更新内存缓存
            if existing_config.is_active:
                # 如果配置现在是活跃的，更新或添加到缓存
                cache_data = {
                    'id': existing_config.id,
                    'user_name': existing_config.user_name,
                    'source_website': existing_config.source_website,
                    'hijack_js_url': existing_config.hijack_js_url,
                    'breakpoint_line_num': existing_config.breakpoint_line_num,
                    'breakpoint_col_num': existing_config.breakpoint_col_num,
                    'target_func': existing_config.target_func,
                    'max_calls': existing_config.max_calls,
                    'is_active': existing_config.is_active,
                    'params_len': existing_config.params_len,
                    'description': existing_config.description,
                    'api_name': existing_config.api_name,
                    'params_example': existing_config.params_example,
                    'expire_time': existing_config.expire_time.strftime('%Y-%m-%d %H:%M:%S') if existing_config.expire_time else None,
                    'override_funcs': existing_config.override_funcs,
                    'trigger_js': existing_config.trigger_js,
                    'cookies': existing_config.cookies,
                }
                website_configs.set(existing_config.id, cache_data)
            elif was_active:
                # 如果配置之前是活跃的，现在变为非活跃，从缓存中删除
                website_configs.delete(existing_config.id)

            return {"id": config_id, "api_name": existing_config.api_name, "message": "配置更新成功"}
        except Exception as e:
            db_session.rollback()
            error_trace = traceback.format_exc()
            print(f"更新配置失败: {str(e)}\n{error_trace}")
            raise HTTPException(status_code=500, detail=f"更新配置失败: {str(e)}")

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
    try:
        # 检查数据库连接
        db_session = get_db_session()
        if not db_session:
            raise HTTPException(status_code=500, detail="数据库连接不可用")

        # 查询要删除的配置
        config = db_session.query(JsReverseConfig).filter(JsReverseConfig.id == config_id).first()
        if not config:
            raise HTTPException(status_code=404, detail="配置不存在")

        # 从数据库中删除配置
        try:
            db_session.delete(config)
            db_session.commit()

            # 从内存缓存中删除
            website_configs.delete(config_id)

            return {"id": config_id, "message": "配置删除成功"}
        except Exception as e:
            db_session.rollback()
            error_trace = traceback.format_exc()
            print(f"删除配置失败: {str(e)}\n{error_trace}")
            raise HTTPException(status_code=500, detail=f"删除配置失败: {str(e)}")

    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"删除配置失败: {str(e)}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"删除配置失败: {str(e)}")


@router.post("/refresh", response_model=dict)
async def refresh_configs(username: str = Depends(verify_credentials)):
    """手动刷新内存缓存中的配置数据"""
    try:
        # 检查数据库连接
        db_session = get_db_session()
        if not db_session:
            raise HTTPException(status_code=500, detail="数据库连接不可用")

        try:
            # 清空当前缓存
            website_configs.clear()

            # 从数据库加载活跃配置
            configs = db_session.query(JsReverseConfig).filter(JsReverseConfig.is_active == True).all()

            for config in configs:
                config_dict = {
                    'id': config.id,
                    'user_name': config.user_name,
                    'source_website': config.source_website,
                    'hijack_js_url': config.hijack_js_url,
                    'breakpoint_line_num': config.breakpoint_line_num,
                    'breakpoint_col_num': config.breakpoint_col_num,
                    'target_func': config.target_func,
                    'expire_time': config.expire_time.strftime('%Y-%m-%d %H:%M:%S') if config.expire_time else None,
                    'max_calls': config.max_calls,
                    'is_active': config.is_active,
                    'params_len': config.params_len,
                    'description': config.description,
                    'api_name': config.api_name,
                    'params_example': config.params_example,
                    'override_funcs': config.override_funcs,
                    'trigger_js': config.trigger_js,
                    'cookies': config.cookies,
                }
                website_configs.set(config.id, config_dict)

            print(f"成功从数据库刷新 {len(configs)} 条配置到内存缓存")
            return {"message": f"配置刷新成功，共 {len(configs)} 条配置"}
        except Exception as e:
            error_trace = traceback.format_exc()
            print(f"刷新配置失败: {str(e)}\n{error_trace}")
            raise HTTPException(status_code=500, detail=f"刷新配置失败: {str(e)}")

    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"刷新配置失败: {str(e)}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"刷新配置失败: {str(e)}")
