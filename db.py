from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import yaml
import os
from sqlalchemy.ext.declarative import declarative_base
import json
import traceback
import redis

Base = declarative_base()
db_session = None
redis_client = None
redis_prefix = 'antijs:'

# 从配置文件加载数据库配置


def load_config(config_path=None):
    """从配置文件加载数据库配置

    Args:
        config_path: 配置文件路径，如果不提供则不使用数据库

    Returns:
        dict: 配置字典，如果加载失败则返回None
    """
    try:
        if not config_path:
            print("未提供配置文件路径，将不使用数据库")
            return None
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        print(f"加载配置文件失败: {str(e)}")
        return None


def init_redis(config=None):
    """初始化Redis连接"""
    global redis_client, redis_prefix

    if not config:
        # 默认配置
        host = 'localhost'
        port = 6379
        db = 0
        password = None
    else:
        # 从配置文件读取
        host = config['redis'].get('host', 'localhost')
        port = config['redis'].get('port', 6379)
        db = config['redis'].get('db', 0)
        password = config['redis'].get('password') if config['redis'].get('password') else None
        redis_prefix = config['redis'].get('prefix', 'antijs:')

    try:
        # 创建Redis连接
        redis_client = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=password,
            decode_responses=True  # 自动将响应解码为字符串
        )
        # 测试连接
        redis_client.ping()
        print(f"Redis连接成功: {host}:{port}/{db}")
        return True
    except Exception as e:
        print(f"Redis连接失败: {str(e)}")
        redis_client = None
        return False


def init_database_and_cache(config_path=None):
    """初始化数据库和内存缓存

    Args:
        config_path: 配置文件路径，如果不提供则不使用数据库

    Returns:
        bool: 初始化是否成功
    """
    global db_session
    engine = None

    # 如果没有提供配置文件路径，则不使用数据库
    if not config_path:
        print("未提供配置文件路径，将不使用数据库")
        # 确保内存缓存初始化正确
        try:
            from models import website_configs
            website_configs.sanitize_configs()
        except Exception as e:
            print(f"处理内存缓存失败: {str(e)}")
        return True

    try:
        config = load_config(config_path)
        if not config:
            print("无法加载配置")
            return False

        # 初始化Redis
        init_redis(config)

        # 创建数据库引擎
        db_url = f"mysql+pymysql://{config['mysql']['user']}:{config['mysql']['password']}@{config['mysql']['host']}:{config['mysql']['port']}/{config['mysql']['database']}"
        engine = create_engine(db_url)

        # 创建表
        Base.metadata.create_all(engine)

        # 创建会话
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # 从数据库直接加载数据到内存缓存
        try:
            from models import AntiJsConfig, website_configs

            # 清空当前缓存
            website_configs.clear()

            # 从数据库加载活跃配置
            configs = db_session.query(AntiJsConfig).filter(AntiJsConfig.is_active == True).all()

            for config in configs:
                config_dict = {
                    'id': config.id,
                    'user_name': config.user_name,
                    'source_website': config.source_website,
                    'hijack_js_url': config.hijack_js_url,
                    'breakpoint_line_num': config.breakpoint_line_num,
                    'breakpoint_col_num': config.breakpoint_col_num,
                    'target_func': config.target_func,
                    'expire_time': config.expire_time,
                    'max_calls': config.max_calls,
                    'is_active': config.is_active,
                    'params_len': config.params_len,
                    'api_name': config.api_name,
                    'override_funcs': config.override_funcs,
                    'trigger_js': config.trigger_js,
                    'cookies': config.cookies,
                }
                website_configs.set(config.id, config_dict)

            # 确保所有缓存的配置格式一致
            website_configs.sanitize_configs()
            print(f"成功加载 {len(configs)} 条配置到内存缓存")
        except Exception as e:
            print(f"加载配置到内存缓存失败: {str(e)}")
            return False

        print("数据库初始化成功")
        return True

    except Exception as e:
        print(f"数据库连接失败: {str(e)}")
        # 即使数据库连接失败，也确保内存缓存格式正确
        try:
            from models import website_configs
            website_configs.sanitize_configs()
        except Exception as e_cache:
            print(f"处理内存缓存失败: {str(e_cache)}")
        return False

# 导出数据库会话的getter方法


def get_db_session():
    """获取数据库会话"""
    global db_session
    return db_session


def get_redis_client():
    """获取Redis客户端连接"""
    global redis_client
    return redis_client
