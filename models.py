from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, UniqueConstraint, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from typing import Optional
import random
import string

Base = declarative_base()


# 生成随机api_name
def generate_random_api_name(length=10):
    """生成10位由小写字母和数字随机组合的api_name"""
    characters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


class AntiJsConfig(Base):
    __tablename__ = 'antijs_configs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    create_time = Column(DateTime, default=datetime.utcnow)
    update_time = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    api_name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    user_name = Column(String(255), nullable=False)
    source_website = Column(String(255), nullable=False)
    hijack_js_url = Column(Text, nullable=False)
    breakpoint_line_num = Column(Integer, nullable=False)
    breakpoint_col_num = Column(Integer, nullable=False)
    target_func = Column(String(255), nullable=False)
    params_len = Column(Integer, nullable=True)
    params_example = Column(Text, nullable=True)
    expire_time = Column(DateTime, nullable=True)
    max_calls = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    override_funcs = Column(String(255), default='setTimeout,setInterval', nullable=True)
    trigger_js = Column(Text, nullable=True)
    cookies = Column(Text, nullable=True)

    def __repr__(self):
        return f"<AntiJsConfig(id='{self.id}', user_name='{self.user_name}', api_name='{self.api_name}')>"

# 内存缓存


class WebsiteConfigs:
    def __init__(self):
        self.configs = {}  # 直接使用api_name作为键

    def set(self, api_name: str, config: dict):
        # 确保 expire_time 是字符串或 None
        if isinstance(config.get('expire_time'), datetime):
            config['expire_time'] = config['expire_time'].strftime('%Y-%m-%d %H:%M:%S')

        # 直接以api_name为键保存配置
        self.configs[api_name] = config

    def get_by_api_name(self, api_name: str) -> Optional[dict]:
        """通过api_name获取配置"""
        return self.configs.get(api_name)

    def get_all(self) -> dict:
        return self.configs

    def delete(self, api_name: str):
        """删除指定api_name的配置"""
        if api_name in self.configs:
            self.configs.pop(api_name)

    def sanitize_configs(self):
        """确保所有配置的expire_time字段格式一致"""
        for config in self.configs.values():
            if 'expire_time' in config:
                if isinstance(config['expire_time'], datetime):
                    config['expire_time'] = config['expire_time'].strftime('%Y-%m-%d %H:%M:%S')
                elif config['expire_time'] is not None and not isinstance(config['expire_time'], str):
                    config['expire_time'] = None

    def clear(self):
        """清空所有配置"""
        self.configs = {}


# 全局配置缓存
website_configs = WebsiteConfigs()


def init_db(db_url):
    engine = create_engine(
        db_url,
        pool_recycle=1800,  # 30分钟内回收连接，避免MySQL超时断开
        pool_pre_ping=True   # 在使用连接前先ping测试，自动处理失效连接
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()
