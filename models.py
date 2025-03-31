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


class JsReverseConfig(Base):
    __tablename__ = 'js_reverse_configs'

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

    def __repr__(self):
        return f"<JsReverseConfig(id='{self.id}', user_name='{self.user_name}', api_name='{self.api_name}')>"

# 内存缓存


class WebsiteConfigs:
    def __init__(self):
        self.configs = {}
        self.api_name_map = {}  # 用于存储api_name到id的映射

    def set(self, config_id: int, config: dict):
        # 确保 expire_time 是字符串或 None
        if isinstance(config.get('expire_time'), datetime):
            config['expire_time'] = config['expire_time'].strftime('%Y-%m-%d %H:%M:%S')

        # 保存配置，同时更新api_name到id的映射
        self.configs[config_id] = config
        if 'api_name' in config and config['api_name']:
            self.api_name_map[config['api_name']] = config_id

    def get(self, config_id: int) -> Optional[dict]:
        return self.configs.get(config_id)

    def get_by_api_name(self, api_name: str) -> Optional[dict]:
        """通过api_name获取配置"""
        config_id = self.api_name_map.get(api_name)
        if config_id is not None:
            return self.configs.get(config_id)
        return None

    def get_all(self) -> dict:
        return self.configs

    def delete(self, config_id: int):
        # 删除配置时，同时删除api_name映射
        config = self.configs.get(config_id)
        if config and 'api_name' in config:
            self.api_name_map.pop(config['api_name'], None)
        self.configs.pop(config_id, None)

    def sanitize_configs(self):
        """确保所有配置的expire_time字段格式一致"""
        self.api_name_map = {}  # 重置api_name映射
        for config_id, config in self.configs.items():
            if 'expire_time' in config:
                if isinstance(config['expire_time'], datetime):
                    config['expire_time'] = config['expire_time'].strftime('%Y-%m-%d %H:%M:%S')
                elif config['expire_time'] is not None and not isinstance(config['expire_time'], str):
                    config['expire_time'] = None

            # 更新api_name映射
            if 'api_name' in config and config['api_name']:
                self.api_name_map[config['api_name']] = config_id

    def clear(self):
        """清空所有配置"""
        self.configs = {}
        self.api_name_map = {}


# 全局配置缓存
website_configs = WebsiteConfigs()


def init_db(db_url):
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()
