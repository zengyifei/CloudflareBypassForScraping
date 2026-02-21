"""
API 配置模型与本地文件存储。
不再使用 MySQL/Redis，配置持久化到本地 JSON 文件，便于 Docker 挂载与迁移。
"""
import os
import json
import random
import string
from typing import Optional

# 配置存储路径：优先环境变量 API_CONFIG_FILE，默认项目下 data/api_configs.json（便于 Docker 挂载）
def _get_config_file_path() -> str:
    return os.getenv("API_CONFIG_FILE", os.path.join(os.getcwd(), "data", "api_configs.json"))


def generate_random_api_name(length=10):
    """生成10位由小写字母和数字随机组合的 api_name"""
    characters = string.ascii_lowercase + string.digits
    return "".join(random.choice(characters) for _ in range(length))


class WebsiteConfigs:
    """API 配置内存缓存，支持从本地文件加载与保存。"""

    def __init__(self):
        # api_name -> config 字典，供按 api_name 查询
        self.configs = {}
        # 按 id 顺序的配置列表，用于持久化与按 id 操作
        self.configs_list = []
        self.next_id = 1

    def _ensure_data_dir(self, filepath: str):
        """确保文件所在目录存在"""
        d = os.path.dirname(filepath)
        if d:
            os.makedirs(d, exist_ok=True)

    def load_from_file(self, filepath: Optional[str] = None) -> bool:
        """
        从本地 JSON 文件加载配置到内存。
        filepath 为空时使用环境变量或默认路径。
        返回是否加载成功。
        """
        path = filepath or _get_config_file_path()
        self.configs = {}
        self.configs_list = []
        self.next_id = 1
        if not os.path.isfile(path):
            return True
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.next_id = data.get("next_id", 1)
            for c in data.get("configs", []):
                api_name = c.get("api_name")
                if not api_name:
                    continue
                self.configs_list.append(c)
                self.configs[api_name] = c
            return True
        except Exception as e:
            print(f"加载配置文件失败: {path}, {e}")
            return False

    def save_to_file(self, filepath: Optional[str] = None) -> bool:
        """
        将当前内存中的配置写入本地 JSON 文件。
        filepath 为空时使用环境变量或默认路径。
        """
        path = filepath or _get_config_file_path()
        self._ensure_data_dir(path)
        try:
            data = {"next_id": self.next_id, "configs": self.configs_list}
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"保存配置文件失败: {path}, {e}")
            return False

    def set(self, api_name: str, config: dict):
        """新增或更新一条配置（以 api_name 为键）。若为新增且 config 已带 id则保留，并保证 next_id 不与之冲突。"""
        config = dict(config)
        config["api_name"] = api_name
        if api_name in self.configs:
            # 更新：保持原 id，替换列表中对应项
            old = self.configs[api_name]
            config["id"] = old["id"]
            for i, c in enumerate(self.configs_list):
                if c.get("api_name") == api_name:
                    self.configs_list[i] = config
                    break
        else:
            # 新增：若传入的 config 已有 id（如 inject_apis），则保留，并让 next_id 大于所有已有 id
            incoming_id = config.get("id")
            if isinstance(incoming_id, int):
                config["id"] = incoming_id
                if self.next_id <= incoming_id:
                    self.next_id = incoming_id + 1
            else:
                config["id"] = self.next_id
                self.next_id += 1
            self.configs_list.append(config)
        self.configs[api_name] = config

    def get_by_api_name(self, api_name: str) -> Optional[dict]:
        """通过 api_name 获取配置"""
        return self.configs.get(api_name)

    def get_by_id(self, config_id: int) -> Optional[dict]:
        """通过 id 获取配置"""
        for c in self.configs_list:
            if c.get("id") == config_id:
                return c
        return None

    def get_all(self) -> dict:
        """返回 api_name -> config 的字典"""
        return self.configs

    def get_all_list(self) -> list:
        """按 id 顺序返回配置列表（用于接口返回）"""
        return list(self.configs_list)

    def delete(self, api_name: str):
        """删除指定 api_name 的配置"""
        if api_name in self.configs:
            self.configs.pop(api_name)
            self.configs_list[:] = [c for c in self.configs_list if c.get("api_name") != api_name]

    def clear(self):
        """清空所有配置（不重置 next_id，仅内存）"""
        self.configs.clear()
        self.configs_list.clear()


# 全局配置缓存
website_configs = WebsiteConfigs()
