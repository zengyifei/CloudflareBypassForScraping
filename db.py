"""
配置加载：仅从 YAML 读取服务配置，API 配置由 models.website_configs 从本地 JSON 文件加载。
不再使用 MySQL / Redis。
"""
import os
import yaml


def load_config(config_path=None):
    """
    从 YAML 配置文件加载（如 server.port 等）。
    config_path 为空则不使用配置文件。
    返回配置字典，失败返回 None。
    """
    try:
        if not config_path or not os.path.isfile(config_path):
            return None
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"加载配置文件失败: {config_path}, {e}")
        return None


def init_api_config_from_file(config_path=None):
    """
    启动时从本地 JSON 文件加载 API 配置到 website_configs。
    文件路径优先级：环境变量 API_CONFIG_FILE > 默认 ./data/api_configs.json。
    若提供了 config_path（YAML），可从其中读取 api_config_file 键覆盖路径（可选）。
    返回是否加载成功。
    """
    from models import website_configs

    filepath = os.getenv("API_CONFIG_FILE")
    if not filepath and config_path:
        config = load_config(config_path)
        if config and isinstance(config.get("api_config_file"), str):
            filepath = config["api_config_file"]
    if not filepath:
        filepath = os.path.join(os.getcwd(), "data", "api_configs.json")

    ok = website_configs.load_from_file(filepath)
    if ok:
        n = len(website_configs.get_all_list())
        print(f"已从本地文件加载 {n} 条 API 配置: {filepath}")
    return ok
