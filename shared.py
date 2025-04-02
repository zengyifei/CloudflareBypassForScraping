"""
共享模块，存放在多个模块之间共享的对象，避免循环导入问题
"""

# 页面和浏览器缓存
page_cache = {}
browser_cache = {}

# 清理页面的函数


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
            # 这里不能导入logger，因为会造成新的循环引用
            print(f"关闭标签页时出错: {str(e)}")
