import asyncio
import json
import math
from typing import List, Dict, Any, Optional
from xml.etree import ElementTree as ET

import httpx
from nonebot import on_command
from nonebot.adapters import Message
from nonebot.adapters.onebot.v11 import MessageEvent
from nonebot.matcher import Matcher
from nonebot.params import CommandArg
from nonebot.log import logger

# 插件元数据
__plugin_name__ = "博客文章查询"
__plugin_description__ = "查看afo.im博客文章列表，支持分页、搜索和详情查看"
__plugin_usage__ = """
使用方法：
/blog [页码] - 查看博客文章列表
/blog -i <序号> - 查看指定序号的文章详情
/blog -s <关键词> - 按标题或URL搜索文章

示例：
/blog 2 - 查看第2页文章
/blog -i 3 - 查看第3篇文章详情
/blog -s "Python" - 搜索包含Python的文章
"""

# 配置常量
RSS_URL = "https://www.afo.im/rss.xml"
PAGE_SIZE = 50
TIMEOUT = 10.0  # 10秒超时

# 博客项数据结构
class BlogItem:
    def __init__(self, title: str, link: str, description: str, pub_date: str):
        self.title = title
        self.link = link
        self.description = description
        self.pub_date = pub_date

# 注册命令 - 严格匹配，避免误触发
cmd_blog = on_command("blog", aliases={"博客", "文章"}, priority=10, block=True, force_whitespace=True)

async def fetch_blogs() -> List[BlogItem]:
    """获取博客文章列表"""
    try:
        logger.info(f"请求RSS源: {RSS_URL}")
        
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.get(
                RSS_URL,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
            )
            response.raise_for_status()
            xml_content = response.text
        
        logger.debug(f"RSS原始内容: {xml_content[:200]}{'...（已截断）' if len(xml_content) > 200 else ''}")
        
        # 解析XML
        root = ET.fromstring(xml_content)
        
        # 查找所有item元素
        items = root.findall('.//item')
        
        blogs = []
        for item in items:
            title_elem = item.find('title')
            link_elem = item.find('link')
            description_elem = item.find('description')
            pub_date_elem = item.find('pubDate')
            
            title = title_elem.text if title_elem is not None else ""
            link = link_elem.text if link_elem is not None else ""
            description = description_elem.text if description_elem is not None else ""
            pub_date = pub_date_elem.text if pub_date_elem is not None else ""
            
            blogs.append(BlogItem(title, link, description, pub_date))
        
        logger.info(f"成功获取 {len(blogs)} 篇博客")
        return blogs
        
    except httpx.TimeoutException:
        logger.error("获取RSS源超时")
        raise ValueError("请求超时，请稍后重试")
    except httpx.HTTPError as e:
        logger.error(f"HTTP请求失败: {e}")
        raise ValueError("获取博客列表失败，请稍后重试")
    except ET.ParseError as e:
        logger.error(f"XML解析失败: {e}")
        raise ValueError("RSS源格式错误，请稍后重试")
    except Exception as e:
        logger.error(f"获取RSS源失败: {e}")
        raise ValueError("获取博客列表失败，请稍后重试")

def parse_command_args(args_text: str) -> tuple[Optional[int], Optional[int], Optional[str]]:
    """解析命令参数
    
    Returns:
        tuple: (page, index, search_keyword)
    """
    args = args_text.strip().split()
    page = None
    index = None
    search_keyword = None
    
    i = 0
    while i < len(args):
        arg = args[i]
        
        if arg == "-i" and i + 1 < len(args):
            try:
                index = int(args[i + 1])
                i += 2
            except ValueError:
                i += 1
        elif arg == "-s" and i + 1 < len(args):
            # 搜索关键词可能包含空格，收集剩余所有参数
            search_keyword = " ".join(args[i + 1:])
            break
        else:
            # 尝试解析为页码
            try:
                if page is None:
                    page = int(arg)
            except ValueError:
                pass
            i += 1
    
    return page, index, search_keyword

@cmd_blog.handle()
async def handle_blog(matcher: Matcher, event: MessageEvent, args: Message = CommandArg()):
    """处理博客查询命令"""
    
    args_text = args.extract_plain_text().strip()
    page, index, search_keyword = parse_command_args(args_text)
    
    # 默认页码为1
    if page is None and index is None and search_keyword is None:
        page = 1
    
    try:
        logger.info(f"/blog 命令被调用，页码: {page}, 序号: {index}, 搜索: {search_keyword}")
        blogs = await fetch_blogs()
        
        if not blogs:
            logger.warning("未获取到任何文章")
            await matcher.finish("未获取到任何文章。")
        
        # 搜索功能
        if search_keyword:
            keyword = search_keyword.lower()
            search_results = [
                blog for blog in blogs 
                if keyword in blog.title.lower() or keyword in blog.link.lower()
            ]
            
            if not search_results:
                logger.info(f'搜索关键词 "{search_keyword}" 未找到匹配文章')
                await matcher.finish(f'未找到包含 "{search_keyword}" 的文章。')
            
            msg = "afo.im 博文搜索结果：\n\n"
            for i, item in enumerate(search_results):
                msg += f"{i + 1}. {item.title}\n{item.link}\n"
                if item.description:
                    msg += f"{item.description}\n"
                msg += "\n"
            
            logger.info(f'搜索 "{search_keyword}" 找到 {len(search_results)} 篇文章')
            await matcher.finish(msg.strip())
        
        # 查看文章详情
        if index is not None:
            if index < 1 or index > len(blogs):
                logger.warning(f"用户输入序号超出范围: {index}")
                await matcher.finish(f"请输入 1~{len(blogs)} 之间的序号。")
            
            item = blogs[index - 1]
            msg = f"文章标题：{item.title}\n文章链接：{item.link}"
            logger.info(f"发送第{index}篇文章详情：{item.title}")
            await matcher.finish(msg)
        
        # 分页显示文章列表
        if page is not None:
            total_pages = math.ceil(len(blogs) / PAGE_SIZE)
            if page < 1 or page > total_pages:
                await matcher.finish(f"请输入 1~{total_pages} 之间的页码。")
            
            # 获取当前页的文章
            start = (page - 1) * PAGE_SIZE
            end = start + PAGE_SIZE
            current_page_blogs = blogs[start:end]
            
            # 构建消息
            msg = f"博客：https://afo.im\n博客文章 (第 {page}/{total_pages} 页)\n\n"
            for i, item in enumerate(current_page_blogs):
                index_num = start + i + 1
                msg += f"{index_num}. {item.title}\n"
            
            msg += "\n发送 /blog 页码 可查看更多文章，如 /blog 2"
            msg += "\n发送 /blog -i 序号 可查看文章详情，如 /blog -i 3"
            msg += '\n发送 /blog -s 关键词 可搜索文章，如 /blog -s "标题关键词"'
            
            logger.info(f"发送第{page}页博客列表")
            await matcher.finish(msg.strip())
    
    except ValueError as e:
        await matcher.finish(str(e))
    except Exception as e:
        logger.error(f"处理命令时发生错误: {e}")
        return