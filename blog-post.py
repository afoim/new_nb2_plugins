import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Dict, Any

from fastapi import FastAPI, Request
from nonebot import get_driver, get_bot
from nonebot.adapters.onebot.v11 import Bot
from nonebot.plugin import PluginMetadata
from nonebot.log import logger
import uvicorn

# 插件元数据
__plugin_meta__ = PluginMetadata(
    name="博客文章推送",
    description="接收GitHub Webhook并推送博客文章更新到QQ群",
    usage="自动接收Webhook推送",
    homepage=None,
    type="application",
    config=None,
    supported_adapters=None,
)

# 硬编码的群组配置（完全按照原Koishi插件逻辑）
TARGET_GROUPS = [
    "1051035890",  # 替换为实际的QQ群号
    "1051639698",  # 可以添加多个群号
    "811724851"
]

# 调试模式开关（完全按照原Koishi插件逻辑）
DEBUG_MODE = True

# 配置日志
blog_logger = logging.getLogger('blog_post')
blog_logger.setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)

# 获取驱动器
driver = get_driver()

# 创建独立的FastAPI应用（按照Koishi插件逻辑）
app = FastAPI(title="Blog Post Webhook Server")

# 完全按照原Koishi插件的端口配置
WEBHOOK_PORT = 15667  # 原Koishi插件使用的端口


def log_webhook_data(data: Dict[str, Any]) -> None:
    """记录Webhook数据到日志文件（完全按照原Koishi插件逻辑）"""
    if DEBUG_MODE:
        # 确保log.txt文件存在
        log_path = os.path.join(os.path.dirname(__file__), '..', '..', 'log.txt')
        if not os.path.exists(log_path):
            with open(log_path, 'w', encoding='utf-8') as f:
                f.write('')
        
        # 写入日志文件
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] {json.dumps(data, indent=2, ensure_ascii=False)}\n\n"
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(log_entry)


# 原Koishi插件的函数已经直接集成到webhook_handler中


async def send_to_groups(message: str) -> None:
    """发送消息到配置的QQ群"""
    if not message:
        return
    
    try:
        bot: Bot = get_bot()
        blog_logger.info(f"准备发送消息到 {len(TARGET_GROUPS)} 个群组")
        
        for group_id in TARGET_GROUPS:
            try:
                await bot.send_group_msg(group_id=int(group_id), message=message)
                blog_logger.info(f"成功发送消息到群组 {group_id}")
            except Exception as e:
                blog_logger.error(f"发送消息到群组 {group_id} 失败: {str(e)}")
                
    except Exception as e:
        blog_logger.error(f"获取Bot实例失败: {str(e)}")


@app.post("/")
async def webhook_handler(request: Request):
    """处理GitHub Webhook请求（完全按照原Koishi插件逻辑）"""
    try:
        # 获取请求数据
        body = await request.body()
        content_type = request.headers.get('content-type', '')
        
        if 'application/json' in content_type:
            payload = json.loads(body)
        elif 'application/x-www-form-urlencoded' in content_type:
            form_data = await request.form()
            payload_str = form_data.get('payload')
            if payload_str:
                payload = json.loads(payload_str)
            else:
                payload = dict(form_data)
        else:
            payload = json.loads(body)
        
        # 记录调试信息（完全按照原Koishi插件逻辑）
        log_webhook_data(payload)
        blog_logger.info(f"收到 Webhook: {payload if DEBUG_MODE else '(调试模式未开启)'}")
        
        # 返回状态（完全按照原Koishi插件逻辑）
        response_data = {"status": "ok"}
        
        # 处理GitHub Ping事件（完全按照原Koishi插件逻辑）
        if payload.get('zen'):
            blog_logger.info(f"收到 GitHub Ping: {payload['zen']}")
            return response_data
        
        # 处理提交事件（完全按照原Koishi插件逻辑）
        if payload.get('ref') and payload.get('commits'):
            # 过滤以 'posts:' 开头的提交
            posts_commits = [commit for commit in payload['commits'] 
                           if commit['message'].lower().startswith('posts:')]
            
            # 收集所有文章的URL和摘要
            all_posts = []
            summaries = set()
            
            for commit in posts_commits:
                # 获取新增和修改的文件
                commit_posts = []
                for file in commit.get('added', []) + commit.get('modified', []):
                    if file.startswith('src/content/posts/'):
                        filename = file.replace('src/content/posts/', '').replace('.md', '')
                        commit_posts.append(f"https://afo.im/posts/{filename}/")
                
                if commit_posts:
                    all_posts.extend(commit_posts)
                    # 提取摘要（去掉 'posts:' 前缀）
                    summary = commit['message'].replace('posts:', '', 1).strip()
                    if summary:
                        summaries.add(summary)
            
            if all_posts:
                # 构建消息（完全按照原Koishi插件逻辑）
                msg_parts = [
                    '二叉树树的博客有文章更新辣！',
                    f'摘要：{"；".join(summaries)}',
                    '链接：'
                ]
                msg_parts.extend(all_posts)
                message = '\n'.join(msg_parts)
                
                blog_logger.info(f"检测到 {len(all_posts)} 篇文章更新，准备推送")
                
                # 延迟2分钟后发送消息（完全按照原Koishi插件逻辑）
                async def delayed_send():
                    await asyncio.sleep(2 * 60)  # 2分钟延迟
                    await send_to_groups(message)
                
                # 创建后台任务
                asyncio.create_task(delayed_send())
                
                blog_logger.info(f"预定2分钟后发送消息到：onebot: {len(TARGET_GROUPS)}个群组")
        
        return response_data
        
    except Exception as e:
        blog_logger.error(f"Webhook 处理异常: {str(e)}")
        return {"status": "error", "message": str(e)}


# 独立HTTP服务器实例
webhook_server = None


async def start_webhook_server():
    """启动独立的Webhook服务器（按照Koishi插件逻辑）"""
    global webhook_server
    try:
        config = uvicorn.Config(
            app=app,
            host="0.0.0.0",
            port=WEBHOOK_PORT,
            log_level="info" if DEBUG_MODE else "warning"
        )
        webhook_server = uvicorn.Server(config)
        blog_logger.info(f"启动独立Webhook服务器，端口: {WEBHOOK_PORT}")
        await webhook_server.serve()
    except Exception as e:
        blog_logger.error(f"Webhook服务器启动失败: {str(e)}")


@driver.on_startup
async def startup():
    """插件启动时的初始化"""
    blog_logger.info("博客推送插件已启动")
    blog_logger.info(f"Webhook 服务器已启动，监听 http://0.0.0.0:{WEBHOOK_PORT}")
    blog_logger.info(f"目标群组: {', '.join(TARGET_GROUPS)}")
    blog_logger.info(f"调试模式: {'开启' if DEBUG_MODE else '关闭'}")
    
    # 启动独立的Webhook服务器（按照Koishi插件逻辑）
    asyncio.create_task(start_webhook_server())


@driver.on_shutdown
async def shutdown():
    """插件关闭时的清理"""
    global webhook_server
    if webhook_server:
        blog_logger.info("正在关闭Webhook服务器...")
        webhook_server.should_exit = True
    blog_logger.info("博客推送插件已关闭")