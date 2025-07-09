import asyncio
import re
import subprocess
from nonebot import on_command
from nonebot.adapters.onebot.v11 import MessageEvent
from nonebot.matcher import Matcher
from nonebot.params import CommandArg
from nonebot.adapters.onebot.v11 import Message
from nonebot.plugin import PluginMetadata

__plugin_meta__ = PluginMetadata(
    name="系统信息",
    description="获取系统信息",
    usage="/info - 获取系统信息"
)

cmd_info = on_command("info", aliases={"info"}, priority=5, block=True, force_whitespace=True)

@cmd_info.handle()
async def handle_info(matcher: Matcher, event: MessageEvent, args: Message = CommandArg()):
    """处理系统信息查询命令"""
    
    # 检查是否为严格的info命令（防止info1等触发）
    raw_message = str(event.get_message()).strip()
    if not (raw_message == "info" or raw_message == "/info" or raw_message.startswith("info ") or raw_message.startswith("/info ")):
        return
    
    # 获取用户自定义的前缀内容
    custom_prefix = '博客：https://afo.im'
    
    try:
        # 执行 fastfetch 命令
        process = await asyncio.create_subprocess_exec(
            'fastfetch',
            '--logo', 'none',
            '--pipe',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            # 获取 fastfetch 输出
            fastfetch_output = stdout.decode('utf-8', errors='ignore').strip()
            
            # 过滤ANSI色彩代码和控制字符
            # 移除ANSI转义序列
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            clean_output = ansi_escape.sub('', fastfetch_output)
            
            # 过滤掉底部的色块部分（通常包含大量的特殊字符或重复的符号）
            lines = clean_output.split('\n')
            filtered_lines = []
            
            for line in lines:
                # 跳过包含大量重复字符的行（色块）
                if len(line.strip()) > 0:
                    # 检查是否为色块行：包含大量重复的特殊字符
                    unique_chars = set(line.strip())
                    if len(unique_chars) <= 3 and len(line.strip()) > 10:
                        # 可能是色块，跳过
                        continue
                    # 检查是否包含大量的方块字符或其他装饰字符
                    if any(char in line for char in ['█', '▄', '▀', '■', '□', '●', '○']):
                        continue
                    filtered_lines.append(line)
                else:
                    filtered_lines.append(line)
            
            clean_fastfetch = '\n'.join(filtered_lines).strip()
            
            # 构建最终输出
            response_parts = []
            
            # 如果有自定义前缀内容，添加到开头
            if custom_prefix:
                response_parts.append(custom_prefix)
                response_parts.append("")  # 空行分隔
            
            # 添加过滤后的 fastfetch 输出
            response_parts.append(clean_fastfetch)
            
            # 发送结果
            await matcher.finish('\n'.join(response_parts))
        else:
            # fastfetch 执行失败
            error_msg = stderr.decode('utf-8', errors='ignore').strip()
            await matcher.finish(f"获取系统信息失败：{error_msg}")
            
    except FileNotFoundError:
        await matcher.finish("错误：未找到 fastfetch 命令，请确保已安装 fastfetch")
    except Exception as e:
        # FinishedException 是 nonebot 的正常机制，不需要特殊处理
        if "FinishedException" not in str(type(e)):
            await matcher.finish(f"获取系统信息时发生错误：{str(e)}")