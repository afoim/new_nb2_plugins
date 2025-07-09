import asyncio
import json
import logging
import os
import re
import subprocess
import time
from typing import Optional
from urllib.parse import urlparse

from nonebot import on_command
from nonebot.adapters import Event
from nonebot.matcher import Matcher
from nonebot.plugin import PluginMetadata
from nonebot.params import CommandArg
from nonebot.adapters.onebot.v11 import Message
from nonebot.exception import FinishedException

# 配置HTTP插件专用的logger
logger = logging.getLogger('http_plugin')
logger.setLevel(logging.DEBUG)

# 如果还没有handler，添加一个
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(asctime)s] [HTTP] [%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# Debug模式开关
DEBUG_MODE = False  # 设置为False可关闭详细日志

__plugin_meta__ = PluginMetadata(
    name="HTTP检测",
    description="检测HTTP网站信息，包括状态码、IP、标题、描述等",
    usage="指令：http <URL>",
    homepage=None,
    type="application",
    config=None,
    supported_adapters=None,
)

# 使用更严格的命令匹配，确保http后面必须跟空格
cmd_http = on_command("http", aliases={"HTTP"}, force_whitespace=True)


async def get_ip_from_url(url: str) -> Optional[str]:
    """通过nslookup获取域名对应的IP地址"""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        
        process = await asyncio.create_subprocess_exec(
            'nslookup', domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        
        # 解析nslookup输出
        output = stdout.decode('utf-8', errors='ignore')
        # 查找IP地址模式
        ip_pattern = r'Address: (\d+\.\d+\.\d+\.\d+)'
        matches = re.findall(ip_pattern, output)
        if matches:
            return matches[-1]  # 返回最后一个IP地址
        
        # 备用模式
        ip_pattern2 = r'(\d+\.\d+\.\d+\.\d+)'
        matches2 = re.findall(ip_pattern2, output)
        for ip in matches2:
            if not ip.startswith('127.') and ip != '0.0.0.0':
                return ip
                
        return None
    except Exception:
        return None


async def extract_html_info(html_content: str) -> dict:
    """从HTML内容中提取标题、描述、关键词和图标"""
    info = {
        'title': 'N/A',
        'description': 'N/A',
        'keywords': 'N/A',
        'icon': 'N/A'
    }
    
    try:
        # 提取标题
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
        if title_match:
            info['title'] = title_match.group(1).strip()
        
        # 提取描述
        desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\'>]+)["\']', html_content, re.IGNORECASE)
        if not desc_match:
            desc_match = re.search(r'<meta[^>]*content=["\']([^"\'>]+)["\'][^>]*name=["\']description["\']', html_content, re.IGNORECASE)
        if desc_match:
            info['description'] = desc_match.group(1).strip()
        
        # 提取关键词
        keywords_match = re.search(r'<meta[^>]*name=["\']keywords["\'][^>]*content=["\']([^"\'>]+)["\']', html_content, re.IGNORECASE)
        if not keywords_match:
            keywords_match = re.search(r'<meta[^>]*content=["\']([^"\'>]+)["\'][^>]*name=["\']keywords["\']', html_content, re.IGNORECASE)
        if keywords_match:
            info['keywords'] = keywords_match.group(1).strip()
        
        # 提取图标
        icon_patterns = [
            r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\'>]+)["\']',
            r'<link[^>]*href=["\']([^"\'>]+)["\'][^>]*rel=["\'](?:shortcut )?icon["\']'
        ]
        for pattern in icon_patterns:
            icon_match = re.search(pattern, html_content, re.IGNORECASE)
            if icon_match:
                icon_url = icon_match.group(1).strip()
                if icon_url.startswith('//'):
                    icon_url = 'https:' + icon_url
                elif icon_url.startswith('/'):
                    # 需要拼接域名，这里简化处理
                    pass
                info['icon'] = icon_url
                break
    
    except Exception:
        pass
    
    return info


async def format_cert_date(date_str: str) -> str:
    """格式化证书日期为UTC+8格式"""
    try:
        from datetime import datetime, timedelta
        # 解析GMT时间格式，例如："Jun  8 07:13:16 2025 GMT"
        # 移除GMT后缀
        date_str = date_str.replace(' GMT', '').strip()
        
        # 解析日期
        dt = datetime.strptime(date_str, '%b %d %H:%M:%S %Y')
        
        # 转换为UTC+8
        dt_utc8 = dt + timedelta(hours=8)
        
        # 格式化为YYYY-MM-DD格式
        return dt_utc8.strftime('%Y-%m-%d')
    except Exception:
        return date_str


async def get_connection_timing(url: str) -> dict:
    """获取连接延迟信息"""
    if DEBUG_MODE:
        logger.debug(f"开始获取连接延迟信息: {url}")
    
    timing_info = {
        'dns_lookup': 'N/A',
        'tcp_connect': 'N/A',
        'tls_handshake': 'N/A',
        'server_response': 'N/A',
        'total_time': 'N/A'
    }
    
    try:
        # 使用curl获取详细的时间信息
        cmd = [
            'curl',
            '-o', 'NUL' if os.name == 'nt' else '/dev/null',
            '-s',
            '-w', 'DNS Lookup Time: %{time_namelookup}s\nTCP Connect Time: %{time_connect}s\nTLS Handshake Time: %{time_appconnect}s\nServer Response Time: %{time_starttransfer}s\nTotal Time: %{time_total}s\n',
            '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            url
        ]
        
        if DEBUG_MODE:
            logger.debug(f"执行连接延迟检测命令: {' '.join(cmd)}")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if DEBUG_MODE:
            logger.debug(f"连接延迟检测命令返回码: {process.returncode}")
        
        if process.returncode == 0:
            output = stdout.decode('utf-8', errors='ignore')
            if DEBUG_MODE:
                logger.debug(f"连接延迟检测输出: {output.strip()}")
            
            # 解析时间信息
            for line in output.split('\n'):
                if 'DNS Lookup Time:' in line:
                    time_value = line.split(':')[1].strip().replace('s', '')
                    timing_info['dns_lookup'] = f"{float(time_value)*1000:.0f}ms"
                elif 'TCP Connect Time:' in line:
                    time_value = line.split(':')[1].strip().replace('s', '')
                    timing_info['tcp_connect'] = f"{float(time_value)*1000:.0f}ms"
                elif 'TLS Handshake Time:' in line:
                    time_value = line.split(':')[1].strip().replace('s', '')
                    if float(time_value) > 0:
                        timing_info['tls_handshake'] = f"{float(time_value)*1000:.0f}ms"
                    else:
                        timing_info['tls_handshake'] = '不适用(HTTP)'
                elif 'Server Response Time:' in line:
                    time_value = line.split(':')[1].strip().replace('s', '')
                    timing_info['server_response'] = f"{float(time_value)*1000:.0f}ms"
                elif 'Total Time:' in line:
                    time_value = line.split(':')[1].strip().replace('s', '')
                    timing_info['total_time'] = f"{float(time_value)*1000:.0f}ms"
    
    except Exception as e:
        if DEBUG_MODE:
            logger.error(f"连接延迟检测失败: {str(e)}")
    
    if DEBUG_MODE:
        logger.debug(f"连接延迟信息获取完成: {timing_info}")
    
    return timing_info


async def get_ssl_certificate_info(url: str) -> dict:
    """获取SSL证书信息"""
    cert_info = {
        'valid_from': 'N/A',
        'valid_to': 'N/A',
        'issuer': 'N/A',
        'subject': 'N/A',
        'san_domains': 'N/A'
    }
    
    # 只对HTTPS网站进行证书检测
    if not url.startswith('https://'):
        return cert_info
    
    try:
        # 使用openssl命令获取证书信息
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        
        cmd = [
            'openssl',
            's_client',
            '-connect', f'{hostname}:{port}',
            '-servername', hostname,
            '-showcerts'
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # 发送空输入并关闭stdin
        stdout, stderr = await process.communicate(input=b'')
        
        if process.returncode == 0:
            output = stdout.decode('utf-8', errors='ignore')
            
            # 提取证书部分
            cert_start = output.find('-----BEGIN CERTIFICATE-----')
            cert_end = output.find('-----END CERTIFICATE-----')
            
            if cert_start != -1 and cert_end != -1:
                cert_pem = output[cert_start:cert_end + len('-----END CERTIFICATE-----')]
                
                # 使用openssl x509命令解析证书
                x509_cmd = [
                    'openssl',
                    'x509',
                    '-noout',
                    '-dates',
                    '-issuer',
                    '-subject',
                    '-ext', 'subjectAltName'
                ]
                
                x509_process = await asyncio.create_subprocess_exec(
                    *x509_cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                x509_stdout, _ = await x509_process.communicate(input=cert_pem.encode())
                
                if x509_process.returncode == 0:
                    x509_output = x509_stdout.decode('utf-8', errors='ignore')
                    
                    # 解析证书信息
                    for line in x509_output.split('\n'):
                        if line.startswith('notBefore='):
                            date_str = line.replace('notBefore=', '').strip()
                            cert_info['valid_from'] = await format_cert_date(date_str)
                        elif line.startswith('notAfter='):
                            date_str = line.replace('notAfter=', '').strip()
                            cert_info['valid_to'] = await format_cert_date(date_str)
                        elif line.startswith('issuer='):
                            issuer = line.replace('issuer=', '').strip()
                            # 提取CN部分
                            if 'CN=' in issuer:
                                cn_start = issuer.find('CN=')
                                cn_part = issuer[cn_start + 3:]
                                cn_end = cn_part.find(',')
                                if cn_end != -1:
                                    cert_info['issuer'] = cn_part[:cn_end]
                                else:
                                    cert_info['issuer'] = cn_part
                            else:
                                cert_info['issuer'] = issuer
                        elif line.startswith('subject='):
                            subject = line.replace('subject=', '').strip()
                            # 提取CN部分
                            if 'CN=' in subject:
                                cn_start = subject.find('CN=')
                                cn_part = subject[cn_start + 3:]
                                cn_end = cn_part.find(',')
                                if cn_end != -1:
                                    cert_info['subject'] = cn_part[:cn_end]
                                else:
                                    cert_info['subject'] = cn_part
                            else:
                                cert_info['subject'] = subject
                        elif 'DNS:' in line:
                            # 提取SAN域名
                            dns_names = []
                            parts = line.split(',')
                            for part in parts:
                                if 'DNS:' in part:
                                    dns_name = part.split('DNS:')[1].strip()
                                    dns_names.append(dns_name)
                            if dns_names:
                                cert_info['san_domains'] = ', '.join(dns_names)
    
    except Exception:
        pass
    
    return cert_info


async def detect_tls_versions(url: str) -> dict:
    """使用openssl s_client检测网站支持的TLS协议版本"""
    if DEBUG_MODE:
        logger.debug(f"开始使用openssl s_client检测TLS协议版本: {url}")
    
    versions = {
        'tls1.0': False,
        'tls1.1': False,
        'tls1.2': False,
        'tls1.3': False
    }
    
    # 只对HTTPS网站进行TLS检测
    if not url.startswith('https://'):
        if DEBUG_MODE:
            logger.debug("跳过TLS检测：非HTTPS网站")
        return versions
    
    try:
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        
        # 定义TLS版本测试参数
        tls_tests = {
            'tls1.0': ['-tls1'],
            'tls1.1': ['-tls1_1'],
            'tls1.2': ['-tls1_2'],
            'tls1.3': ['-tls1_3']
        }
        
        for tls_version, tls_args in tls_tests.items():
            if DEBUG_MODE:
                logger.debug(f"开始检测 {tls_version.upper()} 支持")
            
            try:
                cmd = [
                    'openssl',
                    's_client',
                    '-connect', f'{hostname}:{port}',
                    '-servername', hostname,
                    '-verify_return_error',
                    '-brief'
                ] + tls_args
                
                if DEBUG_MODE:
                    logger.debug(f"执行命令: {' '.join(cmd)}")
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                # 发送空输入并设置超时
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(input=b''),
                        timeout=10.0
                    )
                    
                    # 解码输出
                    output = stdout.decode('utf-8', errors='ignore')
                    stderr_output = stderr.decode('utf-8', errors='ignore')
                    
                    # 合并stdout和stderr进行检查（openssl s_client的输出可能在stderr中）
                    combined_output = output + stderr_output
                    
                    if DEBUG_MODE:
                        logger.debug(f"{tls_version.upper()} 返回码: {process.returncode}")
                        if stderr_output:
                            logger.debug(f"stderr输出: {stderr_output.strip()}")
                    
                    # 检查连接是否成功建立（无论返回码如何，只要有连接成功的标志）
                    connection_success = (
                        'CONNECTION ESTABLISHED' in combined_output or 
                        'CONNECTED' in combined_output or
                        'Verification: OK' in combined_output or 
                        'Protocol version:' in combined_output or
                        'Ciphersuite:' in combined_output
                    )
                    
                    if connection_success:
                        # 进一步验证TLS版本
                        if tls_version == 'tls1.3' and 'TLSv1.3' in combined_output:
                            versions[tls_version] = True
                        elif tls_version == 'tls1.2' and 'TLSv1.2' in combined_output:
                            versions[tls_version] = True
                        elif tls_version == 'tls1.1' and 'TLSv1.1' in combined_output:
                            versions[tls_version] = True
                        elif tls_version == 'tls1.0' and ('TLSv1.0' in combined_output or ('TLSv1' in combined_output and 'TLSv1.' not in combined_output)):
                            versions[tls_version] = True
                        
                        if DEBUG_MODE:
                            logger.debug(f"{tls_version.upper()} 支持检测：{'成功' if versions[tls_version] else '失败（版本不匹配）'}")
                    else:
                        if DEBUG_MODE:
                            if process.returncode != 0:
                                logger.debug(f"{tls_version.upper()} 支持检测：失败（返回码: {process.returncode})")
                            else:
                                logger.debug(f"{tls_version.upper()} 支持检测：失败（连接未建立）")
                            if stderr_output and 'CONNECTION ESTABLISHED' not in stderr_output:
                                logger.debug(f"错误信息: {stderr_output.strip()}")
                
                except asyncio.TimeoutError:
                    if DEBUG_MODE:
                        logger.debug(f"{tls_version.upper()} 支持检测：超时")
                    try:
                        process.terminate()
                        await process.wait()
                    except:
                        pass
                        
            except Exception as e:
                if DEBUG_MODE:
                    logger.debug(f"{tls_version.upper()} 支持检测异常: {str(e)}")
    
    except Exception as e:
        if DEBUG_MODE:
            logger.error(f"TLS协议版本检测失败: {str(e)}")
    
    if DEBUG_MODE:
        logger.debug(f"TLS协议版本检测完成: {versions}")
    
    return versions


async def detect_http_versions(url: str) -> dict:
    """探测网站支持的HTTP协议版本"""
    versions = {
        'http1.1': False,
        'http2': False,
        'http3': False
    }
    
    try:
        # 测试HTTP/1.1
        cmd_http1 = [
            'curl',
            '-s',
            '-I',
            '--http1.1',
            '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            url
        ]
        
        process_http1 = await asyncio.create_subprocess_exec(
            *cmd_http1,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout_http1, _ = await process_http1.communicate()
        
        if process_http1.returncode == 0:
            output_http1 = stdout_http1.decode('utf-8', errors='ignore')
            if 'HTTP/1.1' in output_http1:
                versions['http1.1'] = True
        
        # 测试HTTP/2
        cmd_http2 = [
            'curl',
            '-s',
            '-I',
            '--http2',
            '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            url
        ]
        
        process_http2 = await asyncio.create_subprocess_exec(
            *cmd_http2,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout_http2, _ = await process_http2.communicate()
        
        if process_http2.returncode == 0:
            output_http2 = stdout_http2.decode('utf-8', errors='ignore')
            if 'HTTP/2' in output_http2:
                versions['http2'] = True
        
        # 测试HTTP/3
        cmd_http3 = [
            'curl',
            '-s',
            '-I',
            '--http3',
            '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            url
        ]
        
        process_http3 = await asyncio.create_subprocess_exec(
            *cmd_http3,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout_http3, _ = await process_http3.communicate()
        
        if process_http3.returncode == 0:
            output_http3 = stdout_http3.decode('utf-8', errors='ignore')
            if 'HTTP/3' in output_http3:
                versions['http3'] = True
    
    except Exception:
        pass
    
    return versions


async def _curl_request_internal(url: str) -> dict:
    """内部curl请求函数"""
    if DEBUG_MODE:
        logger.debug(f"开始HTTP请求: {url}")
    
    start_time = time.time()
    
    try:
        # 构建curl命令
        cmd = [
            'curl',
            '-s',  # 静默模式
            '-I',  # 只获取头部信息
            '-L',  # 跟随重定向
            '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            url
        ]
        
        # 执行curl命令获取头部信息
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        headers_output = stdout.decode('utf-8', errors='ignore')
        
        # 解析状态码
        status_match = re.search(r'HTTP/[\d\.]+\s+(\d+)\s+([^\r\n]+)', headers_output)
        if status_match:
            status_code = status_match.group(1)
            status_text = status_match.group(2).strip()
        else:
            status_code = 'Unknown'
            status_text = 'Unknown'
        
        # 解析重定向Location头部
        location = None
        if status_code in ['301', '302', '303', '307', '308']:
            location_match = re.search(r'location:\s*([^\r\n]+)', headers_output, re.IGNORECASE)
            if location_match:
                location = location_match.group(1).strip()
        
        # 如果状态码是200，再获取完整内容来解析HTML信息
        html_info = {'title': 'N/A', 'description': 'N/A', 'keywords': 'N/A', 'icon': 'N/A'}
        if status_code == '200':
            # 获取完整HTML内容
            if DEBUG_MODE:
                logger.debug("开始获取HTML内容")
            cmd_full = [
                'curl',
                '-s',
                '-L',
                '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                url
            ]
            
            if DEBUG_MODE:
                logger.debug(f"执行HTML获取命令: {' '.join(cmd_full)}")
            
            process_full = await asyncio.create_subprocess_exec(
                *cmd_full,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_full, _ = await process_full.communicate()
            
            if DEBUG_MODE:
                logger.debug(f"HTML获取命令返回码: {process_full.returncode}")
            
            html_content = stdout_full.decode('utf-8', errors='ignore')
            if DEBUG_MODE:
                logger.debug(f"HTML内容获取成功，长度: {len(html_content)} 字符")
            html_info = await extract_html_info(html_content)
        
        # 获取IP地址
        if DEBUG_MODE:
            logger.debug("开始获取IP地址")
        ip_address = await get_ip_from_url(url)
        
        # 探测HTTP协议版本支持
        if DEBUG_MODE:
            logger.debug("开始探测HTTP协议版本支持")
        http_versions = await detect_http_versions(url)
        
        # 探测TLS协议版本支持
        if DEBUG_MODE:
            logger.debug("开始探测TLS协议版本支持")
        tls_versions = await detect_tls_versions(url)
        
        # 获取SSL证书信息
        if DEBUG_MODE:
            logger.debug("开始获取SSL证书信息")
        ssl_cert_info = await get_ssl_certificate_info(url)
        
        # 获取连接延迟信息
        if DEBUG_MODE:
            logger.debug("开始获取连接延迟信息")
        timing_info = await get_connection_timing(url)
        
        end_time = time.time()
        duration = end_time - start_time
        
        return {
            'status_code': status_code,
            'status_text': status_text,
            'ip': ip_address or 'N/A',
            'duration': duration,
            'location': location,
            'http_versions': http_versions,
            'tls_versions': tls_versions,
            'ssl_cert_info': ssl_cert_info,
            'timing_info': timing_info,
            **html_info
        }
        
    except Exception as e:
        if DEBUG_MODE:
            logger.error(f"HTTP请求过程中发生异常: {str(e)}")
        end_time = time.time()
        duration = end_time - start_time
        return {
            'status_code': 'Error',
            'status_text': str(e),
            'ip': 'N/A',
            'duration': duration,
            'location': None,
            'http_versions': {'http1.1': False, 'http2': False, 'http3': False},
            'tls_versions': {'tls1.0': False, 'tls1.1': False, 'tls1.2': False, 'tls1.3': False},
            'ssl_cert_info': {'valid_from': 'N/A', 'valid_to': 'N/A', 'issuer': 'N/A', 'subject': 'N/A', 'san_domains': 'N/A'},
            'timing_info': {'dns_lookup': 'N/A', 'tcp_connect': 'N/A', 'tls_handshake': 'N/A', 'server_response': 'N/A', 'total_time': 'N/A'},
            'title': 'N/A',
            'description': 'N/A',
            'keywords': 'N/A',
            'icon': 'N/A'
        }


async def curl_request(url: str) -> dict:
    """使用curl发送HTTP请求并获取响应信息，带120秒超时控制"""
    if DEBUG_MODE:
        logger.debug(f"开始执行带超时控制的HTTP请求: {url}")
    
    try:
        # 使用asyncio.wait_for实现120秒超时控制
        result = await asyncio.wait_for(_curl_request_internal(url), timeout=120.0)
        if DEBUG_MODE:
            logger.debug(f"HTTP请求在超时时间内完成: {url}")
        return result
    except asyncio.TimeoutError:
        if DEBUG_MODE:
            logger.warning(f"HTTP请求超时(120秒): {url}")
        return {
            'status_code': 'Timeout',
            'status_text': '请求超时(120秒)',
            'ip': 'N/A',
            'duration': 120.0,
            'location': None,
            'http_versions': {'http1.1': False, 'http2': False, 'http3': False},
            'tls_versions': {'tls1.0': False, 'tls1.1': False, 'tls1.2': False, 'tls1.3': False},
            'ssl_cert_info': {'valid_from': 'N/A', 'valid_to': 'N/A', 'issuer': 'N/A', 'subject': 'N/A', 'san_domains': 'N/A'},
            'timing_info': {'dns_lookup': 'N/A', 'tcp_connect': 'N/A', 'tls_handshake': 'N/A', 'server_response': 'N/A', 'total_time': 'N/A'},
            'title': 'N/A',
            'description': 'N/A',
            'keywords': 'N/A',
            'icon': 'N/A'
        }


@cmd_http.handle()
async def _(matcher: Matcher, event: Event, args: Message = CommandArg()):
    url = args.extract_plain_text().strip()
    
    if not url:
        await matcher.finish("请提供要检测的URL，例如：http https://example.com")
    
    # 检查是否只是一个链接（没有命令前缀），如果是则不处理
    original_message = str(event.get_message()).strip()
    if original_message.startswith(('http://', 'https://')) and not original_message.startswith(('http ', 'HTTP ')):
        return  # 直接返回，不处理纯链接
    
    # 如果URL不包含协议，默认添加https://
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    if DEBUG_MODE:
        logger.info(f"开始HTTP检测任务: {url} (用户: {event.user_id})")
    
    await matcher.send("正在检测中，请稍候...")
    
    try:
        if DEBUG_MODE:
            logger.debug("开始执行curl_request")
        result = await curl_request(url)
        
        if DEBUG_MODE:
            logger.debug(f"curl_request执行完成，状态码: {result.get('status_code')}")
        
        # 格式化响应消息
        response_parts = [
            f"状态码：{result['status_code']}",
            f"网站：{url}",
            f"IP：{result['ip']}"
        ]
        
        # 如果有重定向信息，添加到响应中
        if result.get('location'):
            response_parts.append(f"重定向到：{result['location']}")
        
        # 添加HTTP协议版本支持信息
        http_versions = result.get('http_versions', {})
        supported_versions = []
        if http_versions.get('http1.1'):
            supported_versions.append('HTTP/1.1')
        if http_versions.get('http2'):
            supported_versions.append('HTTP/2')
        if http_versions.get('http3'):
            supported_versions.append('HTTP/3')
        
        if supported_versions:
            response_parts.append(f"HTTP协议：{', '.join(supported_versions)}")
        else:
            response_parts.append("HTTP协议：未知")
        
        # 添加TLS协议版本支持信息
        tls_versions = result.get('tls_versions', {})
        supported_tls = []
        if tls_versions.get('tls1.0'):
            supported_tls.append('TLS 1.0')
        if tls_versions.get('tls1.1'):
            supported_tls.append('TLS 1.1')
        if tls_versions.get('tls1.2'):
            supported_tls.append('TLS 1.2')
        if tls_versions.get('tls1.3'):
            supported_tls.append('TLS 1.3')
        
        if url.startswith('https://'):
            if supported_tls:
                response_parts.append(f"TLS协议：{', '.join(supported_tls)}")
            else:
                response_parts.append("TLS协议：未知")
            
            # 添加SSL证书信息
            ssl_cert_info = result.get('ssl_cert_info', {})
            if ssl_cert_info.get('valid_from') != 'N/A' and ssl_cert_info.get('valid_to') != 'N/A':
                response_parts.append(f"证书有效期：{ssl_cert_info.get('valid_from')} - {ssl_cert_info.get('valid_to')}")
            else:
                response_parts.append("证书有效期：未知")
            
            if ssl_cert_info.get('issuer') != 'N/A':
                response_parts.append(f"证书签发者：{ssl_cert_info.get('issuer')}")
            else:
                response_parts.append("证书签发者：未知")
            
            if ssl_cert_info.get('san_domains') != 'N/A':
                response_parts.append(f"证书域名：{ssl_cert_info.get('san_domains')}")
            elif ssl_cert_info.get('subject') != 'N/A':
                response_parts.append(f"证书域名：{ssl_cert_info.get('subject')}")
            else:
                response_parts.append("证书域名：未知")
        else:
            response_parts.append("TLS协议：不适用(HTTP)")
        
        # 添加连接延迟信息
        timing_info = result.get('timing_info', {})
        if timing_info.get('dns_lookup') != 'N/A':
            response_parts.extend([
                f"DNS解析时间：{timing_info.get('dns_lookup')}",
                f"TCP连接时间：{timing_info.get('tcp_connect')}",
                f"TLS握手时间：{timing_info.get('tls_handshake')}",
                f"服务器响应时间：{timing_info.get('server_response')}",
                f"总连接时间：{timing_info.get('total_time')}"
            ])
        
        response_parts.extend([
            f"标题：{result['title']}",
            f"简介：{result['description']}",
            f"关键词：{result['keywords']}",
            f"网站图标：{result['icon']}",
            f"用时：{result['duration']:.3f}s"
        ])
        
        response_msg = "\n".join(response_parts)
        
        if DEBUG_MODE:
            logger.debug(f"准备发送检测结果，共 {len(response_parts)} 行信息")
            logger.info(f"HTTP检测任务完成: {url} (状态码: {result.get('status_code')})")
        
        await matcher.finish(response_msg)
        
    except FinishedException:
        # FinishedException 是正常的完成回调，重新抛出
        raise
    except Exception as e:
        if DEBUG_MODE:
            logger.error(f"HTTP检测任务失败: {url} - {str(e)}")
        await matcher.finish(f"检测失败：{str(e)}")