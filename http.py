import asyncio
import json
import logging
import os
import re
import subprocess
import time
from typing import Optional
from urllib.parse import urlparse
import aiohttp

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
DEBUG_MODE = True  # 设置为False可关闭详细日志

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
    """通过nslookup获取域名对应的IP地址，如果传入的是IP地址则直接返回"""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # 检查是否已经是IP地址，如果是则直接返回
        ip_pattern = r'^\d+\.\d+\.\d+\.\d+$'
        if re.match(ip_pattern, domain):
            if DEBUG_MODE:
                logger.debug(f"检测到IP地址，跳过nslookup: {domain}")
            return domain
        
        if DEBUG_MODE:
            logger.debug(f"开始nslookup查询域名: {domain}")
        
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
            if DEBUG_MODE:
                logger.debug(f"nslookup查询成功，返回IP: {matches[-1]}")
            return matches[-1]  # 返回最后一个IP地址
        
        # 备用模式
        ip_pattern2 = r'(\d+\.\d+\.\d+\.\d+)'
        matches2 = re.findall(ip_pattern2, output)
        for ip in matches2:
            if not ip.startswith('127.') and ip != '0.0.0.0':
                if DEBUG_MODE:
                    logger.debug(f"nslookup备用模式查询成功，返回IP: {ip}")
                return ip
                
        if DEBUG_MODE:
            logger.debug(f"nslookup查询失败，未找到有效IP地址")
        return None
    except Exception as e:
        if DEBUG_MODE:
            logger.error(f"nslookup查询异常: {str(e)}")
        return None


async def get_ip_location(ip: str) -> dict:
    """通过ip-api.com获取IP归属信息"""
    location_info = {
        'country': 'N/A',
        'region': 'N/A', 
        'city': 'N/A',
        'isp': 'N/A',
        'org': 'N/A',
        'as': 'N/A'
    }
    
    if not ip or ip == 'N/A':
        return location_info
    
    try:
        if DEBUG_MODE:
            logger.debug(f"开始查询IP归属信息: {ip}")
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            url = f"http://ip-api.com/json/{ip}"
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('status') == 'success':
                        location_info.update({
                            'country': data.get('country', 'N/A'),
                            'region': data.get('regionName', 'N/A'),
                            'city': data.get('city', 'N/A'),
                            'isp': data.get('isp', 'N/A'),
                            'org': data.get('org', 'N/A'),
                            'as': data.get('as', 'N/A')
                        })
                        if DEBUG_MODE:
                            logger.debug(f"IP归属查询成功: {location_info}")
                    else:
                        if DEBUG_MODE:
                            logger.debug(f"IP归属查询失败: {data.get('message', '未知错误')}")
                else:
                    if DEBUG_MODE:
                        logger.debug(f"IP归属查询HTTP错误: {response.status}")
    except Exception as e:
        if DEBUG_MODE:
            logger.error(f"IP归属查询异常: {str(e)}")
    
    return location_info


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


async def get_connection_timing(url: str, resolved_ip: Optional[str] = None) -> dict:
    """获取连接延迟信息"""
    if DEBUG_MODE:
        logger.debug(f"开始获取连接延迟信息: {url}")
        if resolved_ip:
            logger.debug(f"使用强制绑定IP: {resolved_ip}")
    
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
            '--location',
            '-o', 'NUL' if os.name == 'nt' else '/dev/null',
            '-s',
            '-w', 'DNS Lookup Time: %{time_namelookup}s\nTCP Connect Time: %{time_connect}s\nTLS Handshake Time: %{time_appconnect}s\nServer Response Time: %{time_starttransfer}s\nTotal Time: %{time_total}s\n',
            '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            '-k'  # 忽略SSL证书验证错误
        ]
        
        # 如果有解析到的IP，添加--resolve参数强制绑定
        if resolved_ip:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            resolve_param = f"{hostname}:{port}:{resolved_ip}"
            cmd.extend(['--resolve', resolve_param])
            if DEBUG_MODE:
                logger.debug(f"连接延迟检测添加resolve参数: {resolve_param}")
        
        cmd.append(url)
        
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


async def get_ssl_certificate_info(url: str, resolved_ip: Optional[str] = None) -> dict:
    """获取SSL证书信息"""
    cert_info = {
        'valid_from': 'N/A',
        'valid_to': 'N/A',
        'issuer': 'N/A',
        'subject': 'N/A',
        'san_domains': 'N/A',
        'is_trusted': 'N/A'
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
        
        # 如果有强制绑定的IP，使用该IP进行连接
        connect_host = resolved_ip if resolved_ip else hostname
        if DEBUG_MODE and resolved_ip:
            logger.debug(f"SSL证书检测使用强制绑定IP: {resolved_ip}")
        
        # 首先检查证书是否可信（不忽略验证）
        cmd_verify = [
            'openssl',
            's_client',
            '-connect', f'{connect_host}:{port}',
            '-servername', hostname,
            '-verify_return_error'
        ]
        
        verify_process = await asyncio.create_subprocess_exec(
            *cmd_verify,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # 发送空输入并关闭stdin
        verify_stdout, verify_stderr = await verify_process.communicate(input=b'')
        
        # 检查证书验证结果
        if verify_process.returncode == 0:
            verify_output = verify_stdout.decode('utf-8', errors='ignore')
            if 'Verification: OK' in verify_output or 'Verify return code: 0' in verify_output:
                cert_info['is_trusted'] = '可信'
            else:
                cert_info['is_trusted'] = '不可信'
        else:
            cert_info['is_trusted'] = '不可信'
        
        # 然后获取证书详细信息（忽略验证错误）
        cmd = [
            'openssl',
            's_client',
            '-connect', f'{connect_host}:{port}',
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
        
        # 即使返回码不为0，也尝试解析证书信息（因为可能是验证失败但连接成功）
        output = stdout.decode('utf-8', errors='ignore')
        stderr_output = stderr.decode('utf-8', errors='ignore')
        
        # 合并stdout和stderr，因为openssl的输出可能在stderr中
        combined_output = output + stderr_output
        
        if combined_output:
             # 提取证书部分
             cert_start = combined_output.find('-----BEGIN CERTIFICATE-----')
             cert_end = combined_output.find('-----END CERTIFICATE-----')
             
             if cert_start != -1 and cert_end != -1:
                 cert_pem = combined_output[cert_start:cert_end + len('-----END CERTIFICATE-----')]
                 
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


async def detect_tls_versions(url: str, resolved_ip: Optional[str] = None) -> dict:
    """使用openssl s_client检测网站支持的TLS协议版本"""
    if DEBUG_MODE:
        logger.debug(f"开始使用openssl s_client检测TLS协议版本: {url}")
        if resolved_ip:
            logger.debug(f"TLS检测使用强制绑定IP: {resolved_ip}")
    
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
        
        # 如果有强制绑定的IP，使用该IP进行连接
        connect_host = resolved_ip if resolved_ip else hostname
        
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
                    '-connect', f'{connect_host}:{port}',
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


async def detect_http_versions(url: str, resolved_ip: Optional[str] = None) -> dict:
    """探测网站支持的HTTP协议版本"""
    versions = {
        'http1.1': False,
        'http2': False,
        'http3': False
    }
    
    try:
        # 解析URL信息用于--resolve参数
        resolve_params = []
        if resolved_ip:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            resolve_param = f"{hostname}:{port}:{resolved_ip}"
            resolve_params = ['--resolve', resolve_param]
            if DEBUG_MODE:
                logger.debug(f"HTTP版本检测使用强制绑定IP: {resolve_param}")
        
        # 测试HTTP/1.1
        cmd_http1 = [
            'curl',
            '--location',
            '-s',
            '-I',
            '--http1.1',
            '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            '-k'  # 忽略SSL证书验证错误
        ] + resolve_params + [url]
        
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
            '--location',
            '-s',
            '-I',
            '--http2',
            '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            '-k'  # 忽略SSL证书验证错误
        ] + resolve_params + [url]
        
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
            '--location',
            '-s',
            '-I',
            '--http3',
            '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            '-k'  # 忽略SSL证书验证错误
        ] + resolve_params + [url]
        
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


async def _curl_request_internal(url: str, custom_ip: Optional[str] = None) -> dict:
    """内部curl请求函数"""
    if DEBUG_MODE:
        logger.debug(f"开始HTTP请求: {url}")
        if custom_ip:
            logger.debug(f"使用自定义IP: {custom_ip}")
    
    start_time = time.time()
    
    try:
        # 先获取域名的IP地址（如果没有指定自定义IP）
        resolved_ip = custom_ip
        if not resolved_ip:
            if DEBUG_MODE:
                logger.debug("开始通过nslookup获取域名IP")
            resolved_ip = await get_ip_from_url(url)
            if DEBUG_MODE:
                logger.debug(f"nslookup获取到的IP: {resolved_ip}")
        
        # 构建curl命令
        cmd = [
            'curl',
            '--location',
            '-s',  # 静默模式
            '-I',  # 只获取头部信息
            '-L',  # 跟随重定向
            '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        ]
        
        # 如果有解析到的IP，添加--resolve参数强制绑定
        if resolved_ip:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            resolve_param = f"{hostname}:{port}:{resolved_ip}"
            cmd.extend(['--resolve', resolve_param])
            if DEBUG_MODE:
                logger.debug(f"添加resolve参数强制绑定IP: {resolve_param}")
        
        cmd.append(url)
        
        # 直接获取完整内容并解析状态码和HTML信息
        # 修改curl命令为获取完整内容而非仅头部
        cmd_full = [
            'curl',
            '--location',
            '-s',
            '-D', '-',  # 输出响应头到stdout
            '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            '-k'  # 忽略SSL证书验证错误
        ]
        
        # 如果有解析到的IP，添加--resolve参数强制绑定
        if resolved_ip:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            resolve_param = f"{hostname}:{port}:{resolved_ip}"
            cmd_full.extend(['--resolve', resolve_param])
            if DEBUG_MODE:
                logger.debug(f"添加resolve参数强制绑定IP: {resolve_param}")
        
        cmd_full.append(url)
        
        if DEBUG_MODE:
            logger.debug(f"执行HTTP请求和HTML获取命令: {' '.join(cmd_full)}")
        
        process = await asyncio.create_subprocess_exec(
            *cmd_full,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if DEBUG_MODE:
            logger.debug(f"curl命令执行完成，返回码: {process.returncode}")
        
        full_output = stdout.decode('utf-8', errors='ignore')
        
        # 分离HTTP头部和HTML内容
        # 查找双换行符分隔头部和内容
        header_end = full_output.find('\r\n\r\n')
        if header_end == -1:
            header_end = full_output.find('\n\n')
        
        if header_end != -1:
            headers_output = full_output[:header_end]
            html_content = full_output[header_end + 4:] if '\r\n\r\n' in full_output else full_output[header_end + 2:]
        else:
            headers_output = full_output
            html_content = ''
        
        # 解析状态码
        if DEBUG_MODE:
            logger.debug(f"HTTP响应头部内容: {headers_output[:300]}...")  # 显示前300字符
        
        status_match = re.search(r'HTTP/[\d\.]+\s+(\d+)\s+([^\r\n]+)', headers_output)
        if status_match:
            status_code = status_match.group(1)
            status_text = status_match.group(2).strip()
            if DEBUG_MODE:
                logger.debug(f"成功解析状态码: {status_code} {status_text}")
        else:
            status_code = 'Unknown'
            status_text = 'Unknown'
            if DEBUG_MODE:
                logger.debug("未能从HTTP响应中解析到状态码")
        
        # 解析重定向Location头部
        location = None
        if status_code in ['301', '302', '303', '307', '308']:
            location_match = re.search(r'location:\s*([^\r\n]+)', headers_output, re.IGNORECASE)
            if location_match:
                location = location_match.group(1).strip()
        
        # 解析HTML信息
        html_info = {'title': 'N/A', 'description': 'N/A', 'keywords': 'N/A', 'icon': 'N/A'}
        if DEBUG_MODE:
            logger.debug(f"HTML内容获取成功，长度: {len(html_content)} 字符")
        html_info = await extract_html_info(html_content)
        
        # 使用已解析的IP地址
        if DEBUG_MODE:
            logger.debug(f"使用已解析的IP地址: {resolved_ip}")
        ip_address = resolved_ip
        
        # 获取IP归属信息
        if DEBUG_MODE:
            logger.debug("开始获取IP归属信息")
        ip_location = await get_ip_location(ip_address)
        
        # 探测HTTP协议版本支持
        if DEBUG_MODE:
            logger.debug("开始探测HTTP协议版本支持")
        http_versions = await detect_http_versions(url, resolved_ip)
        
        # 探测TLS协议版本支持
        if DEBUG_MODE:
            logger.debug("开始探测TLS协议版本支持")
        tls_versions = await detect_tls_versions(url, resolved_ip)
        
        # 获取SSL证书信息
        if DEBUG_MODE:
            logger.debug("开始获取SSL证书信息")
        ssl_cert_info = await get_ssl_certificate_info(url, resolved_ip)
        
        # 获取连接延迟信息
        if DEBUG_MODE:
            logger.debug("开始获取连接延迟信息")
        timing_info = await get_connection_timing(url, resolved_ip)
        
        end_time = time.time()
        duration = end_time - start_time
        
        return {
            'status_code': status_code,
            'status_text': status_text,
            'ip': ip_address or 'N/A',
            'ip_location': ip_location,
            'duration': duration,
            'location': location,
            'http_versions': http_versions,
            'tls_versions': tls_versions,
            'ssl_cert_info': ssl_cert_info,
            'timing_info': timing_info,
            'original_url': url,
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
            'ip_location': {'country': 'N/A', 'region': 'N/A', 'city': 'N/A', 'isp': 'N/A', 'org': 'N/A', 'as': 'N/A'},
            'duration': duration,
            'location': None,
            'http_versions': {'http1.1': False, 'http2': False, 'http3': False},
            'tls_versions': {'tls1.0': False, 'tls1.1': False, 'tls1.2': False, 'tls1.3': False},
            'ssl_cert_info': {'valid_from': 'N/A', 'valid_to': 'N/A', 'issuer': 'N/A', 'subject': 'N/A', 'san_domains': 'N/A', 'is_trusted': 'N/A'},
            'timing_info': {'dns_lookup': 'N/A', 'tcp_connect': 'N/A', 'tls_handshake': 'N/A', 'server_response': 'N/A', 'total_time': 'N/A'},
            'title': 'N/A',
            'description': 'N/A',
            'keywords': 'N/A',
            'icon': 'N/A',
            'original_url': url
        }


async def get_website_info(url: str, custom_ip: Optional[str] = None) -> dict:
    """获取网站信息，支持自定义IP解析"""
    return await curl_request(url, custom_ip)


def format_website_info(site_info: dict, custom_ip: Optional[str] = None) -> str:
    """格式化网站信息为消息字符串"""
    response_parts = [
        f"状态码：{site_info['status_code']}",
        f"网站：{site_info.get('original_url', 'N/A')}",
        f"IP：{site_info['ip']}"
    ]
    
    if custom_ip:
        response_parts.append(f"指定IP：{custom_ip}")
    
    # 添加IP归属信息
    ip_location = site_info.get('ip_location', {})
    if ip_location.get('country') != 'N/A':
        location_parts = []
        if ip_location.get('country') != 'N/A':
            location_parts.append(ip_location['country'])
        if ip_location.get('region') != 'N/A':
            location_parts.append(ip_location['region'])
        if ip_location.get('city') != 'N/A':
            location_parts.append(ip_location['city'])
        
        if location_parts:
            response_parts.append(f"IP归属：{' '.join(location_parts)}")
        
        if ip_location.get('isp') != 'N/A':
            response_parts.append(f"ISP：{ip_location['isp']}")
        
        if ip_location.get('as') != 'N/A':
            response_parts.append(f"AS：{ip_location['as']}")
    else:
        response_parts.append("IP归属：未知")
    
    # 如果有重定向信息，添加到响应中
    if site_info.get('location'):
        response_parts.append(f"重定向到：{site_info['location']}")
    
    # 添加HTTP协议版本支持信息
    http_versions = site_info.get('http_versions', {})
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
    tls_versions = site_info.get('tls_versions', {})
    supported_tls = []
    if tls_versions.get('tls1.0'):
        supported_tls.append('TLS 1.0')
    if tls_versions.get('tls1.1'):
        supported_tls.append('TLS 1.1')
    if tls_versions.get('tls1.2'):
        supported_tls.append('TLS 1.2')
    if tls_versions.get('tls1.3'):
        supported_tls.append('TLS 1.3')
    
    original_url = site_info.get('original_url', '')
    if original_url.startswith('https://'):
        if supported_tls:
            response_parts.append(f"TLS协议：{', '.join(supported_tls)}")
        else:
            response_parts.append("TLS协议：未知")
        
        # 添加SSL证书信息
        ssl_cert_info = site_info.get('ssl_cert_info', {})
        
        # 添加SSL证书状态
        if ssl_cert_info.get('is_trusted') != 'N/A':
            response_parts.append(f"SSL证书：{ssl_cert_info.get('is_trusted')}")
        else:
            response_parts.append("SSL证书：未知")
        
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
    timing_info = site_info.get('timing_info', {})
    if timing_info.get('dns_lookup') != 'N/A':
        response_parts.extend([
            f"DNS解析时间：{timing_info.get('dns_lookup')}",
            f"TCP连接时间：{timing_info.get('tcp_connect')}",
            f"TLS握手时间：{timing_info.get('tls_handshake')}",
            f"服务器响应时间：{timing_info.get('server_response')}",
            f"总连接时间：{timing_info.get('total_time')}"
        ])
    
    response_parts.extend([
        f"标题：{site_info['title']}",
        f"简介：{site_info['description']}",
        f"关键词：{site_info['keywords']}",
        f"网站图标：{site_info['icon']}",
        f"用时：{site_info['duration']:.3f}s"
    ])
    
    return "\n".join(response_parts)


async def curl_request(url: str, custom_ip: Optional[str] = None) -> dict:
    """使用curl发送HTTP请求并获取响应信息，带120秒超时控制"""
    if DEBUG_MODE:
        logger.debug(f"开始执行带超时控制的HTTP请求: {url}")
    
    try:
        # 使用asyncio.wait_for实现120秒超时控制
        result = await asyncio.wait_for(_curl_request_internal(url, custom_ip), timeout=120.0)
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
            'ip_location': {'country': 'N/A', 'region': 'N/A', 'city': 'N/A', 'isp': 'N/A', 'org': 'N/A', 'as': 'N/A'},
            'duration': 120.0,
            'location': None,
            'http_versions': {'http1.1': False, 'http2': False, 'http3': False},
            'tls_versions': {'tls1.0': False, 'tls1.1': False, 'tls1.2': False, 'tls1.3': False},
            'ssl_cert_info': {'valid_from': 'N/A', 'valid_to': 'N/A', 'issuer': 'N/A', 'subject': 'N/A', 'san_domains': 'N/A', 'is_trusted': 'N/A'},
            'timing_info': {'dns_lookup': 'N/A', 'tcp_connect': 'N/A', 'tls_handshake': 'N/A', 'server_response': 'N/A', 'total_time': 'N/A'},
            'title': 'N/A',
            'description': 'N/A',
            'keywords': 'N/A',
            'icon': 'N/A',
            'original_url': url
        }


def parse_http_command(args_text: str) -> tuple[str, Optional[str]]:
    """解析HTTP命令参数
    
    Returns:
        tuple: (url, custom_ip)
    """
    parts = args_text.strip().split()
    
    if len(parts) == 1:
        return parts[0], None
    elif len(parts) == 2:
        return parts[0], parts[1]
    else:
        # 如果有多个参数，取前两个
        return parts[0], parts[1] if len(parts) > 1 else None


@cmd_http.handle()
async def handle_http_command(matcher: Matcher, event: Event, args: Message = CommandArg()):
    """处理HTTP检测命令"""
    args_text = args.extract_plain_text().strip()
    
    if not args_text:
        await matcher.finish("请提供要检测的URL，例如：\nhttp https://example.com\nhttp afo.im 76.76.21.21 (指定IP)")
    
    # 解析命令参数
    url, custom_ip = parse_http_command(args_text)
    
    # 如果URL不包含协议，默认添加https://
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    if custom_ip:
        logger.info(f"开始检测网站: {url} (指定IP: {custom_ip})")
    else:
        logger.info(f"开始检测网站: {url}")
    
    try:
        # 获取网站信息
        site_info = await get_website_info(url, custom_ip)
        
        # 构建回复消息
        message = format_website_info(site_info, custom_ip)
        
        await matcher.finish(message)
        
    except Exception as e:
        logger.error(f"检测网站时发生错误: {str(e)}")
        return