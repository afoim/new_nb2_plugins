import asyncio
import re
import subprocess
import json
import aiohttp
from nonebot import on_command
from nonebot.adapters.onebot.v11 import MessageEvent
from nonebot.matcher import Matcher
from nonebot.params import CommandArg
from nonebot.adapters.onebot.v11 import Message
from nonebot.plugin import PluginMetadata
from nonebot.log import logger
from bs4 import BeautifulSoup

# DEBUG模式设置
DEBUG_MODE = False  # 设置为True可开启详细调试日志

__plugin_meta__ = PluginMetadata(
    name="WHOIS查询",
    description="查询域名或IP地址的WHOIS信息，支持RDAP和传统WHOIS协议",
    usage="/whois <域名或IP> - 查询WHOIS信息\n支持RDAP协议的域名将优先使用RDAP查询"
)

cmd_whois = on_command("whois", aliases={"域名查询", "whois查询"}, priority=5, block=True, force_whitespace=True)

def is_valid_domain(domain: str) -> bool:
    """验证域名格式"""
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'  # 域名部分
        r'[a-zA-Z]{2,}$'  # 顶级域名
    )
    return bool(domain_pattern.match(domain))

def is_valid_ip(ip: str) -> bool:
    """验证IP地址格式"""
    # IPv4 格式验证
    ipv4_pattern = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    # IPv6 格式验证（简化版）
    ipv6_pattern = re.compile(
        r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
        r'^::1$|^::$'
    )
    return bool(ipv4_pattern.match(ip) or ipv6_pattern.match(ip))

def get_tld(domain: str) -> str:
    """获取域名的顶级域"""
    parts = domain.split('.')
    if len(parts) >= 2:
        return parts[-1].lower()
    return ''

async def supports_rdap(domain: str) -> tuple[bool, str]:
    """检查域名是否支持RDAP查询，返回(是否支持, RDAP服务器URL)"""
    try:
        iana_info = await query_iana_registry_info(domain)
        rdap_server = iana_info.get('rdap_server')
        if rdap_server:
            return True, rdap_server
        return False, None
    except Exception:
        return False, None

async def query_rdap(domain: str, rdap_server: str) -> dict:
    """使用RDAP协议查询域名信息"""
    if not rdap_server:
        raise ValueError(f"未提供RDAP服务器URL")
    
    # 确保RDAP服务器URL以/结尾
    if not rdap_server.endswith('/'):
        rdap_server += '/'
    rdap_url = rdap_server + f"domain/{domain}"
    
    # 上报访问的IANA相关地址
    logger.info(f"[IANA ACCESS] 正在访问RDAP服务器: {rdap_server}")
    logger.info(f"[IANA ACCESS] 完整查询URL: {rdap_url}")
    
    if DEBUG_MODE:
        logger.info(f"[RDAP DEBUG] 正在查询域名: {domain}")
        logger.info(f"[RDAP DEBUG] RDAP服务器: {rdap_server}")
        logger.info(f"[RDAP DEBUG] 完整URL: {rdap_url}")
    
    async with aiohttp.ClientSession() as session:
        try:
            if DEBUG_MODE:
                logger.info(f"[RDAP DEBUG] 开始HTTP请求...")
            
            async with session.get(rdap_url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if DEBUG_MODE:
                    logger.info(f"[RDAP DEBUG] HTTP响应状态码: {response.status}")
                    logger.info(f"[RDAP DEBUG] 响应头: {dict(response.headers)}")
                
                if response.status == 200:
                    response_text = await response.text()
                    if DEBUG_MODE:
                        logger.info(f"[RDAP DEBUG] 响应内容长度: {len(response_text)} 字符")
                        logger.info(f"[RDAP DEBUG] 响应内容前500字符: {response_text[:500]}")
                    
                    try:
                        json_data = json.loads(response_text)
                        if DEBUG_MODE:
                            logger.info(f"[RDAP DEBUG] JSON解析成功，包含字段: {list(json_data.keys())}")
                        return json_data
                    except json.JSONDecodeError as e:
                        if DEBUG_MODE:
                            logger.error(f"[RDAP DEBUG] JSON解析失败: {str(e)}")
                        raise ValueError(f"RDAP响应JSON解析失败: {str(e)}")
                        
                elif response.status == 404:
                    if DEBUG_MODE:
                        logger.info(f"[RDAP DEBUG] 域名未找到 (404)")
                    raise ValueError(f"未找到域名 {domain} 的信息")
                else:
                    response_text = await response.text()
                    if DEBUG_MODE:
                        logger.error(f"[RDAP DEBUG] HTTP错误响应: {response_text[:500]}")
                    raise ValueError(f"RDAP查询失败，HTTP状态码: {response.status}")
                    
        except aiohttp.ClientError as e:
            if DEBUG_MODE:
                logger.error(f"[RDAP DEBUG] 网络连接错误: {type(e).__name__}: {str(e)}")
            raise ValueError(f"RDAP查询网络错误: {str(e)}")
        except asyncio.TimeoutError:
            if DEBUG_MODE:
                logger.error(f"[RDAP DEBUG] 请求超时")
            raise ValueError("RDAP查询超时")

def format_rdap_response(rdap_data: dict, domain: str) -> str:
    """格式化RDAP响应数据"""
    result_lines = []
    
    # 域名信息
    result_lines.append(f"域名: {domain}")
    
    # Unicode域名（如果存在且与ASCII不同）
    if 'unicodeName' in rdap_data and rdap_data['unicodeName'] != domain:
        result_lines.append(f"Unicode域名: {rdap_data['unicodeName']}")
    
    # 域名句柄
    if 'handle' in rdap_data:
        result_lines.append(f"域名句柄: {rdap_data['handle']}")
    
    # 状态信息
    if 'status' in rdap_data:
        status_list = rdap_data['status']
        if status_list:
            result_lines.append(f"状态: {', '.join(status_list)}")
    
    # 注册商信息（增强版）
    registrar_info = []
    if 'entities' in rdap_data:
        for entity in rdap_data['entities']:
            if 'roles' in entity and 'registrar' in entity['roles']:
                # 注册商名称
                if 'vcardArray' in entity:
                    vcard = entity['vcardArray'][1] if len(entity['vcardArray']) > 1 else []
                    for item in vcard:
                        if isinstance(item, list) and len(item) >= 4:
                            if item[0] == 'fn':  # 全名
                                registrar_info.append(f"注册商: {item[3]}")
                                break
                
                # 注册商ID
                if 'publicIds' in entity:
                    for pub_id in entity['publicIds']:
                        if pub_id.get('type') == 'IANA Registrar ID':
                            registrar_info.append(f"注册商ID: {pub_id.get('identifier')}")
                
                # 滥用联系方式
                if 'entities' in entity:
                    for sub_entity in entity['entities']:
                        if 'roles' in sub_entity and 'abuse' in sub_entity['roles']:
                            if 'vcardArray' in sub_entity:
                                abuse_vcard = sub_entity['vcardArray'][1] if len(sub_entity['vcardArray']) > 1 else []
                                for item in abuse_vcard:
                                    if isinstance(item, list) and len(item) >= 4:
                                        if item[0] == 'email':
                                            registrar_info.append(f"滥用举报邮箱: {item[3]}")
                                        elif item[0] == 'tel':
                                            tel_value = item[3] if isinstance(item[3], str) else item[3].replace('tel:', '') if 'tel:' in str(item[3]) else str(item[3])
                                            registrar_info.append(f"滥用举报电话: {tel_value}")
                break
    
    if registrar_info:
        result_lines.extend(registrar_info)
    
    # 重要日期（增强版）
    events = rdap_data.get('events', [])
    date_info = {}
    for event in events:
        event_action = event.get('eventAction', '')
        event_date = event.get('eventDate', '')
        if event_date:
            # 只显示日期部分，去掉时间
            date_part = event_date.split('T')[0]
            if event_action == 'registration':
                date_info['注册日期'] = date_part
            elif event_action == 'expiration':
                date_info['到期日期'] = date_part
            elif event_action == 'last update of RDAP database':
                date_info['数据库更新'] = date_part
            elif event_action == 'reregistration':
                date_info['重新注册'] = date_part
            elif event_action == 'last changed':
                date_info['最后修改'] = date_part
    
    # 显示所有日期信息
    for date_type in ['注册日期', '到期日期', '重新注册', '最后修改', '数据库更新']:
        if date_type in date_info:
            result_lines.append(f"{date_type}: {date_info[date_type]}")
    
    # 名称服务器（增强版）
    if 'nameservers' in rdap_data:
        ns_info = []
        for ns in rdap_data['nameservers']:
            ns_details = []
            if 'ldhName' in ns:
                ns_details.append(ns['ldhName'])
            
            # 添加IP地址信息
            if 'ipAddresses' in ns:
                ip_addresses = ns['ipAddresses']
                ipv4_list = ip_addresses.get('v4', [])
                ipv6_list = ip_addresses.get('v6', [])
                
                if ipv4_list or ipv6_list:
                    ip_info = []
                    if ipv4_list:
                        ip_info.extend([f"IPv4: {ip}" for ip in ipv4_list[:2]])  # 限制显示数量
                    if ipv6_list:
                        ip_info.extend([f"IPv6: {ip}" for ip in ipv6_list[:1]])  # 限制显示数量
                    
                    if ip_info:
                        ns_details.append(f"({', '.join(ip_info)})")
            
            if ns_details:
                ns_info.append(' '.join(ns_details))
        
        if ns_info:
            result_lines.append(f"名称服务器: {'; '.join(ns_info)}")
    
    # DNSSEC信息
    if 'secureDNS' in rdap_data:
        secure_dns = rdap_data['secureDNS']
        
        # DNSSEC状态
        if 'zoneSigned' in secure_dns:
            zone_signed = secure_dns['zoneSigned']
            if zone_signed:
                result_lines.append("DNSSEC: 已启用")
                
                # DS记录信息
                if 'dsData' in secure_dns:
                    ds_records = secure_dns['dsData']
                    if ds_records:
                        ds_info = []
                        for ds in ds_records:
                            ds_parts = []
                            if 'keyTag' in ds:
                                ds_parts.append(f"KeyTag: {ds['keyTag']}")
                            if 'algorithm' in ds:
                                ds_parts.append(f"算法: {ds['algorithm']}")
                            if 'digestType' in ds:
                                ds_parts.append(f"摘要类型: {ds['digestType']}")
                            if ds_parts:
                                ds_info.append(f"DS记录: {', '.join(ds_parts)}")
                        
                        if ds_info:
                            result_lines.extend(ds_info)
                
                # 密钥数据信息
                if 'keyData' in secure_dns:
                    key_data = secure_dns['keyData']
                    if key_data:
                        key_info = []
                        for key in key_data:
                            key_parts = []
                            if 'flags' in key:
                                key_parts.append(f"标志: {key['flags']}")
                            if 'protocol' in key:
                                key_parts.append(f"协议: {key['protocol']}")
                            if 'algorithm' in key:
                                key_parts.append(f"算法: {key['algorithm']}")
                            if key_parts:
                                key_info.append(f"DNSKEY: {', '.join(key_parts)}")
                        
                        if key_info:
                            result_lines.extend(key_info)
            else:
                result_lines.append("DNSSEC: 未启用")
        
        # 委托签名者信息
        if 'delegationSigned' in secure_dns:
            delegation_signed = secure_dns['delegationSigned']
            if delegation_signed:
                result_lines.append("委托签名: 已启用")
            else:
                result_lines.append("委托签名: 未启用")
    
    # 相关链接（增强版）
    if 'links' in rdap_data:
        link_info = []
        for link in rdap_data['links']:
            href = link.get('href', '')
            rel = link.get('rel', '')
            link_type = link.get('type', '')
            
            if rel == 'related' and 'rdap' in href.lower():
                link_info.append(f"相关RDAP服务器: {href}")
            elif rel == 'self':
                link_info.append(f"自身链接: {href}")
            elif rel == 'alternate' and link_type:
                link_info.append(f"备用链接({link_type}): {href}")
        
        if link_info:
            result_lines.extend(link_info)
    
    # 联系信息处理（全面增强版）
    contact_sections = []
    privacy_protected = False
    
    # 定义联系人类型映射
    contact_type_map = {
        'registrant': '注册人',
        'administrative': '管理联系人',
        'technical': '技术联系人',
        'billing': '计费联系人'
    }
    
    if 'entities' in rdap_data:
        for entity in rdap_data['entities']:
            roles = entity.get('roles', [])
            
            # 检查是否有隐私保护
            if 'remarks' in entity:
                for remark in entity['remarks']:
                    if 'REDACTED FOR PRIVACY' in remark.get('title', '') or 'REDACTED FOR PRIVACY' in remark.get('description', [''])[0]:
                        privacy_protected = True
                        break
            
            # 处理各种联系人类型
            for role in roles:
                if role in contact_type_map:
                    contact_info = []
                    contact_type = contact_type_map[role]
                    
                    if 'vcardArray' in entity:
                        vcard = entity['vcardArray'][1] if len(entity['vcardArray']) > 1 else []
                        vcard_data = {}
                        
                        # 解析vCard数据
                        for item in vcard:
                            if isinstance(item, list) and len(item) >= 4:
                                field_name = item[0]
                                value = item[3] if len(item) > 3 else ''
                                if value and str(value).strip():
                                    if field_name == 'fn':  # 全名
                                        vcard_data['name'] = value
                                    elif field_name == 'org':  # 组织
                                        vcard_data['org'] = value
                                    elif field_name == 'email':  # 邮箱
                                        vcard_data['email'] = value
                                    elif field_name == 'tel':  # 电话
                                        tel_value = value if isinstance(value, str) else str(value).replace('tel:', '')
                                        vcard_data['tel'] = tel_value
                                    elif field_name == 'adr':  # 地址
                                        if isinstance(value, list) and len(value) > 1:
                                            # 地址通常是数组格式，取有效部分
                                            addr_parts = [part for part in value if part and str(part).strip()]
                                            if addr_parts:
                                                vcard_data['address'] = ', '.join(addr_parts)
                                    elif field_name == 'url':  # 网址
                                        vcard_data['url'] = value
                        
                        # 构建联系信息显示
                        if vcard_data:
                            contact_line_parts = [contact_type]
                            if 'name' in vcard_data:
                                contact_line_parts.append(vcard_data['name'])
                            if 'org' in vcard_data:
                                contact_line_parts.append(f"({vcard_data['org']})")
                            
                            contact_info.append(': '.join([contact_line_parts[0], ' '.join(contact_line_parts[1:])] if len(contact_line_parts) > 1 else contact_line_parts))
                            
                            # 添加详细信息
                            if 'email' in vcard_data:
                                contact_info.append(f"  邮箱: {vcard_data['email']}")
                            if 'tel' in vcard_data:
                                contact_info.append(f"  电话: {vcard_data['tel']}")
                            if 'address' in vcard_data:
                                contact_info.append(f"  地址: {vcard_data['address']}")
                            if 'url' in vcard_data:
                                contact_info.append(f"  网址: {vcard_data['url']}")
                    
                    if contact_info:
                        contact_sections.extend(contact_info)
                        break  # 每种角色只处理第一个实体
    
    
    # 添加联系信息到结果
    if contact_sections:
        result_lines.extend(contact_sections)
    elif privacy_protected:
        result_lines.append("联系信息: 已启用隐私保护")
    
    return '\n'.join(result_lines)

def clean_whois_output(output: str) -> str:
    """清理和格式化传统WHOIS输出"""
    lines = output.split('\n')
    cleaned_lines = []
    
    # 过滤掉一些不必要的行
    skip_patterns = [
        r'^%',  # 注释行
        r'^#',  # 注释行
        r'^\s*$',  # 空行
        r'NOTICE:',  # 通知信息
        r'TERMS OF USE:',  # 使用条款
        r'>>>',  # 重定向信息
        r'Last update of',  # 最后更新信息
        r'For more information on Whois status codes',  # 状态码说明
        r'URL of the ICANN',  # ICANN相关信息
        r'Whois Server Version',  # 服务器版本信息
        r'Registrar WHOIS Server:',  # 注册商WHOIS服务器（通常重复）
        r'^\*\*\*',  # 星号分隔线
        r'^---',  # 横线分隔线
        r'^===',  # 等号分隔线
        r'The Registry database contains',  # 数据库说明
        r'Access to .* WHOIS information',  # 访问说明
        r'By submitting a WHOIS query',  # 提交说明
        r'The data contained in',  # 数据说明
        r'This information is provided for',  # 信息说明
        r'The compilation, repackaging',  # 编译说明
        r'Registrar URL:.*http',  # 注册商URL（通常很长）
    ]
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # 检查是否需要跳过这一行
        should_skip = False
        for pattern in skip_patterns:
            if re.match(pattern, line, re.IGNORECASE):
                should_skip = True
                break
        
        if not should_skip:
            cleaned_lines.append(line)
    
    # 限制输出长度，避免过长的响应
    if len(cleaned_lines) > 20:
        cleaned_lines = cleaned_lines[:20]
        cleaned_lines.append("... (输出已截断)")
    
    return '\n'.join(cleaned_lines)

async def query_iana_registry_info(domain: str) -> dict:
    """查询IANA Registry Information"""
    tld = get_tld(domain)
    if not tld:
        raise ValueError("无效的域名格式")
    
    iana_url = f"https://www.iana.org/domains/root/db/{tld}.html"
    
    # 上报访问IANA官方数据库
    logger.info(f"[IANA ACCESS] 正在访问IANA官方数据库: {iana_url}")
    
    if DEBUG_MODE:
        logger.info(f"[IANA DEBUG] 查询TLD: {tld}")
        logger.info(f"[IANA DEBUG] IANA URL: {iana_url}")
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(iana_url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if DEBUG_MODE:
                    logger.info(f"[IANA DEBUG] HTTP响应状态码: {response.status}")
                
                if response.status == 200:
                    html_content = await response.text()
                    if DEBUG_MODE:
                        logger.info(f"[IANA DEBUG] 获取到HTML内容，长度: {len(html_content)}")
                    
                    # 解析HTML获取Registry Information
                    soup = BeautifulSoup(html_content, 'html.parser')
                    
                    registry_info = {}
                    
                    # 查找Registry Information部分
                    registry_section = soup.find('h2', string='Registry Information')
                    if registry_section:
                        # 获取下一个兄弟元素（通常是包含信息的p标签）
                        info_element = registry_section.find_next_sibling('p')
                        if info_element:
                            # 查找Registration URL
                            reg_url_element = info_element.find('b', string='URL for registration services:')
                            if reg_url_element:
                                link_element = reg_url_element.find_next_sibling('a')
                                if link_element and link_element.get('href'):
                                    registry_info['registration_url'] = link_element.get('href')
                                    if DEBUG_MODE:
                                        logger.info(f"[IANA DEBUG] 找到Registration URL: {registry_info['registration_url']}")
                            
                            # 查找RDAP Server
                            rdap_element = info_element.find('b', string='RDAP Server: ')
                            if rdap_element:
                                # RDAP服务器地址通常在<b>标签后面的文本中
                                rdap_text = rdap_element.next_sibling
                                if rdap_text and isinstance(rdap_text, str):
                                    rdap_url = rdap_text.strip()
                                    if rdap_url:
                                        registry_info['rdap_server'] = rdap_url
                                        if DEBUG_MODE:
                                            logger.info(f"[IANA DEBUG] 找到RDAP服务器: {rdap_url}")
                            
                            # 查找WHOIS Server（如果存在）
                            whois_element = info_element.find('b', string='WHOIS Server:')
                            if whois_element:
                                whois_text = whois_element.next_sibling
                                if whois_text and isinstance(whois_text, str):
                                    whois_server = whois_text.strip()
                                    if whois_server:
                                        registry_info['whois_server'] = whois_server
                                        if DEBUG_MODE:
                                            logger.info(f"[IANA DEBUG] 找到WHOIS服务器: {whois_server}")
                    
                    # 查找日期信息
                    date_elements = soup.find_all('p')
                    for p in date_elements:
                        text = p.get_text()
                        if 'Record last updated' in text:
                            registry_info['last_updated'] = text.strip()
                        elif 'Registration date' in text:
                            registry_info['registration_date'] = text.strip()
                    
                    if DEBUG_MODE:
                        logger.info(f"[IANA DEBUG] 解析到的Registry Information: {registry_info}")
                    
                    return registry_info
                    
                elif response.status == 404:
                    if DEBUG_MODE:
                        logger.info(f"[IANA DEBUG] TLD {tld} 在IANA数据库中未找到")
                    raise ValueError(f"TLD .{tld} 在IANA数据库中未找到")
                else:
                    if DEBUG_MODE:
                        logger.error(f"[IANA DEBUG] HTTP错误状态码: {response.status}")
                    raise ValueError(f"访问IANA数据库失败，HTTP状态码: {response.status}")
                    
        except aiohttp.ClientError as e:
            if DEBUG_MODE:
                logger.error(f"[IANA DEBUG] 网络连接错误: {str(e)}")
            raise ValueError(f"访问IANA数据库网络错误: {str(e)}")
        except Exception as e:
            if DEBUG_MODE:
                logger.error(f"[IANA DEBUG] 解析IANA数据时发生错误: {str(e)}")
            raise ValueError(f"解析IANA数据失败: {str(e)}")

async def query_traditional_whois_with_server(query: str, whois_server: str) -> str:
    """使用指定WHOIS服务器查询"""
    try:
        # 上报传统WHOIS查询
        logger.info(f"[IANA ACCESS] 正在使用IANA指定的WHOIS服务器查询: {query}")
        logger.info(f"[IANA ACCESS] WHOIS服务器: {whois_server}")
        
        # 执行whois命令，指定服务器
        process = await asyncio.create_subprocess_exec(
            'whois',
            '-h', whois_server,
            query,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # 设置30秒超时
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=30.0
            )
        except asyncio.TimeoutError:
            raise ValueError("传统WHOIS查询超时")
        
        if process.returncode == 0:
            # 获取whois输出
            whois_output = stdout.decode('utf-8', errors='ignore')
            
            if not whois_output.strip():
                raise ValueError(f"未找到 {query} 的WHOIS信息")
            
            # 清理和格式化输出
            cleaned_output = clean_whois_output(whois_output)
            
            if not cleaned_output.strip():
                raise ValueError(f"未找到 {query} 的有效WHOIS信息")
            
            return cleaned_output
        else:
            # whois命令执行失败
            error_msg = stderr.decode('utf-8', errors='ignore').strip()
            if "No whois server is known" in error_msg:
                raise ValueError(f"不支持查询此类型的域名或IP: {query}")
            elif "No match" in error_msg or "No Found" in error_msg:
                raise ValueError(f"未找到 {query} 的WHOIS信息")
            else:
                raise ValueError(f"传统WHOIS查询失败: {error_msg}")
                
    except FileNotFoundError:
        raise ValueError("错误：未找到 whois 命令，请确保已安装 whois 工具")

async def query_traditional_whois(query: str) -> str:
    """使用传统WHOIS命令查询（自动选择服务器）"""
    try:
        # 上报传统WHOIS查询
        logger.info(f"[IANA ACCESS] 正在使用传统WHOIS协议查询: {query}")
        logger.info(f"[IANA ACCESS] WHOIS查询将通过系统默认WHOIS服务器进行")
        
        # 执行whois命令
        process = await asyncio.create_subprocess_exec(
            'whois',
            query,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # 设置30秒超时
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=30.0
            )
        except asyncio.TimeoutError:
            raise ValueError("传统WHOIS查询超时")
        
        if process.returncode == 0:
            # 获取whois输出
            whois_output = stdout.decode('utf-8', errors='ignore')
            
            if not whois_output.strip():
                raise ValueError(f"未找到 {query} 的WHOIS信息")
            
            # 清理和格式化输出
            cleaned_output = clean_whois_output(whois_output)
            
            if not cleaned_output.strip():
                raise ValueError(f"未找到 {query} 的有效WHOIS信息")
            
            return cleaned_output
        else:
            # whois命令执行失败
            error_msg = stderr.decode('utf-8', errors='ignore').strip()
            if "No whois server is known" in error_msg:
                raise ValueError(f"不支持查询此类型的域名或IP: {query}")
            elif "No match" in error_msg or "No Found" in error_msg:
                raise ValueError(f"未找到 {query} 的WHOIS信息")
            else:
                raise ValueError(f"传统WHOIS查询失败: {error_msg}")
                
    except FileNotFoundError:
        raise ValueError("错误：未找到 whois 命令，请确保已安装 whois 工具")

@cmd_whois.handle()
async def handle_whois(matcher: Matcher, event: MessageEvent, args: Message = CommandArg()):
    """处理WHOIS查询命令"""
    
    # 检查是否为严格的whois命令（防止whois1等触发）
    raw_message = str(event.get_message()).strip()
    if not (raw_message.startswith("whois ") or raw_message.startswith("/whois ") or 
            raw_message in ["域名查询", "whois查询"] or 
            raw_message.startswith("域名查询 ") or raw_message.startswith("whois查询 ")):
        return
    
    query = args.extract_plain_text().strip()
    if not query:
        await matcher.finish("请提供要查询的域名或IP地址\n\n使用方法：/whois example.com")
    
    # 清理输入，移除协议前缀
    query = re.sub(r'^https?://', '', query)
    query = re.sub(r'^www\.', '', query)
    query = query.split('/')[0]  # 移除路径部分
    
    # 验证输入格式
    if not (is_valid_domain(query) or is_valid_ip(query)):
        await matcher.finish(f"无效的域名或IP地址格式: {query}")
    
    # IP地址只能使用传统WHOIS查询
    if is_valid_ip(query):
        await matcher.send(f"正在查询 {query} 的WHOIS信息（传统协议），请稍候...")
        try:
            result = await query_traditional_whois(query)
            response_parts = [
                f"🔍 WHOIS查询结果: {query}",
                "📡 查询协议: 传统WHOIS",
                "" + "="*40,
                result
            ]
            response_msg = '\n'.join(response_parts)
            
            # 检查消息长度，避免过长
            if len(response_msg) > 4000:
                response_msg = response_msg[:4000] + "\n\n... (输出过长已截断)"
            
            await matcher.finish(response_msg)
        except ValueError as e:
            await matcher.finish(str(e))
        except Exception as e:
            if "FinishedException" not in str(type(e)):
                await matcher.finish(f"查询过程中发生错误: {str(e)}")
        return
    
    # 对于域名，首先查询IANA Registry Information获取权威服务器信息
    iana_info = None
    try:
        if DEBUG_MODE:
            logger.info(f"[WHOIS DEBUG] 开始查询IANA Registry Information...")
        iana_info = await query_iana_registry_info(query)
        if DEBUG_MODE:
            logger.info(f"[WHOIS DEBUG] IANA Registry Information查询成功")
    except Exception as e:
        if DEBUG_MODE:
            logger.error(f"[WHOIS DEBUG] IANA Registry Information查询失败: {str(e)}")
        await matcher.finish(f"无法获取域名 {query} 的IANA Registry Information: {str(e)}\n\n请检查网络连接或域名格式是否正确。")
        return
    
    # 根据IANA信息智能决定查询方式
    use_rdap = False
    rdap_server = None
    whois_server = None
    
    if iana_info:
        if 'whois_server' in iana_info:
            whois_server = iana_info['whois_server']
        if 'rdap_server' in iana_info:
            rdap_server = iana_info['rdap_server']
            use_rdap = True
            if DEBUG_MODE:
                logger.info(f"[WHOIS DEBUG] 从IANA获取到RDAP服务器: {rdap_server}")
        else:
            # IANA没有提供RDAP服务器，说明该TLD不支持RDAP
            if DEBUG_MODE:
                logger.info(f"[WHOIS DEBUG] IANA未提供RDAP服务器，该TLD不支持RDAP协议")
    
    # 如果IANA没有提供RDAP信息，则不使用RDAP
    # 移除硬编码依赖，完全依赖IANA数据库
    
    # 如果找到了RDAP服务器，优先使用RDAP查询
    if use_rdap and rdap_server:
        if DEBUG_MODE:
            logger.info(f"[WHOIS DEBUG] 域名 {query} 将使用RDAP查询，服务器: {rdap_server}")
        await matcher.send(f"正在查询 {query} 的WHOIS信息（RDAP协议），请稍候...")
        try:
            # 尝试RDAP查询
            if DEBUG_MODE:
                logger.info(f"[WHOIS DEBUG] 开始RDAP查询...")
            # 使用IANA提供的RDAP服务器或硬编码服务器
            rdap_data = await query_rdap(query, rdap_server)
            if DEBUG_MODE:
                logger.info(f"[WHOIS DEBUG] RDAP查询成功")
            formatted_result = format_rdap_response(rdap_data, query)
            
            response_parts = [
                f"🔍 {query}"
            ]
            
            response_parts.append(formatted_result)
            response_msg = '\n'.join(response_parts)
            
            # 检查消息长度，避免过长
            if len(response_msg) > 4000:
                response_msg = response_msg[:4000] + "\n\n... (输出过长已截断)"
            
            await matcher.finish(response_msg)
            
        except ValueError as e:
            # RDAP查询失败，回退到传统WHOIS
            if DEBUG_MODE:
                logger.error(f"[WHOIS DEBUG] RDAP查询失败: {str(e)}")
            await matcher.send(f"RDAP查询失败，正在尝试传统WHOIS查询...")
            try:
                if DEBUG_MODE:
                    logger.info(f"[WHOIS DEBUG] 开始传统WHOIS查询...")
                result = await query_traditional_whois(query)
                response_parts = [
                    f"🔍 {query}"
                ]
                
                response_parts.append(result)
                response_msg = '\n'.join(response_parts)
                
                # 检查消息长度，避免过长
                if len(response_msg) > 4000:
                    response_msg = response_msg[:4000] + "\n\n... (输出过长已截断)"
                
                await matcher.finish(response_msg)
            except ValueError as fallback_e:
                await matcher.finish(f"RDAP查询失败: {str(e)}\n传统WHOIS查询也失败: {str(fallback_e)}")
            except Exception as fallback_e:
                if "FinishedException" not in str(type(fallback_e)):
                    await matcher.finish(f"查询过程中发生错误: {str(fallback_e)}")
        except Exception as e:
            if "FinishedException" not in str(type(e)):
                await matcher.finish(f"查询过程中发生错误: {str(e)}")
    else:
        # 使用传统WHOIS查询
        tld = get_tld(query)
        if DEBUG_MODE:
            logger.info(f"[WHOIS DEBUG] 域名 {query} 使用传统WHOIS查询，TLD: {tld}")
            if whois_server:
                logger.info(f"[WHOIS DEBUG] 使用IANA指定的WHOIS服务器: {whois_server}")
        
        await matcher.send(f"正在查询 {query} 的WHOIS信息（传统WHOIS协议），请稍候...")
        
        try:
            if DEBUG_MODE:
                logger.info(f"[WHOIS DEBUG] 开始传统WHOIS查询...")
            # 如果IANA提供了特定的WHOIS服务器，优先使用
            if whois_server:
                result = await query_traditional_whois_with_server(query, whois_server)
            else:
                result = await query_traditional_whois(query)
            response_parts = [
                f"🔍 {query}"
            ]
            
            response_parts.append(result)
            
            # 移除IANA信息显示以精简输出
            # if iana_info:
            #     response_parts.append("\n📋 IANA Registry Information")
            #     if 'registration_url' in iana_info:
            #         response_parts.append(f"  🔗 注册服务URL: `{iana_info['registration_url']}`")
            #     if 'rdap_server' in iana_info:
            #         response_parts.append(f"  🌐 RDAP服务器: `{iana_info['rdap_server']}`")
            #     if 'whois_server' in iana_info:
            #         response_parts.append(f"  📡 WHOIS服务器: `{iana_info['whois_server']}`")
            #     if 'last_updated' in iana_info:
            #         response_parts.append(f"  📅 {iana_info['last_updated']}")
            #     if 'registration_date' in iana_info:
            #         response_parts.append(f"  📅 {iana_info['registration_date']}")
            
            response_parts.append(result)
            response_msg = '\n'.join(response_parts)
            
            # 检查消息长度，避免过长
            if len(response_msg) > 4000:
                response_msg = response_msg[:4000] + "\n\n... (输出过长已截断)"
            
            await matcher.finish(response_msg)
        except ValueError as e:
            await matcher.finish(str(e))
        except Exception as e:
            if "FinishedException" not in str(type(e)):
                await matcher.finish(f"查询过程中发生错误: {str(e)}")