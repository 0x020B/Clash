#!python3
# -*- coding: UTF-8 -*-
# vim: fdm=marker
from __future__ import absolute_import

from functools import reduce
from ipaddress import ip_address
from math import log
from os import sched_getaffinity
from os.path import isfile
from socket import gaierror, gethostbyname
from threading import Thread, Semaphore
from threading import enumerate as enum

from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError
from requests import get
from ruamel.yaml import YAML
from scapy.layers.inet import ICMP
from scapy.layers.inet import IP as IPv4
from scapy.layers.inet import TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import sr1

# {{{ 初始环境
yaml = YAML()
count = len(sched_getaffinity(0)) * 2
tcp, udp, http, socks5, ss, ssr, vmess, trojan, snell = (
    {'proxies': []} for _ in range(9))
flags = {'AD': '🇦🇩', 'AE': '🇦🇪', 'AF': '🇦🇫', 'AG': '🇦🇬', 'AI': '🇦🇮',
         'AL': '🇦🇱', 'AM': '🇦🇲', 'AO': '🇦🇴', 'AQ': '🇦🇶', 'AR': '🇦🇷',
         'AS': '🇦🇸', 'AT': '🇦🇹', 'AU': '🇦🇺', 'AW': '🇦🇼', 'AX': '🇦🇽',
         'AZ': '🇦🇿', 'BA': '🇧🇦', 'BB': '🇧🇧', 'BD': '🇧🇩', 'BE': '🇧🇪',
         'BF': '🇧🇫', 'BG': '🇧🇬', 'BH': '🇧🇭', 'BI': '🇧🇮', 'BJ': '🇧🇯',
         'BL': '🇧🇱', 'BM': '🇧🇲', 'BN': '🇧🇳', 'BO': '🇧🇴', 'BQ': '🇧🇶',
         'BR': '🇧🇷', 'BS': '🇧🇸', 'BT': '🇧🇹', 'BV': '🇧🇻', 'BW': '🇧🇼',
         'BY': '🇧🇾', 'BZ': '🇧🇿', 'CA': '🇨🇦', 'CC': '🇨🇨', 'CD': '🇨🇩',
         'CF': '🇨🇫', 'CG': '🇨🇬', 'CH': '🇨🇭', 'CI': '🇨🇮', 'CK': '🇨🇰',
         'CL': '🇨🇱', 'CM': '🇨🇲', 'CN': '🇨🇳', 'CO': '🇨🇴', 'CR': '🇨🇷',
         'CU': '🇨🇺', 'CV': '🇨🇻', 'CW': '🇨🇼', 'CX': '🇨🇽', 'CY': '🇨🇾',
         'CZ': '🇨🇿', 'DE': '🇩🇪', 'DJ': '🇩🇯', 'DK': '🇩🇰', 'DM': '🇩🇲',
         'DO': '🇩🇴', 'DZ': '🇩🇿', 'EC': '🇪🇨', 'EE': '🇪🇪', 'EG': '🇪🇬',
         'EH': '🇪🇭', 'ER': '🇪🇷', 'ES': '🇪🇸', 'ET': '🇪🇹', 'EU': '🇪🇺',
         'FI': '🇫🇮', 'FJ': '🇫🇯', 'FK': '🇫🇰', 'FM': '🇫🇲', 'FO': '🇫🇴',
         'FR': '🇫🇷', 'GA': '🇬🇦', 'GB': '🇬🇧', 'GD': '🇬🇩', 'GE': '🇬🇪',
         'GF': '🇬🇫', 'GG': '🇬🇬', 'GH': '🇬🇭', 'GI': '🇬🇮', 'GL': '🇬🇱',
         'GM': '🇬🇲', 'GN': '🇬🇳', 'GP': '🇬🇵', 'GQ': '🇬🇶', 'GR': '🇬🇷',
         'GS': '🇬🇸', 'GT': '🇬🇹', 'GU': '🇬🇺', 'GW': '🇬🇼', 'GY': '🇬🇾',
         'HK': '🇭🇰', 'HM': '🇭🇲', 'HN': '🇭🇳', 'HR': '🇭🇷', 'HT': '🇭🇹',
         'HU': '🇭🇺', 'ID': '🇮🇩', 'IE': '🇮🇪', 'IL': '🇮🇱', 'IM': '🇮🇲',
         'IN': '🇮🇳', 'IO': '🇮🇴', 'IQ': '🇮🇶', 'IR': '🇮🇷', 'IS': '🇮🇸',
         'IT': '🇮🇹', 'JE': '🇯🇪', 'JM': '🇯🇲', 'JO': '🇯🇴', 'JP': '🇯🇵',
         'KE': '🇰🇪', 'KG': '🇰🇬', 'KH': '🇰🇭', 'KI': '🇰🇮', 'KM': '🇰🇲',
         'KN': '🇰🇳', 'KP': '🇰🇵', 'KR': '🇰🇷', 'KW': '🇰🇼', 'KY': '🇰🇾',
         'KZ': '🇰🇿', 'LA': '🇱🇦', 'LB': '🇱🇧', 'LC': '🇱🇨', 'LI': '🇱🇮',
         'LK': '🇱🇰', 'LR': '🇱🇷', 'LS': '🇱🇸', 'LT': '🇱🇹', 'LU': '🇱🇺',
         'LV': '🇱🇻', 'LY': '🇱🇾', 'MA': '🇲🇦', 'MC': '🇲🇨', 'MD': '🇲🇩',
         'ME': '🇲🇪', 'MF': '🇲🇫', 'MG': '🇲🇬', 'MH': '🇲🇭', 'MK': '🇲🇰',
         'ML': '🇲🇱', 'MM': '🇲🇲', 'MN': '🇲🇳', 'MO': '🇲🇴', 'MP': '🇲🇵',
         'MQ': '🇲🇶', 'MR': '🇲🇷', 'MS': '🇲🇸', 'MT': '🇲🇹', 'MU': '🇲🇺',
         'MV': '🇲🇻', 'MW': '🇲🇼', 'MX': '🇲🇽', 'MY': '🇲🇾', 'MZ': '🇲🇿',
         'NA': '🇳🇦', 'NC': '🇳🇨', 'NE': '🇳🇪', 'NF': '🇳🇫', 'NG': '🇳🇬',
         'NI': '🇳🇮', 'NL': '🇳🇱', 'NO': '🇳🇴', 'NP': '🇳🇵', 'NR': '🇳🇷',
         'NU': '🇳🇺', 'NZ': '🇳🇿', 'OM': '🇴🇲', 'PA': '🇵🇦', 'PE': '🇵🇪',
         'PF': '🇵🇫', 'PG': '🇵🇬', 'PH': '🇵🇭', 'PK': '🇵🇰', 'PL': '🇵🇱',
         'PM': '🇵🇲', 'PN': '🇵🇳', 'PR': '🇵🇷', 'PS': '🇵🇸', 'PT': '🇵🇹',
         'PW': '🇵🇼', 'PY': '🇵🇾', 'QA': '🇶🇦', 'RE': '🇷🇪', 'RO': '🇷🇴',
         'RS': '🇷🇸', 'RU': '🇷🇺', 'RW': '🇷🇼', 'SA': '🇸🇦', 'SB': '🇸🇧',
         'SC': '🇸🇨', 'SD': '🇸🇩', 'SE': '🇸🇪', 'SG': '🇸🇬', 'SH': '🇸🇭',
         'SI': '🇸🇮', 'SJ': '🇸🇯', 'SK': '🇸🇰', 'SL': '🇸🇱', 'SM': '🇸🇲',
         'SN': '🇸🇳', 'SO': '🇸🇴', 'SR': '🇸🇷', 'SS': '🇸🇸', 'ST': '🇸🇹',
         'SV': '🇸🇻', 'SX': '🇸🇽', 'SY': '🇸🇾', 'SZ': '🇸🇿', 'TC': '🇹🇨',
         'TD': '🇹🇩', 'TF': '🇹🇫', 'TG': '🇹🇬', 'TH': '🇹🇭', 'TJ': '🇹🇯',
         'TK': '🇹🇰', 'TL': '🇹🇱', 'TM': '🇹🇲', 'TN': '🇹🇳', 'TO': '🇹🇴',
         'TR': '🇹🇷', 'TT': '🇹🇹', 'TV': '🇹🇻', 'TW': '🇹🇼', 'TZ': '🇹🇿',
         'UA': '🇺🇦', 'UG': '🇺🇬', 'UM': '🇺🇲', 'US': '🇺🇸', 'UY': '🇺🇾',
         'UZ': '🇺🇿', 'VA': '🇻🇦', 'VC': '🇻🇨', 'VE': '🇻🇪', 'VG': '🇻🇬',
         'VI': '🇻🇮', 'VN': '🇻🇳', 'VU': '🇻🇺', 'WF': '🇼🇫', 'WS': '🇼🇸',
         'XK': '🇽🇰', 'YE': '🇾🇪', 'YT': '🇾🇹', 'ZA': '🇿🇦', 'ZM': '🇿🇲',
         'ZW': '🇿🇼', 'RELiAY': '🏁', 'NOWHERE': '🇦🇶'}
geo = {i: [] for i in flags}
if not isfile('Country.mmdb'):
    with open('Country.mmdb', 'wb') as f:
        for chunk in get('https://fastly.jsdelivr.net/gh/'
                         'Dreamacro/maxmind-geoip@release'
                         '/Country.mmdb').iter_content(1024):
            f.write(chunk)
config = yaml.load(open('default.config'))
config['proxy-providers'] = {}


def add_provider(provider):
    config['proxy-providers'] |= {
        f'{provider}-provider': {
            'type': 'file',
            'interval': 3600,
            'path': './{}.yaml'.format(provider),
            'health-check': {
                'enable': True,
                'interval': 300,
                'url': 'http://www.gstatic.com/generate_204'
            }
        }
    }


def add_group(group):
    config['proxy-groups'].extend(({
        'name': '{}-url-test'.format(group),
        'type': 'url-test',
        'use': [
            '{}-provider'.format(group)
        ],
        'url': 'http://www.gstatic.com/generate_204',
        'interval': 300
    },
        {
        'name': '{}-fallback'.format(group),
        'type': 'fallback',
        'proxies': [
            '{}-url-test'.format(group),
            'proxy'
        ],
        'url': 'http://www.gstatic.com/generate_204',
        'interval': 300
    },
        {
        'name': group,
        'type': 'relay',
        'proxies': [
            'proxy',
            '{}-fallback'.format(group)
        ]
    }))

# }}}
# {{{ 节点测试


def test(_proxy):
    # 去掉未加密或使用不安全加密方式的节点
    if _proxy['type'] != 'trojan' and _proxy['cipher'] in (
            'none', 'rc4', 'rc4-md5', 'aes-128-cfb'):
        return None

    # 读取节点IP地址
    server = _proxy['server']
    try:
        ip = ip_address(server)
    except ValueError:
        try:
            ip = ip_address(gethostbyname(server))
        except gaierror:
            return None
    ip = ip.exploded
    
    # 分析节点IP属地
    with Reader('Country.mmdb') as ip_reader:
        try:
            code = ip_reader.country(ip).country.iso_code
        except (AddressNotFoundError, ValueError):
            return None
    if code in ('CLOUDFLARE', 'PRIVATE'):
        code = 'RELAY'
    if code not in flags:
        code = 'NOWHERE'
    _proxy['name'] = (f'{flags[code]}{ip}-'
                      f'{proxys.index(proxy):0>{length}}')

    # 存活测试
    _ip = globals()[f'IPv{ip_address(ip).version}'](dst=ip)
    _port = _proxy['port']
    if (sr1(_ip / ICMP(), timeout=3) or
        sr1(_ip / TCP(dport=_port, flags="S"), timeout=3) or
        sr1(_ip / UDP(dport=_port), timeout=3)):
        
        # 节点分类
        globals()[proxy['type']]['proxies'].append(_proxy)
        _proxy.get('udp') and udp['proxies'].append(_proxy)
        tcp['proxies'].append(_proxy)
        geo[code].append(_proxy)
    return None


# }}}
# {{{ 获取订阅
with open('urls.txt') as f:
    urls = f.read().split()
proxys = [[]]
for url in urls:
    r = get(url)
    if r.status_code != 200:
        continue
    info = r.text
    if isinstance(proxies := yaml.load(info), dict):
        for proxy in proxies['proxies']:
            proxy.pop('name', None)
            proxy.pop('country', None)
            proxys.append(proxy)
# }}}
# {{{ 节点去重
proxys = reduce(lambda x, y: x if y in x else x + [y], proxys)
#proxys.sort(key=lambda proxy: proxy['server'])
length = int(log(len(proxys), 10)) + 1
# }}}
# {{{ 线程调度
with Semaphore(count):
    for proxy in proxys:
        Thread(target=test, args=[proxy]).start()
for thread in enum()[1:]:
    thread.join()
# }}}
# {{{ 配置写入
yaml.indent(2, 4, 2)
for protocol in ('tcp', 'udp', 'http', 'socks5', 'ss',
                 'ssr', 'vmess', 'trojan', 'snell'):
    if locals()[protocol]['proxies']:
        yaml.dump(locals()[protocol], open(protocol + '.yaml', 'w'))
        add_provider(protocol)
for code in geo:
    if geo[code]:
        yaml.dump({'proxies': geo[code]}, open(code + '.yaml', 'w'))
        # 优先使用目标服务器所在国家/地区的节点
        add_provider(code)
        add_group(code)
        config['rules'].append(f'GEOIP,{code},{code}')
config['rules'].append('MATCH,proxy')
yaml.dump(config, open('config.yaml', 'w'))
# }}}
