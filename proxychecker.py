"""
Copyright (C) 2024 Arseniy Astankov

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

import socket
import ssl
import argparse
import logging
import concurrent.futures
from enum import Enum
from collections.abc import Iterator

class ProxyType(Enum):
    HTTP = 1
    HTTPS = 2
    SOCKS4 = 3
    SOCKS5 = 4

PROTOCOLS = {
    ProxyType.HTTP: 'http',
    ProxyType.HTTPS: 'https',
    ProxyType.SOCKS4: 'socks4',
    ProxyType.SOCKS5: 'socks5'
}

def parse_line(line: str) -> tuple[ProxyType, str, int]:
    line = line.strip().split(':')
    line[1] = line[1].strip('//')
    return (PROTOCOLS.keys()[PROTOCOLS.values().index(line[0])], line[1], int(line[2]))

def delete_comments(line: str) -> str:
    index = line.find('#')
    if index != -1:
        return line[:index]
    else:
        return line

def parse_file(file_path: str, proxy_type: ProxyType) -> Iterator[tuple[ProxyType, str, int]]:
    try:
        with open(file_path, 'r') as f:
                for i, line in enumerate(f):
                    try:
                        line = delete_comments(line).strip()
                        if not line:
                            continue
                        if proxy_type:
                            line = line.split(':')
                            yield (proxy_type, line[0], int(line[1]))
                        else:
                            yield parse_line(line)
                    except Exception as err:
                        logger.warning(f"While processing file {file_path}, line {i+1}, an exception occured => {err}. Skipping line...")
    except Exception as exc:
        logger.warning(f"While opening file {file_path}, an exception occured => {exc}. Skipping file...")

# ssl context with default settings (i.e. safe)
ssl_context = ssl.create_default_context()
# ssl context without checking cert (cause we don't care about mitm attacks in double-encrypted channels)
ssl_context_no_check = ssl.create_default_context()
ssl_context_no_check.check_hostname = False
ssl_context_no_check.verify_mode = ssl.CERT_NONE

""" debug
ssl_context.keylog_filename = "./keylog"
ssl_context_no_check.keylog_filename = "./keylognc"
"""

host2check = {
    'hostname': 'example.com',
    'ip': '',
    'iph': ''
}
host2check['ip'] = socket.gethostbyname(host2check['hostname'])
host2check['iph'] = "".join([f'{int(q):02x}' for q in host2check['ip'].split('.')])

useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

def check_proxy(proxy: tuple[ProxyType, str, int]) -> bool:
    try:
        match proxy[0]:
            case ProxyType.HTTP:
                with socket.create_connection((proxy[1], proxy[2])) as sock:
                    sock.sendall("CONNECT {0}:443 HTTP/1.1\r\nHost: {0}:443\r\nUser-Agent: {1}\r\nProxy-Connection: Keep-Alive\r\n\r\n".format(host2check['ip'], useragent).encode())
                    buff = sock.recv(16384)
                    if not buff.startswith(b"HTTP/1.1 200"):
                        raise Exception("answer is not 200 ok")
                    with ssl_context.wrap_socket(sock, server_hostname=host2check['hostname']) as ssock:
                        ssock.sendall("GET / HTTP/1.1\r\nHost: {0}\r\nUser-Agent: {1}\r\nAccept: */*\r\n\r\n".format(host2check['hostname'], useragent).encode())
                        buff = ssock.recv(16384)
                        if not buff:
                            raise Exception("something is wrong in tls tunnel")
                        logger.info(f"{proxy} is good")
                        return True
            case ProxyType.HTTPS:
                with socket.create_connection((proxy[1], proxy[2])) as sock:
                    with ssl_context_no_check.wrap_socket(sock, server_hostname=proxy[1]) as ssock:
                        ssock.sendall("CONNECT {0}:443 HTTP/1.1\r\nHost: {0}:443\r\nUser-Agent: {1}\r\nProxy-Connection: Keep-Alive\r\n\r\n".format(host2check['ip'], useragent).encode())
                        buff = ssock.recv(16384)
                        if not buff.startswith(b"HTTP/1.1 200"):
                            raise Exception("answer is not 200 ok")
                        with ssl_context.wrap_socket(ssock, server_hostname=host2check['hostname']) as sssock:
                            sssock.sendall("GET / HTTP/1.1\r\nHost: {0}\r\nUser-Agent: {1}\r\nAccept: */*\r\n\r\n".format(host2check['hostname'], useragent).encode())
                            buff = sssock.recv(16384)
                            if not buff:
                                raise Exception("something is wrong in tls tunnel")
                            logger.info(f"{proxy} is good")
                            return True
            case ProxyType.SOCKS4:
                with socket.create_connection((proxy[1], proxy[2])) as sock:
                    sock.sendall(bytes.fromhex('040101bb' + host2check['iph'] + '00'))
                    buff = sock.recv(16384)
                    if buff != bytes.fromhex('005a000000000000'):
                        raise Exception("answer is not correct")
                    with ssl_context.wrap_socket(sock, server_hostname=host2check['hostname']) as ssock:
                        ssock.sendall("GET / HTTP/1.1\r\nHost: {0}\r\nUser-Agent: {1}\r\nAccept: */*\r\n\r\n".format(host2check['hostname'], useragent).encode())
                        buff = ssock.recv(16384)
                        if not buff:
                            raise Exception("something is wrong in tls tunnel")
                        logger.info(f"{proxy} is good")
                        return True
            case ProxyType.SOCKS5:
                with socket.create_connection((proxy[1], proxy[2])) as sock:
                    sock.sendall(bytes.fromhex('050100'))
                    buff = sock.recv(16384)
                    if buff != bytes.fromhex('0500'):
                        raise Exception("answer is not correct (stage 1)")
                    sock.sendall(bytes.fromhex('05010001' + host2check['iph'] + '01bb'))
                    buff = sock.recv(16384)
                    if buff != bytes.fromhex('05000001000000000000'):
                        raise Exception("answer is not correct (stage 2)")
                    with ssl_context.wrap_socket(sock, server_hostname=host2check['hostname']) as ssock:
                        ssock.sendall("GET / HTTP/1.1\r\nHost: {0}\r\nUser-Agent: {1}\r\nAccept: */*\r\n\r\n".format(host2check['hostname'], useragent).encode())
                        buff = ssock.recv(16384)
                        if not buff:
                            raise Exception("something is wrong in tls tunnel")
                        logger.info(f"{proxy} is good")
                        return True
    except Exception as exc:
        logger.info(f"{proxy} is bad, reason => {exc}")
        return False

def main():
    parser = argparse.ArgumentParser(description='check proxies')

    parser.add_argument('-X', '--proxy-file', nargs='+', help='file(s) with all types of proxies (must be specified as http:// or socks4:// etc.)')

    parser.add_argument('-Xh', '--http-file', nargs='+', help='file(s) with http proxies')
    parser.add_argument('-Xs', '--https-file', nargs='+', help='file(s) with https proxies')
    parser.add_argument('-X4', '--socks4-file', nargs='+', help='file(s) with socks4 proxies')
    parser.add_argument('-X5', '--socks5-file', nargs='+', help='file(s) with socks5 proxies')

    parser.add_argument('-P', '--proxy', nargs='+', help='prox(y/ies) to check (must be specified as http:// or socks4:// etc.)')

    parser.add_argument('-Ph', '--http', nargs='+', help='http proxies')
    parser.add_argument('-Ps', '--https', nargs='+', help='https proxies')
    parser.add_argument('-P4', '--socks4', nargs='+', help='socks4 proxies')
    parser.add_argument('-P5', '--socks5', nargs='+', help='socks5 proxies')

    parser.add_argument('-b', '--blacklist', nargs=1, help='proxies from this list will not be checked')

    parser.add_argument('-t', '--threads', nargs=1, type=int, default=25)

    args = parser.parse_args()

    global logger
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    proxies_set = set()

    for ptype, plist in [(None, args.proxy_file or []),
                     (ProxyType.HTTP, args.http_file or []),
                     (ProxyType.HTTPS, args.https_file or []),
                     (ProxyType.SOCKS4, args.socks4_file or []),
                     (ProxyType.SOCKS5, args.socks5_file or [])]:
        for p in plist:
            proxies_set.update(parse_file(p, ptype))

    protoarg = {
        None: '',
        ProxyType.HTTP: 'h',
        ProxyType.HTTPS: 's',
        ProxyType.SOCKS4: '4',
        ProxyType.SOCKS5: '5'
    }

    for ptype, plist in [(None, args.proxy or []),
                     (ProxyType.HTTP, args.http or []),
                     (ProxyType.HTTPS, args.https or []),
                     (ProxyType.SOCKS4, args.socks4 or []),
                     (ProxyType.SOCKS5, args.socks5 or [])]:
        for i, p in enumerate(plist):
            try:
                if ptype == None:
                    proxies_set.add(parse_line(p))
                else:
                    a = p.strip().split(':')
                    proxies_set.add((ptype, a[0], int(a[1])))
            except Exception as err:
                logger.warning(f"While processing {i} -P{protoarg[ptype]} arg, an exception occured => {err}. Skipping arg...")

    if args.blacklist:
        for el in parse_file(args.blacklist, None):
            proxies_set.discard(el)

    if len(proxies_set) == 0:
        logger.critical("There are no proxies to be checked. Exiting...")
        exit(1)

    socket.setdefaulttimeout(20)

    proxies_set = list(proxies_set)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = list(executor.map(check_proxy, proxies_set))

    fnames = {
        'all': './good_proxy.txt',
        ProxyType.HTTP: './good_http.txt',
        ProxyType.HTTPS: './good_https.txt',
        ProxyType.SOCKS4: './good_socks4.txt',
        ProxyType.SOCKS5: './good_socks5.txt',
        'bad': './bad_proxy.txt'
    }

    fds = {
        'all': None,
        ProxyType.HTTP: None,
        ProxyType.HTTPS: None,
        ProxyType.SOCKS4: None,
        ProxyType.SOCKS5: None,
        'bad': None
    }

    for prox, good in zip(proxies_set, results):
        if good:
            # writing to all first
            if fds['all'] == None:
                fds['all'] = open(fnames['all'], "a")
            print(PROTOCOLS[prox[0]] + '://' + prox[1] + ":" + str(prox[2]), file=fds['all'])
            # writing to proto file
            if fds[prox[0]] == None:
                fds[prox[0]] = open(fnames[prox[0]], "a")
            print(prox[1] + ":" + str(prox[2]), file=fds[prox[0]])
        else:
            if fds['bad'] == None:
                fds['bad'] = open(fnames['bad'], "a")
            print(PROTOCOLS[prox[0]] + '://' + prox[1] + ":" + str(prox[2]), file=fds['bad'])

    for fd in fds.values():
        if fd != None: fd.close()
        
if __name__ == "__main__":
    main()