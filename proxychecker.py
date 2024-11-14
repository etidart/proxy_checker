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

class proxy_type(Enum):
    HTTP = 1
    HTTPS = 2
    SOCKS4 = 3
    SOCKS5 = 4
    CONNECT = 5

context = ssl.create_default_context()
context_no_check = ssl.create_default_context()
context_no_check.check_hostname = False
context_no_check.verify_mode = ssl.CERT_NONE

def check_proxy(proxy: tuple[proxy_type, str, int]) -> bool:
    try:
        match proxy[0]:
            case proxy_type.HTTP:
                with socket.create_connection((proxy[1], proxy[2])) as sock:
                    sock.sendall(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nProxy-Connection: Keep-Alive\r\n\r\n")
                    buff = sock.recv(16384)
                    if not buff.startswith(b"HTTP/1.1 200"):
                        raise Exception("answer is not 200 ok")
                    logger.info(f"{proxy} is good")
                    return True
                """ # some http proxies may work also as connect proxies, so let's check that
                with socket.create_connection((proxy[1], proxy[2])) as sock:
                    sock.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: curl/8.10.0\r\nProxy-Connection: Keep-Alive\r\n\r\n")
                    buff = sock.recv(16384)
                    if not buff.startswith(b"HTTP/1.1 200"):
                        return True
                    with context.wrap_socket(sock, server_hostname="example.com") as ssock:
                        ssock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.10.0\r\nAccept: */*\r\n\r\n")
                        buff = ssock.recv(16384)
                        if not buff:
                            return True
                        logger.info(f"{proxy} is good for CONNECT too") """
            case proxy_type.HTTPS:
                with socket.create_connection((proxy[1], proxy[2])) as sock:
                    with context_no_check.wrap_socket(sock, server_hostname=proxy[1]) as ssock:
                        ssock.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: curl/8.10.0\r\nProxy-Connection: Keep-Alive\r\n\r\n")
                        buff = ssock.recv(16384)
                        if not buff.startswith(b"HTTP/1.1 200"):
                            raise Exception("answer is not 200 ok")
                        with context.wrap_socket(ssock, server_hostname="example.com") as sssock:
                            sssock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.10.0\r\nAccept: */*\r\n\r\n")
                            buff = sssock.recv(16384)
                            if not buff:
                                raise Exception("something is wrong in tls tunnel")
                            logger.info(f"{proxy} is good")
                            return True
            case proxy_type.SOCKS4:
                with socket.create_connection((proxy[1], proxy[2])) as sock:
                    sock.sendall(bytes.fromhex('040101bb5db8d70e00'))
                    buff = sock.recv(16384)
                    if buff != bytes.fromhex('005a000000000000'):
                        raise Exception("answer is not correct")
                    with context.wrap_socket(sock, server_hostname="example.com") as ssock:
                        ssock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.10.0\r\nAccept: */*\r\n\r\n")
                        buff = ssock.recv(16384)
                        if not buff:
                            raise Exception("something is wrong in tls tunnel")
                        logger.info(f"{proxy} is good")
                        return True
            case proxy_type.SOCKS5:
                with socket.create_connection((proxy[1], proxy[2])) as sock:
                    sock.sendall(bytes.fromhex('050100'))
                    buff = sock.recv(16384)
                    if buff != bytes.fromhex('0500'):
                        raise Exception("answer is not correct")
                    sock.sendall(bytes.fromhex('050100015db8d70ebb01'))
                    buff = sock.recv(16384)
                    if buff != bytes.fromhex('050000015db8d70ebb01'):
                        raise Exception("answer is not correct")
                    with context.wrap_socket(sock, server_hostname="example.com") as ssock:
                        ssock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.10.0\r\nAccept: */*\r\n\r\n")
                        buff = ssock.recv(16384)
                        if not buff:
                            raise Exception("something is wrong in tls tunnel")
                        logger.info(f"{proxy} is good")
                        return True
            case proxy_type.CONNECT:
                with socket.create_connection((proxy[1], proxy[2])) as sock:
                    sock.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: curl/8.10.0\r\nProxy-Connection: Keep-Alive\r\n\r\n")
                    buff = sock.recv(16384)
                    if not buff.startswith(b"HTTP/1.1 200"):
                        raise Exception("answer is not 200 ok")
                    with context.wrap_socket(sock, server_hostname="example.com") as ssock:
                        ssock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.10.0\r\nAccept: */*\r\n\r\n")
                        buff = ssock.recv(16384)
                        if not buff:
                            raise Exception("something is wrong in tls tunnel")
                        logger.info(f"{proxy} is good")
                        return True
    except Exception as exc:
        logger.info(f"{proxy} is bad, reason => {exc=}")
        return False

def delete_comments(line: str) -> str:
    index = line.find('#')
    if index != -1:
        return line[:index]
    else:
        return line

def main():
    parser = argparse.ArgumentParser(description='check proxies')

    parser.add_argument('-X', '--proxy-file', nargs='+', help='file(s) with all types of proxies (must be specified as http:// or socks4:// etc.)')

    parser.add_argument('-Xh', '--http-file', nargs='+', help='file(s) with http proxies')
    parser.add_argument('-Xs', '--https-file', nargs='+', help='file(s) with https proxies')
    parser.add_argument('-X4', '--socks4-file', nargs='+', help='file(s) with socks4 proxies')
    parser.add_argument('-X5', '--socks5-file', nargs='+', help='file(s) with socks5 proxies')
    parser.add_argument('-Xc', '--connect-file', nargs='+', help='file(s) with connect proxies')

    parser.add_argument('-P', '--proxy', nargs='+', help='prox(y/ies) to check (must be specified as http:// or socks4:// etc.)')

    parser.add_argument('-Ph', '--http', nargs='+', help='http proxies')
    parser.add_argument('-Ps', '--https', nargs='+', help='https proxies')
    parser.add_argument('-P4', '--socks4', nargs='+', help='socks4 proxies')
    parser.add_argument('-P5', '--socks5', nargs='+', help='socks5 proxies')
    parser.add_argument('-Pc', '--connect', nargs='+', help='connect proxies')

    parser.add_argument('-b', '--blacklist', nargs=1, help='proxies from this list will not be checked')

    args = parser.parse_args()

    global logger
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    proxies_set = set()

    if args.proxy_file:
        for el in args.proxy_file:
            try:
                with open(el, 'r') as f:
                    for i, line in enumerate(f):
                        try:
                            line = delete_comments(line)
                            a = line.split(':')
                            a[1] = a[1].strip('//')
                            match a[0]:
                                case 'http':
                                    proxies_set.add((proxy_type.HTTP, a[1], int(a[2])))
                                case 'https':
                                    proxies_set.add((proxy_type.HTTPS, a[1], int(a[2])))
                                case 'socks4':
                                    proxies_set.add((proxy_type.SOCKS4, a[1], int(a[2])))
                                case 'socks5':
                                    proxies_set.add((proxy_type.SOCKS5, a[1], int(a[2])))
                                case 'connect':
                                    proxies_set.add((proxy_type.CONNECT, a[1], int(a[2])))
                                case _:
                                    raise ValueError("invalid protocol specified")
                        except Exception as err:
                            logger.warning(f"While processing file {el}, line {i+1}, an exception occured => {err=}, {type(err)=}. Skipping line...")
            except Exception as exc:
                logger.warning(f"While opening file {el}, an exception occured => {exc=}, {type(exc)=}. Skipping file...")

    if args.http_file:
        for el in args.http_file:
            try:
                with open(el, 'r') as f:
                    for i, line in enumerate(f):
                        try:
                            line = delete_comments(line)
                            a = line.split(':')
                            proxies_set.add((proxy_type.HTTP, a[0], int(a[1])))
                        except Exception as err:
                            logger.warning(f"While processing file {el}, line {i+1}, an exception occured => {err=}, {type(err)=}. Skipping line...")
            except Exception as exc:
                logger.warning(f"While opening file {el}, an exception occured => {exc=}, {type(exc)=}. Skipping file...")

    if args.https_file:
        for el in args.https_file:
            try:
                with open(el, 'r') as f:
                    for i, line in enumerate(f):
                        try:
                            line = delete_comments(line)
                            a = line.split(':')
                            proxies_set.add((proxy_type.HTTPS, a[0], int(a[1])))
                        except Exception as err:
                            logger.warning(f"While processing file {el}, line {i+1}, an exception occured => {err=}, {type(err)=}. Skipping line...")
            except Exception as exc:
                logger.warning(f"While opening file {el}, an exception occured => {exc=}, {type(exc)=}. Skipping file...")

    if args.socks4_file:
        for el in args.socks4_file:
            try:
                with open(el, 'r') as f:
                    for i, line in enumerate(f):
                        try:
                            line = delete_comments(line)
                            a = line.split(':')
                            proxies_set.add((proxy_type.SOCKS4, a[0], int(a[1])))
                        except Exception as err:
                            logger.warning(f"While processing file {el}, line {i+1}, an exception occured => {err=}, {type(err)=}. Skipping line...")
            except Exception as exc:
                logger.warning(f"While opening file {el}, an exception occured => {exc=}, {type(exc)=}. Skipping file...")

    if args.socks5_file:
        for el in args.socks5_file:
            try:
                with open(el, 'r') as f:
                    for i, line in enumerate(f):
                        try:
                            line = delete_comments(line)
                            a = line.split(':')
                            proxies_set.add((proxy_type.SOCKS5, a[0], int(a[1])))
                        except Exception as err:
                            logger.warning(f"While processing file {el}, line {i+1}, an exception occured => {err=}, {type(err)=}. Skipping line...")
            except Exception as exc:
                logger.warning(f"While opening file {el}, an exception occured => {exc=}, {type(exc)=}. Skipping file...")

    if args.connect_file:
        for el in args.connect_file:
            try:
                with open(el, 'r') as f:
                    for i, line in enumerate(f):
                        try:
                            line = delete_comments(line)
                            a = line.split(':')
                            proxies_set.add((proxy_type.CONNECT, a[0], int(a[1])))
                        except Exception as err:
                            logger.warning(f"While processing file {el}, line {i+1}, an exception occured => {err=}, {type(err)=}. Skipping line...")
            except Exception as exc:
                logger.warning(f"While opening file {el}, an exception occured => {exc=}, {type(exc)=}. Skipping file...")

    if args.proxy:
        for i, el in enumerate(args.proxy):
            try:
                el = delete_comments(el)
                a = el.split(':')
                a[1] = a[1].strip('//')
                match a[0]:
                    case 'http':
                        proxies_set.add((proxy_type.HTTP, a[1], int(a[2])))
                    case 'https':
                        proxies_set.add((proxy_type.HTTPS, a[1], int(a[2])))
                    case 'socks4':
                        proxies_set.add((proxy_type.SOCKS4, a[1], int(a[2])))
                    case 'socks5':
                        proxies_set.add((proxy_type.SOCKS5, a[1], int(a[2])))
                    case 'connect':
                        proxies_set.add((proxy_type.CONNECT, a[1], int(a[2])))
                    case _:
                        raise ValueError("invalid protocol specified")
            except Exception as err:
                logger.warning(f"While processing {i} -P arg, an exception occured => {err=}, {type(err)=}. Skipping arg...")

    if args.http:
        for i, el in enumerate(args.http):
            try:
                a = el.split(':')
                proxies_set.add((proxy_type.HTTP, a[0], int(a[1])))
            except Exception as err:
                logger.warning(f"While processing {i} -Ph arg, an exception occured => {err=}, {type(err)=}. Skipping arg...")

    if args.https:
        for i, el in enumerate(args.https):
            try:
                a = el.split(':')
                proxies_set.add((proxy_type.HTTPS, a[0], int(a[1])))
            except Exception as err:
                logger.warning(f"While processing {i} -Ps arg, an exception occured => {err=}, {type(err)=}. Skipping arg...")

    if args.socks4:
        for i, el in enumerate(args.socks4):
            try:
                a = el.split(':')
                proxies_set.add((proxy_type.SOCKS4, a[0], int(a[1])))
            except Exception as err:
                logger.warning(f"While processing {i} -P4 arg, an exception occured => {err=}, {type(err)=}. Skipping arg...")

    if args.socks5:
        for i, el in enumerate(args.socks5):
            try:
                a = el.split(':')
                proxies_set.add((proxy_type.SOCKS5, a[0], int(a[1])))
            except Exception as err:
                logger.warning(f"While processing {i} -P5 arg, an exception occured => {err=}, {type(err)=}. Skipping arg...")

    if args.connect:
        for i, el in enumerate(args.connect):
            try:
                a = el.split(':')
                proxies_set.add((proxy_type.CONNECT, a[0], int(a[1])))
            except Exception as err:
                logger.warning(f"While processing {i} -Pc arg, an exception occured => {err=}, {type(err)=}. Skipping arg...")

    if args.blacklist:
        try:
            with open(args.blacklist, 'r') as f:
                for i, line in enumerate(f):
                    try:
                        line = delete_comments(line)
                        a = line.split(':')
                        a[1] = a[1].strip('//')
                        match a[0]:
                            case 'http':
                                proxies_set.discard((proxy_type.HTTP, a[1], int(a[2])))
                            case 'https':
                                proxies_set.discard((proxy_type.HTTPS, a[1], int(a[2])))
                            case 'socks4':
                                proxies_set.discard((proxy_type.SOCKS4, a[1], int(a[2])))
                            case 'socks5':
                                proxies_set.discard((proxy_type.SOCKS5, a[1], int(a[2])))
                            case 'connect':
                                proxies_set.discard((proxy_type.CONNECT, a[1], int(a[2])))
                            case _:
                                raise ValueError("invalid protocol specified")
                    except Exception as err:
                        logger.warning(f"While processing file {el}, line {i+1}, an exception occured => {err=}, {type(err)=}. Skipping line...")
        except Exception as exc:
            logger.warning(f"While opening file {el}, an exception occured => {exc=}, {type(exc)=}. Skipping file...")

    if len(proxies_set) == 0:
        logger.critical("There are no proxies to be checked. Exiting...")
        exit(1)

    socket.setdefaulttimeout(20)

    proxies_set = list(proxies_set)

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        results = list(executor.map(check_proxy, proxies_set))

    all = open("./good_proxy.txt", "a")
    httpl = open("./good_http.txt", "a")
    httpsl = open("./good_https.txt", "a")
    s4l = open("./good_socks4.txt", "a")
    s5l = open("./good_socks5.txt", "a")
    connl = open("./good_connect.txt", "a")
    badl = open("./bad_proxy.txt", "a")
    for i, el in enumerate(results):
        if el:
            match proxies_set[i][0]:
                case proxy_type.HTTP:
                    print('http://' + proxies_set[i][1] + ":" + str(proxies_set[i][2]), file=all)
                    print(proxies_set[i][1] + ":" + str(proxies_set[i][2]), file=httpl)
                case proxy_type.HTTPS:
                    print('https://' + proxies_set[i][1] + ":" + str(proxies_set[i][2]), file=all)
                    print(proxies_set[i][1] + ":" + str(proxies_set[i][2]), file=httpsl)
                case proxy_type.SOCKS4:
                    print('socks4://' + proxies_set[i][1] + ":" + str(proxies_set[i][2]), file=all)
                    print(proxies_set[i][1] + ":" + str(proxies_set[i][2]), file=s4l)
                case proxy_type.SOCKS5:
                    print('socks5://' + proxies_set[i][1] + ":" + str(proxies_set[i][2]), file=all)
                    print(proxies_set[i][1] + ":" + str(proxies_set[i][2]), file=s5l)
                case proxy_type.CONNECT:
                    print('http://' + proxies_set[i][1] + ":" + str(proxies_set[i][2]) + " # connect", file=all)
                    print(proxies_set[i][1] + ":" + str(proxies_set[i][2]), file=connl)
        else:
            proto = ""
            match proxies_set[i][0]:
                case proxy_type.HTTP:
                    proto = "http://"
                case proxy_type.HTTPS:
                    proto = "https://"
                case proxy_type.SOCKS4:
                    proto = "socks4://"
                case proxy_type.SOCKS5:
                    proto = "socks5://"
                case proxy_type.CONNECT:
                    print('http://' + proxies_set[i][1] + ":" + str(proxies_set[i][2]) + " # connect", file=badl)
                    continue
            print(proto + proxies_set[i][1] + ":" + str(proxies_set[i][2]), file=badl)

if __name__ == "__main__":
    main()