import socket
import sys
import ssl
import re
from urllib.parse import urlparse

def is_http2_supported(url):
    try:
        context = ssl.create_default_context()
        context.set_alpn_protocols(['h2', 'spdy/3', 'http/1.1'])
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with context.wrap_socket(sock, server_hostname=url) as ssock:
                ssock.connect((url, 443))
                return ssock.selected_alpn_protocol() == "h2"
    except socket.error as err:
        sys.exit("Error: cannot connect - %s" %err)

def get_status(response):
    return int(re.search(r'(HTTP/1.[01]\s*)(\d+)', response).group(2))

def parse_location(url, host=None, is_https=False):
    protocol = re.search(r'http[s]*://', url)
    if protocol:
        location = urlparse(url)
        host = location.netloc.split(':')[0] # there is this case newlocation.netloc = bright.uvic.ca:443
        path = location.path or '/'
        is_https = location.scheme == "https"
    else:
        new_host = re.search(r'^[^/]*', url)
        if new_host and new_host.group() != '':
            host = new_host.group().split(':')[0]
        path = re.search(r'\/[^\r\n]*', url)
        if path: path = path.group()
        else: path = '/'
    return host, path, is_https

def get_location(response, host, is_https):
    location = re.search(r'(Location:\s*)([^\r\n]*)', response).group(2)
    return parse_location(location, host, is_https)

def print_request(request):
    print("---Request begin---")
    print(request)
    print("---Request end---")

def print_response(response):
    print("---Response begin---")
    print(response)
    print("---Response end---")  

def connect_http(host, path):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, 80))
            request = f"GET {path} HTTP/1.1\r\nHost:{host}\r\n\r\n"
            print_request(request)
            sock.sendall(request.encode())
            response = sock.recv(10000).decode()
            return response
    except socket.error as err:
        sys.exit("Error: cannot connect http - %s" %err)

def connect_https(host, path):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, 443))
            sock = ssl.wrap_socket(sock)
            request = f"GET {path} HTTP/1.1\r\nHost:{host}\r\n\r\n"
            print_request(request)
            sock.sendall(request.encode())
            response = sock.recv(10000).decode() 
            return response
    except socket.error as err:
        sys.exit("Error: cannot connect https - %s" %err)

def connection(host, path):
    response = connect_http(host, path)
    is_https = False
    for i in range(100):
        status = get_status(response)
        print_response(response)
        if status != 301 and status != 302:
            return response

        host, path, is_https = get_location(response, host, is_https)

        if is_https:
            response = connect_https(host, path)
        else:
            response = connect_http(host, path)
    sys.exit("Error: too many redirections")

def to_cookie_string(cookie):
    s = f"cookie name: {cookie['name'].group().strip()}"
    if cookie['expires']:
        s += f", expires time: {cookie['expires'].group().strip()}"
    if cookie['domain']:
        s += f", domain name: {cookie['domain'].group().strip()}"
    return s

def get_cookies(response):
    cookie_lines = filter(lambda line: line.startswith('Set-Cookie:'), response.split('\n'))
    cookies = map(lambda cookie:
                    {
                        'name': re.search(r'(?<=Set-Cookie:)([^=]*)(?=\=)', cookie, re.IGNORECASE),
                        'expires': re.search(r'(?<=expires=)([^;]*)', cookie, re.IGNORECASE),
                        'domain': re.search(r'(?<=domain=)([^;]*)', cookie, re.IGNORECASE)
                    }, cookie_lines)
    return map(lambda cookie: to_cookie_string(cookie), cookies)

def main():
    if len(sys.argv) != 2:
        sys.exit("Error: expected 1 argument")

    socket.setdefaulttimeout(5)

    url = sys.argv[1]
    host, path, is_https = parse_location(url)
    response = connection(host, path)

    print("website:", url)

    # is http2 supported
    print("1. Supports http2:", 'yes' if is_http2_supported(host) else 'no')

    # cookies
    print("2. List of Cookies:")
    cookies = get_cookies(response)
    for cookie in cookies: print(cookie)
    
    # password-protected
    print("3. Password-protected:", 'yes' if get_status(response) == 401 else 'no')

if __name__ == "__main__":
    main()