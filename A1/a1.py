from socket import *
import sys
import ssl
import re

'''
NOTE:
http 2.0: set_alpn_protocols(), ssl
s =  ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_3)

password protected: 401 http response
'''

BYTES = 10000
HTTP_PORT = 80
HTTPS_PORT = 443
REQUEST = "GET /index.html HTTP/1.1\n\n"

def get_response(uri, port):
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((uri, port))
        request = REQUEST
        s.send(request.encode())
        response = s.recv(BYTES).decode()
        s.close()
        return response
    except error as e:
        print(e)
        sys.exit()

def is_https(response):
    location = list(filter(lambda line: line.startswith('Location:'), response.split('\n')))
    return location and re.search('https', location[0])

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
                        'name': re.search('(?<=Set-Cookie:)([^=]*)(?=\=)', cookie),
                        'expires': re.search('(?<=expires=)([^;]*)', cookie),
                        'domain': re.search('(?<=domain=)([^;]*)', cookie)
                    }, cookie_lines)
    return map(lambda cookie: to_cookie_string(cookie), cookies)

def check_401(response):
    return any(filter(lambda line: line.startswith('HTTP/') and '401' in line, response.split('\n')))

def main(uri):
    # ctx = ssl.create_default_context()
    # ctx.set_alpn_protocols(['h2'])
    response = get_response(uri, 80)
    print(response)

    if is_https(response):
        response = get_response(uri, HTTPS_PORT)
        print('---------- ANOTHER ----------')
        print(response)

    # s = socket(AF_INET, SOCK_STREAM)
    # conn = ctx.wrap_socket(s, server_hostname=uri)
    # conn.connect((uri, PORT))
    # is_http2_supported = conn.selected_alpn_protocol()
    # print("HERE:", is_http2_supported)
    # request = "GET /index.html h2\n\n"
    # conn.send(request.encode())
    # response = conn.recv(10000).decode()
    # print(response)
    # conn.close()
    
    
    cookies = get_cookies(response)
    is_password_protected = check_401(response)

    # output
    print("website:", uri)
    print("1. Supports http2:")
    print("2. List of Cookies:")
    for cookie in cookies: print(cookie)
    print("3. Password-protected:", 'yes' if is_password_protected else 'no')


if __name__ == "__main__":
    main(sys.argv[1])