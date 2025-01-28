#!/usr/bin/python

# TODO - use playwright, JS instead

import requests

url = 'http://172.17.0.2:80' # local

proxies = {
	'http': '127.0.0.1:8080',
	'https': '127.0.0.1:8080'
}

def main():
    # for simulating admin session
	s = requests.Session()
	data = {'username':'admin','password':'admin'}

	s.get(f"{url}/login.php")
	s.post(f"{url}/login.php", data=data, proxies=proxies)

if __name__ == "__main__":
	main()