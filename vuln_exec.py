#!/usr/bin/env python3

import scanner

headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:55.0) Gecko/20100101 Firefox/55.0',
}

#print ASCII logo
print(open('logo', 'r').read())

target_url = "http://192.168.217.186/dvwa/"
links_to_ignore = ["http://192.168.217.186/dvwa/logout.php"]
data_dict = {"username": "admin", "password": "password", "Login": "submit"}

vuln_scanner = scanner.Scanner(target_url, links_to_ignore)
response = vuln_scanner.session.post("http://192.168.217.186/dvwa/login.php", data=data_dict, headers=headers)

vuln_scanner.crawler()
vuln_scanner.run_scanner()
