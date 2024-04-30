#!/usr/bin/env python3

import requests
import urllib.parse as urlparse
from bs4 import BeautifulSoup

headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:55.0) Gecko/20100101 Firefox/55.0',
}


class Scanner:
    def __init__(self, url, ignore_links):
        self.session = requests.Session()
        self.target_url = url
        self.target_links = []
        self.links_to_ignore = ignore_links

    def extract_links(self, url):
        response = self.session.get(url, headers=headers)
        response_content = response.content
        soup = BeautifulSoup(response_content, features="lxml")
        href_links = []
        for link in soup.find_all('a'):
            href_links.append(link.get('href'))
        return href_links

    def crawler(self, url=None):
        if url == None:
            url = self.target_url
        href_links = self.extract_links(url)
        for link in href_links:
            link = urlparse.urljoin(url, link)

            if '#' in link:
                link = link.split('#')[0]

            if self.target_url in link and link not in self.target_links and link not in self.links_to_ignore :
                self.target_links.append(link)
                print(link)
                self.crawler(link)

    def extract_forms(self, url):
        response = self.session.get(url, headers=headers)
        response_content = response.content
        soup = BeautifulSoup(response_content, features="lxml")
        return soup.find_all('form')

    def submit_form(self, form, value, url):
        action = form.get("action")
        post_url = urlparse.urljoin(url, action)
        method = form.get("method")

        input_list = form.find_all("input")
        post_data = {}

        for input in input_list:
            input_name = input.get("name")
            input_type = input.get("type")
            input_value = input.get("value")
            if input_type == "text":
                input_value = value

            post_data[input_name] = input_value

        if method == "post":
            return self.session.post(post_url, data=post_data )
        return self.session.get(post_url, params=post_data)

    def run_scanner(self):
        for link in self.target_links:
            forms = self.extract_forms(link)
            for form in forms:
                print(f"[+] Testing form in {link}")
                xss_vuln = self.test_xss_in_form(form, link)
                if xss_vuln:
                    print('-'*100)
                    print(f"[***] Discovered XSS in {link} on following form")
                    print(form)
                    print('-'*100)

            if "=" in link:
                print(f"[+] Testing {link}")
                xss_vuln = self.test_xss_in_link(link)
                if xss_vuln:
                    print('-'*100)
                    print(f"[***] Discovered XSS in {link}")
                    print('-'*100)


    def test_xss_in_form(self, form, url):
        xss_script = "</sCript>alert('alert')</scriPt>"
        response = self.submit_form(form, xss_script, url)
        return xss_script in response.content.decode(errors='ignore')

    def test_xss_in_link(self, url):
        xss_script = "</sCript>alert('alert')</scriPt>"
        url = url.replace("=", "=" + xss_script)
        response = self.session.get(url)
        return xss_script in response.content.decode(errors='ignore')


