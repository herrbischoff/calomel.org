#!/usr/bin/env python3

from urllib.request import urlopen
from bs4 import BeautifulSoup

page = urlopen('https://calomel.org/freebsd_network_tuning.html')
#  f = open('html.txt')
#  page = f.read()

soup = BeautifulSoup(page, 'html.parser')

def saveContent(filename):
    pre = headline.findNext('pre')
    data = pre.text.splitlines(True)
    with open(filename, 'w') as fout:
        fout.writelines(data[1:])
        fout.close()

for headline in soup.find_all('h3'):
    if "/boot/loader.conf" in headline.text:
        saveContent('boot/loader.conf')
    if "/etc/sysctl.conf" in headline.text:
        saveContent('etc/sysctl.conf')
    if "OPTIONAL: Enable the Pf firewall" in headline.text:
        saveContent('etc/rc.conf')
