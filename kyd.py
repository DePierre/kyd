#!/usr/bin/python2
# -*- coding: utf-8 -*-

"""

    KYDScript (KYD stands for "Know Your Domains")

    Code by CPE / CERT Societe Generale

    Greetings to GAR for some Python debugging help ;-)

    Microsoft Windows compatible version by JPT

    v1.2


    What does it do ?

    1. after usual parameter and file checking, it fetches one domain in the
        input file
    2. tries socket.gethostbyname_ex on the domain
    3.		if exception raised : makes a whois, and looks for the "Registrar"
                field
            if none : "domain does not exist". Else : "no web server for
                domain"
    4. checks with urlparse.
        if exception : "no web server" (there could be a "A" record, but no web
            server)
        if 301 or 302 : follow and check if timeout
    5. outputs the results as a CSV file.

"""


import re
import sys
import csv
import time
import socket
import urllib2
from whois import NICClient
from optparse import OptionParser


def csv_save(data, filename='./result.txt'):
    """
        Save the result into a file following the CSV format.
        Data looks like:
            {'domain': {'ip': ip, 'url': url}}
        Each line looks like:
            domain name; ip adresses; url
    """

    with open(filename, 'rb') as output:
        csv_writer = csv.writer(output, delimiter=';', quotechar='"')
        for domain, information in data.items():
            output.writerow([domain, information['ip'], information['url']])


def csv_read(filename='./domains.txt'):
    """
        Read the file 'filename' looking for domain names.
        One line contains one domain name:
            domain1
            domain2
            domain3
            ...
            domainn
        Return a set of domain names.
    """

    domain_names = set()
    with open(filename, 'rb') as input:
        csv_reader = csv.reader(input, delimiter=';', quotechar='"')
        for line in csv_reader:
            domain_names.update([domain.strip() for domain in line if domain])
    return domain_names


class DumbRedirectHandler(urllib2.HTTPRedirectHandler):
    """
        Dummy redirect handler which allows to know wether or not a URL leads
        to a 301 or a 302.
    """
    def http_error_301(self, req, fp, code, msg, headers):
        result = urllib2.HTTPRedirectHandler.http_error_301(
            self, req, fp, code, msg, headers
        )
        result.status = code
        return result
    def http_error_302(self, req, fp, code, msg, headers):
        result = urllib2.HTTPRedirectHandler.http_error_302(
            self, req, fp, code, msg, headers
        )
        result.status = code
        return result



def check_url_http(domain):
    """
        Check URL to find if wether or not there is a Web Server.
        Only support HTTP protocol.

        Return one of the following case:
            {url: {'url': final_url, 'status': status}}
            [domain, url_of_the_webserver]
            [url, 'NO WEB SERVER']
            [url, 'REDIRECTION URL TIME OUT']
    """

    url = domain
    if not url.startswith('http://'):
        url = 'http://' + url
    result = {'url': '', 'status': 'NO_WEB_SERVER'}

    try:
        request = urllib2.Request(url)
        opener = urllib2.build_opener(DumbRedirectHandler())
        f = opener.open(request)
    except urllib2.URLError, e:
        return result
    else:
        if f.status == 301 or f.status == 302:
            try:
                urllib2.urlopen(f.url)
            except urllib2.URLError:
                result['status'] = 'REDIRECTION_URL_TIME_OUT'
            else:
                result['status'] = 'REDIRECTION_URL_OK'
            finally:
                result['url'] = f.url
        else:
            result['url'] = url
            result['status'] = str(f.status)
    return result


def check_domain(domain):
    result = {}
    #socket.setdefaulttimeout(2)
    try:
        domain_name, aliases, ip_addresses = socket.gethostbyname_ex(domain)
    except socket.gaierror:
        result[domain] = {
            'aliases': '',
            'ip_addresses': '',
        }
        whois_data = NICClient().whois(domain, 'whois.crsnic.net', 0x02)
        if not re.search('registrar:', whois_data, re.IGNORECASE):
            result[domain]['web'] = {
                'url': '',
                'status': 'DOMAIN_DOES_NOT_EXIST'
            }
        else:
            result[domain]['web'] = {
                'url': '',
                'status': 'NO_WEB_SERVER_FOR_DOMAIN'
            }
    else:
        result[domain] = {
            'aliases': aliases,
            'ip_addresses': ip_addresses,
            'web': check_url_http(domain)
        }
    return result

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option(
        '-f', '--file',
        default='./domains.txt',
        help='the file name containing the list of the domain names (default=%default)',
        action='store',
        dest='input',
        type='string'
    )
    parser.add_option(
        '-o', '--output',
        default='./result.txt',
        help='the file name of the result (default=%default)',
        action='store',
        dest='output',
        type='string'
    )

    (opt, args) = parser.parse_args()

    start = time.time()
    domains = csv_read(opt.input)
    for domain in domains:
        print check_domain(domain)
    elapsed = time.time() - start

    print '(elapsed time: %.2f seconds)' % elapsed
