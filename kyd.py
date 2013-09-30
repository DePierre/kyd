#!/usr/bin/python2
# -*- coding: utf-8 -*-

"""

    KYDScript (KYD stands for "Know Your Domains")

    Code by CPE / CERT Societe Generale

    Greetings to GAR for some Python debugging help ;-)

    Microsoft Windows compatible version by JPT

    Rework and thread implementation by DePierre

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
        if exception :
            "no web server" (there could be a "A" record, but no web server)
        if 301, 302, 303 or 307 : follow and check if timeout
    5. outputs the results as a CSV file.

"""


import re
import sys
import csv
import time
import socket
import urllib2
import logging
import threading
from whois import NICClient
from optparse import OptionParser


logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s] (%(threadName)-10s) %(message)s',
)


def csv_save(data, filename='./result.txt'):
    """
        Save the result into a file following the CSV format.
        Data looks like:
            {
                'domain': {
                    'ip_addresse': ip_addresses,
                    'aliases': aliases,
                    'web': {
                        'url': url,
                        'status': status
                    }
                }
            }

        Each line looks like:
            domain name; ip adresses; aliases; url; status
    """

    with open(filename, 'wb') as output:
        csv_writer = csv.writer(output, delimiter=';', quotechar='"')
        for domain, info in data.iteritems():
            row = [domain]
            row.append(
                ';'.join([ip for ip in info['ip_addresses'] if ip])
            )
            if info['aliases']:
                row.extend([
                    alias for alias in info['aliases'] if alias
                ])
            else:
                row.append('')
            row.extend([info['web']['url'], info['web']['status']])
            csv_writer.writerow(row)


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
        to a 301, 302, 303 or 307.
    """
    def http_error_301(self, req, fp, code, msg, headers):
        result = urllib2.HTTPRedirectHandler.http_error_301(
            self, req, fp, code, msg, headers
        )
        result.status = code
        return result

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301


class LookupThread(threading.Thread):
    """
        Threaded class for threaded domain lookup.
    """

    def __init__(self, domain, result, pool, verbose=False):
        self.domain = domain
        self.result = result
        self.pool = pool
        self.verbose = verbose
        threading.Thread.__init__(self)

    def run(self):
        """
            Try the domain lookup if it can access the pool
        """
        self.pool.acquire()
        try:
            if self.verbose:
                logging.debug('Starting')
            self.lookup(self.domain)
        finally:
            self.pool.release()
            if self.verbose:
                logging.debug('Exiting')

    def lookup(self, domain):
        """
            Determines if the domain is a valid one by asking to
            gethostbyname_ex. If it fails, it uses a whois request on the
            domain name to check wether or not the domain has been reserved.
            If the gethostname succeeds, it checks if it can find a web server
            on it.
        """

        try:
            domain_name, aliases, ip_addresses = socket.gethostbyname_ex(
                domain
            )
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
                'web': self.check_url_http(domain)
            }
        self.result.update(result)

    def check_url_http(self, domain):
        """
            Check URL to find if wether or not there is a Web Server.
            Only support HTTP protocol.

            Return:
                {'url': final_url, 'status': status}
        """

        url = domain
        if not url.startswith('http://'):
            url = 'http://' + url
        result = {'url': '', 'status': 'NO_WEB_SERVER'}

        try:
            request = urllib2.Request(url)
            opener = urllib2.build_opener(DumbRedirectHandler())
            f = opener.open(request)
        except urllib2.URLError:
            return result
        else:
            # The opener only has the status attribute when it is a redirection
            if hasattr(f, 'status'):
                try:
                    urllib2.urlopen(f.url)
                except urllib2.URLError:
                    result['status'] = 'REDIRECTION_URL_TIME_OUT'
                else:
                    result['status'] = str(f.status)
                finally:
                    result['url'] = f.url
            else:
                result['status'] = str(f.getcode())
                result['url'] = f.url
        return result


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option(
        '-v', '--verbose',
        default=False,
        help='print the debug messages (default=%default)',
        action='store_true',
        dest='verbose'
    )
    parser.add_option(
        '-f', '--file',
        default='./domains.txt',
        help='the file name containing the list of the domain names'
        ' (default=%default)',
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
    parser.add_option(
        '-p', '--pool',
        default='8',
        help='the number of concurrent threads (default=%default)',
        action='store',
        dest='pool',
        type='int'
    )
    parser.add_option(
        '-t', '--timeout',
        default=None,
        help='the timeout value of the lookup (default=%default)',
        action='store',
        dest='timeout',
        type=int
    )

    (opt, args) = parser.parse_args()

    start = time.time()
    result = {}
    domains = csv_read(opt.input)

    pool = threading.BoundedSemaphore(opt.pool)

    lookup_threads = [
        LookupThread(domain, result, pool, verbose=opt.verbose)
        for domain in domains
    ]
    for thread in lookup_threads:
        thread.start()

    main_thread = threading.currentThread()
    for thread in threading.enumerate():
        if thread is main_thread:
            continue
        if opt.verbose:
            logging.debug('Joining %s', thread.getName())
        thread.join(opt.timeout)

    print 'Result:'
    print result

    csv_save(result, filename=opt.output)
    elapsed = time.time() - start

    print
    print '(elapsed time: %.2f seconds)' % elapsed
