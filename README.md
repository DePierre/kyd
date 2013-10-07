Know Your Domain
================

Aim to gather information about a domain.

Rework of the CERT Société Générale's script:

* Thread system
* Timeout option
* PEP8 valid

Usage
-----

    Usage: kyd.py [options]

    Options:

    -h, --help            show this help message and exit
    -v, --verbose         print the debug messages (default=False)
    -f INPUT, --file=INPUT
                          the file name containing the list of the domain names
                          (default=./domains.txt)
    -o OUTPUT, --output=OUTPUT
                          the file name of the result (default=./result.txt)
    -p POOL, --pool=POOL  the number of concurrent threads (default=8)
    -t TIMEOUT, --timeout=TIMEOUT
                          the timeout value of the lookup (default=none)
