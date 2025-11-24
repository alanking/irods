#!/usr/bin/python3
from __future__ import print_function
import argparse
import itertools

import irods.lib

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--regex', dest='regex', action='store_true', default=False,
            help='Enable regular expressions for search string')
    parser.add_argument('args', nargs='+')
    args = parser.parse_args()
    for so in args.args:
        so_paths = irods.lib.find_shared_object(so, regex=args.regex)
        print('\n\t'.join(itertools.chain([''.join([so, ':'])], so_paths)))

if __name__ == '__main__':
    main()
