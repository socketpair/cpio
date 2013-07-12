#!/usr/bin/python
# coding: utf-8

import os
import logging
import cpio


'''
1. /start as symlink to python
2. minimal python interpreter
3. python libraries
4. NFS, LVM, dmsetup, shell (busybox), syslogging
'''


def main():
    logging.basicConfig(level=logging.DEBUG)
    os.chdir('test')
    with open('../qweq2.cpio.gz', 'wbe') as f:
        cpio.create('.', f)


if __name__ == '__main__':
    main()
