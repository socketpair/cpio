#!/usr/bin/python
# coding: utf-8

import os
import cpio

'''
1. /start as symlink to python
2. minimal python interpreter
3. python libraries
4. NFS, LVM, dmsetup, shell (busybox), syslogging
'''

def main():
    os.chdir('test')
    cpio.CPIO().create(['.'], '../qweq2.cpio.gz')

if __name__ == '__main__':
    main()
