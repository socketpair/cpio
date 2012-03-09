#coding: utf-8
from __future__ import unicode_literals

import os
import stat


class CPIO(object):
    def __init__(self):
        self.outfile = None
        self.ino_real2fake = None
        self.ino2htuple = None
        self.fakegen = None

    def write_headers(self, ino, info, fullpath, zerosize=False):
        #TODO: hack ./paths
        cpio_filename = fullpath.encode('utf-8')
        record = [b'070701']
        record.extend((b'{0:08x}'.format(i) for i in [
            ino,
            info.st_mode, # TODO: need hacks!
            0, #info.st_uid,
            0, #info.st_gid,
            info.st_nlink, # should not be less that references in that CPIO
            int(info.st_mtime),
            0 if stat.S_ISDIR(info.st_mode) or zerosize else info.st_size,
            0, # devmajor
            0, # devminor
            (info.st_rdev >> 8) & 0xff,
            info.st_rdev  & 0xff,
            len(cpio_filename) + 1, # buggy CPIO documentation is SHIT
            0, # check
        ]))
        record.append(cpio_filename)
        # terminating zerobyte, with aligning to 4
        record.append(b'\x00' * (1 - ((110 + len(cpio_filename) + 1) % -4)))
        record = b''.join(record)
        # CHECK!
        if len(record) % 4:
            raise Exception('Internal error 1')
        self.outfile.write(record)

    def fetch_ino(self, info):
        identifier = (info.st_dev, info.st_ino)
        if info.st_ino in self.ino_real2fake:
            return self.ino_real2fake[identifier]
        else:
            self.fakegen += 1
            self.ino_real2fake[identifier] = self.fakegen
            return self.fakegen

    def scandirs(self, path):
        info = os.lstat(path)
        ino = self.fetch_ino(info)

        if info.st_size != 0 and info.st_nlink != 1 and not stat.S_ISDIR(info.st_mode):
            # non-zero sized hardlinks will be handled later
            htuple = self.ino2htuple.setdefault(ino, (info, []))
            htuple[1].append(path)
            return

        self.write_file_contents(ino, info, path)

        if not stat.S_ISDIR(info.st_mode):
            return

        for item in os.listdir(path):
            self.scandirs(os.path.join(path, item))

    def write_file_contents(self, ino, info, fullpath):
        self.write_headers(ino, info, fullpath)

        if info.st_size == 0 or stat.S_ISDIR(info.st_mode):
            return

        # TODO: check if actual file length match in record.
        # symlink - so, read and write that
        if stat.S_ISLNK(info.st_mode):
            data = os.readlink(fullpath).encode('utf-8')
            self.outfile.write(data)
            self.outfile.write(b'\x00' * -(len(data) % -4))
            # CHECK2 !
            if (len(data) -(len(data) % -4)) % 4:
                raise Exception('in error 2')
            return

        if stat.S_ISREG(info.st_mode):
            dlen = 0
            with open(fullpath, 'rbe') as xxx:
                while 1:
                    chunk = xxx.read(4096)
                    if not chunk:
                        break
                    self.outfile.write(chunk)
                    dlen += len(chunk)
            self.outfile.write(b'\x00' * -(dlen % -4))
            if (dlen - (dlen % -4)) % 4:
                raise Exception('in error 3')
            return

        raise Exception('Unknown file type with nonzero len')

    def dddd(self, path):
        self.outfile = open('/tmp/qwe.cpio', 'wbe')
        try:
            self.ino_real2fake = dict()
            self.ino2htuple = dict()
            self.fakegen = 0
            self.scandirs(path)
            # handle hardlinks
            for (ino, (info, fullpaths)) in self.ino2htuple.iteritems():
                # all fullpaths except last
                for fullpath in fullpaths[:-1]:
                    self.write_headers(ino, info, fullpath, True)
                # last fullpaths
                fullpath = fullpaths[-1]
                self.write_file_contents(ino, info, fullpath)

            self.outfile.write(b'070701') # magic
            self.outfile.write(b'00000000' * 11)
            self.outfile.write(b'0000000b') # file name length
            self.outfile.write(b'00000000') # check field
            self.outfile.write(b'TRAILER!!!\x00\x00\x00\x00') #filename and padding
        finally:
            self.fakegen = None
            self.ino2htuple = None
            self.ino_real2fake = None
            self.outfile.close()
            self.outfile = None



CPIO().dddd('.')
