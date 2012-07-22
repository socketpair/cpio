#coding: utf-8
from __future__ import unicode_literals

import os
import stat
import gzip


class CPIO(object):
    def __init__(self):
        self.outfile = None
        self.ino_real2fake = None
        self.ino2htuple = None
        self.fakegen = None
        self.cutlen = None

    def write_file_contents(self, ino, statres, fullpath, zerosize=False):

        if self.cutlen:
            cpio_filename = fullpath[self.cutlen:].encode('utf-8')
            if not cpio_filename:
                cpio_filename = b'.'
        else:
            cpio_filename = fullpath.encode('utf-8')

        cpio_filename += b'\x00'

        if stat.S_ISDIR(statres.st_mode):
            size = 0
        elif zerosize:
            size = 0
        else:
            size = statres.st_size

        self.outfile.write(b'070701')
        # writelines will not add newlines. stupid function name
        self.outfile.writelines((b'{0:08x}'.format(i) for i in [
            ino,
            statres.st_mode,
            statres.st_uid,
            statres.st_gid,
            statres.st_nlink, # should not be less than references in that CPIO
            int(statres.st_mtime),
            size,
            0, # devmajor
            0, # devminor
            (statres.st_rdev >> 8) & 0xff,
            statres.st_rdev & 0xff,
            len(cpio_filename), # buggy CPIO documentation is SHIT. yes, length with last zero needed
            0, # check
        ]))
        self.outfile.write(cpio_filename)

        # alignment
        self.outfile.write(b'\x00' * (-(self.outfile.tell() % -4)))

        if size == 0:
            return

        # TODO: check if actual file length match in record.
        # symlink - so, read and write that
        if stat.S_ISLNK(statres.st_mode):
            self.outfile.write(os.readlink(fullpath).encode('utf-8'))
            self.outfile.write(b'\x00' * (-(self.outfile.tell() % -4)))
            return

        if stat.S_ISREG(statres.st_mode):
            with open(fullpath, 'rbe') as xxx:
                while 1:
                    chunk = xxx.read(65536)
                    if not chunk:
                        break
                    self.outfile.write(chunk)
            self.outfile.write(b'\x00' * (-(self.outfile.tell() % -4)))
            return

        raise Exception('Unknown file type with nonzero len')

    def scandirs(self, path):
        statres = os.lstat(path)

        identifier = (statres.st_dev, statres.st_ino)
        if identifier in self.ino_real2fake:
            ino = self.ino_real2fake[identifier]
        else:
            self.fakegen += 1
            self.ino_real2fake[identifier] = self.fakegen
            ino = self.fakegen

        if statres.st_size != 0 and statres.st_nlink != 1 and not stat.S_ISDIR(statres.st_mode):
            # non-zero sized hardlinks will be handled later
            htuple = self.ino2htuple.setdefault(ino, (statres, []))
            htuple[1].append(path)
            return

        self.write_file_contents(ino, statres, path)

        if not stat.S_ISDIR(statres.st_mode):
            return

        for item in os.listdir(path):
            self.scandirs(os.path.join(path, item))

    def hardlinks_handle(self):
        # handle hardlinks
        for (ino, (statres, fullpaths)) in self.ino2htuple.iteritems():
            # all fullpaths except last
            for fullpath in fullpaths[:-1]:
                self.write_file_contents(ino, statres, fullpath, True)

            # last fullpaths
            self.write_file_contents(ino, statres, fullpaths[-1])

    def write_trailer(self):
        self.outfile.write(b'070701') # magic
        self.outfile.write(b'00000000' * 11)
        self.outfile.write(b'0000000b') # file name length
        self.outfile.write(b'00000000') # check field
        self.outfile.write(b'TRAILER!!!\x00\x00\x00\x00') #filename and padding

    # TODO: allow dst to be already opened file
    def create(self, src, dst):
        '''
        src may be string (as path name) or iterable of ones
        dst is the destination filename, like 'dst.cpio.gz'

        This function will create cpio.gz (NEW format)
        '''
        self.outfile = gzip.open(dst, 'wbe', 9)
        try:
            self.ino_real2fake = dict()
            self.ino2htuple = dict()
            self.fakegen = 0

            if isinstance(src, basestring):
                self.cutlen = len(src) + 1
                self.scandirs(src)
            else:
                self.cutlen = None
                for i in src:
                    self.scandirs(i)
            self.hardlinks_handle()
            self.write_trailer()

        except:
            os.path.unlink(self.outfile.name)
            raise
        finally:
            self.cutlen = None
            self.fakegen = None
            self.ino2htuple = None
            self.ino_real2fake = None
            self.outfile.close()
            self.outfile = None


