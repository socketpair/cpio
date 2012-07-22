#coding: utf-8

import sys
import os
import stat
import posix
import itertools

from collections import defaultdict

class CPIO(object):
    def __init__(self, outfile):
        self.outfile = outfile
        self.ino_real2fake = defaultdict(itertools.count(1).next)
        self.ino2htuple = dict()
        self.encoding = sys.getfilesystemencoding()

    def _align(self):
        position = self.outfile.tell()
        offset = -(self.outfile.tell() % -4)
        if offset:
            self.outfile.seek(position + offset)

    def write_file_contents(self, statres, fullpath):
        if isinstance(fullpath, unicode):
            cpio_filename = fullpath.encode(self.encoding)
        else:
            cpio_filename = fullpath

        cpio_filename += b'\x00'

        if not stat.S_ISLNK(statres.st_mode) and not stat.S_ISREG(statres.st_mode):
            size = 0
        else:
            size = statres.st_size

        if size > 0xffffffff:
            raise ValueError('Too big file size for this CPIO format (size={0})'.format(statres.st_size))

        self._align()
        self.outfile.write(b'070701')
        # writelines will not add newlines. stupid function name
        self.outfile.writelines((b'{0:08x}'.format(i) for i in [
            statres.st_ino,
            statres.st_mode,
            statres.st_uid,
            statres.st_gid,
            statres.st_nlink, # should not be less than references in that CPIO
            int(statres.st_mtime),
            size,
            (statres.st_dev >> 8) & 0xff,
            statres.st_dev & 0xff,
            (statres.st_rdev >> 8) & 0xff,
            statres.st_rdev & 0xff,
            len(cpio_filename), # buggy CPIO documentation is SHIT. yes, length with last zero needed
            0, # check (CRC)
        ]))
        self.outfile.write(cpio_filename)

        if cpio_filename == b'TRAILER!!!\x00':
            return

        if stat.S_ISDIR(statres.st_mode):
            return

        # TODO: check if actual file length match in record.
        # symlink - so, read and write that
        if stat.S_ISLNK(statres.st_mode):
            self._align()
            self.outfile.write(os.readlink(fullpath))
            return

        #TODO: splice
        if stat.S_ISREG(statres.st_mode):
            size = statres.st_size
            if not size:
                return
            self._align()
            with open(fullpath, 'rbe') as xxx:
                while size:
                    chunk = xxx.read(65536)
                    if not chunk:
                        break
                    self.outfile.write(chunk)
                    size -= len(chunk)
            if size:
                raise Exception('File {0!r} was truncated while reading'.format(fullpath))
            return

        raise Exception('Unknown file type')

    def inject_path(self, path):
        statres = os.lstat(path)

        ino = self.ino_real2fake[(statres.st_dev, statres.st_ino)]
        statres = posix.stat_result(statres[:1] + (ino,) + statres[2:], {'st_rdev': statres.st_rdev})

        if stat.S_ISDIR(statres.st_mode):
            self.write_file_contents(statres, path)
            return

        if statres.st_nlink != 1:
            # hardlinks will be handled later
            htuple = self.ino2htuple.setdefault(ino, (statres, []))
            htuple[1].append(path)
            return

        self.write_file_contents(statres, path)

    def hardlinks_handle(self):
        # handle hardlinks
        for (statres, fullpaths) in self.ino2htuple.itervalues():
            # all fullpaths except last
            # fix st_nlink
            statres = posix.stat_result(statres[:3] + (len(fullpaths),) + statres[4:], {'st_rdev': statres.st_rdev})
            # fix size
            statres_cpio = posix.stat_result(statres[:6] + (0,) + statres[7:], {'st_rdev': statres.st_rdev})
            for fullpath in fullpaths[:-1]:
                self.write_file_contents(statres_cpio, fullpath)

            # last fullpath
            self.write_file_contents(statres, fullpaths[-1])

    # TODO: convert to __exit__
    def write_trailer(self):
        self.write_file_contents(posix.stat_result((0,) * 10, {'st_rdev': 0}), 'TRAILER!!!')
        # for really buggy cpio unpacker implementations...
        self._align()


    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.hardlinks_handle()
        self.write_trailer()

def _walkhandler(error):
    raise error

def _create(cpio_obj, src):
    if isinstance(src, basestring):
        src = [src]

    for i in src:
        cpio_obj.inject_path(i)
        if not os.path.isdir(i):
            continue
        if os.path.islink(i):
            continue
        for (root, dirs, files) in os.walk(i, onerror=_walkhandler):
            for i in itertools.chain(files, dirs):
                cpio_obj.inject_path(os.path.join(root, i))

def create(src, dst, gzip=None, ingzipname=None):
    '''
    src may be string (as path name) or iterable of ones
    dst is the destination file object

    This function will create cpio.gz (NEW format)
    '''

    if gzip is None:
        name = dst.name
        gzip = name.endswith('.gz')
        ingzipname = name[:-3]

    if not gzip:
        with CPIO(dst) as cpio_obj:
            return _create(cpio_obj, src)

    from gzip import GzipFile
    with GzipFile(ingzipname, 'wbe', 9, dst) as dst:
        with CPIO(dst) as cpio_obj:
            return _create(cpio_obj, src)
