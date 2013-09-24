#coding: utf-8
from __future__ import absolute_import

import logging

import sys
import os
import stat
import itertools

from collections import defaultdict, namedtuple

log = logging.getLogger('CPIO')

MyStat = namedtuple('MyStat', [
    'st_uid',
    'st_gid',
    'st_ino',
    'st_mode',
    'st_mtime',
    'st_nlink',
    'st_dev',
    'st_rdev',
    'st_size',
])


class CPIOException(Exception):
    pass


class CPIO(object):
    def __init__(self, outfile, save_mtime=True, save_uid_gid=True):
        """
        :type outfile: FileIO of bytes
        """
        self.outfile = outfile
        self.ino_real2fake = defaultdict(itertools.count(1).next)
        self.ino2htuple = dict()
        self.input_encoding = sys.getfilesystemencoding()
        self.output_encoding = 'utf-8'

        self.save_mtime = save_mtime
        self.save_uid_gid = save_uid_gid
        self.position = 0
        log.debug('Output encoding is %s, input one is %s', self.output_encoding, self.input_encoding)

    def _outwrite(self, data):
        """
        :type data: bytes
        """
        self.outfile.write(data)
        self.position += len(data)

    def _align(self):
        offset = -(self.position % -4)
        if offset:
            self._outwrite(b'\x00' * offset)

    def _write_file_contents(self, statres, fullpath):
        """
        :type statres: MyStat
        :type fullpath: str or unicode
        """

        symlink_path = None
        if stat.S_ISLNK(statres.st_mode):
            symlink_path = os.readlink(fullpath)
            if isinstance(symlink_path, unicode):
                symlink_path = symlink_path.encode(self.output_encoding)
            else:
                # validate filename
                symlink_path = symlink_path.decode(self.input_encoding).encode(self.output_encoding)
            size = len(symlink_path)
        elif stat.S_ISREG(statres.st_mode):
            size = statres.st_size
        else:
            size = 0

        # very common error, so check sooner
        if size > 0xffffffff:
            raise CPIOException('Too big file size for this CPIO format', statres.st_size)

        if size != statres.st_size:
            log.warning('Replacing size of stat struct %d => %d', statres.st_size, size)
            statres._replace(st_size=size)

        if isinstance(fullpath, unicode):
            cpio_filename = fullpath.encode(self.output_encoding)
        else:
            # validate filename
            cpio_filename = fullpath.decode(self.input_encoding).encode(self.output_encoding)

        # TODO: fullpath == '.' (!)
        if cpio_filename.startswith(b'./'):
            cpio_filename = cpio_filename[1:]
        elif not cpio_filename.startswith(b'/'):
            cpio_filename = b'/' + cpio_filename

        self._write_header(statres, cpio_filename)

        if stat.S_ISDIR(statres.st_mode):
            return

        if stat.S_ISLNK(statres.st_mode):
            self._align()
            self._outwrite(symlink_path)
            return

        #TODO: splice
        if stat.S_ISREG(statres.st_mode):
            if not size:
                return
            self._align()
            with open(fullpath, 'rbe') as xxx:
                while size:
                    chunk = xxx.read(65536)
                    if not chunk:
                        break
                    self._outwrite(chunk)
                    size -= len(chunk)
            if size:
                raise CPIOException('File was changed while reading', fullpath)
            return

        raise CPIOException('Unknown file type', statres.st_mode)

    def _write_header(self, statres, cpio_filename):
        cpio_filename += b'\x00'

        fields = [
            statres.st_ino,
            statres.st_mode,
            statres.st_uid,
            statres.st_gid,
            statres.st_nlink,
            statres.st_mtime,
            statres.st_size,
            os.major(statres.st_dev),
            os.minor(statres.st_dev),
            os.major(statres.st_rdev),
            os.minor(statres.st_rdev),
            # Yes, length including last zero byte
            len(cpio_filename),
            # New CRC Format
            #  The CRC format is identical to the new ASCII format described in the pre-
            #  vious section except that the magic field is set to ``070702'' and the
            #  check field is set to the sum of all bytes in the file data.  This sum is
            #  computed treating all bytes as unsigned values and using unsigned arith-
            #  metic.  Only the least-significant 32 bits of the sum are stored.
            # BUGS
            #  The ``CRC'' format is mis-named, as it uses a simple checksum and not a
            #  cyclic redundancy check.
            0,
        ]

        self._align()
        self._outwrite(b'070701')
        # writelines will not add newlines. stupid function name
        for (n, i) in enumerate(fields):
            # UNIX epoch overflow, negative timestamps and so on...
            if (i > 0xffffffff) or (i < 0):
                raise CPIOException('You are looser', n, i)
            self._outwrite(b'{0:08x}'.format(i))
        self._outwrite(cpio_filename)

    def inject_path(self, path):
        """
        :type path: basestring
        """
        statres = os.lstat(path)

        ino = self.ino_real2fake[(statres.st_dev, statres.st_ino)]

        if self.save_mtime:
            # statres.st_mtime may be floating point
            mtime = int(statres.st_mtime)
        else:
            # mtime = 0 may make some programs crazy...
            mtime = 1

        if self.save_uid_gid:
            uid = statres.st_uid
            gid = statres.st_gid
        else:
            uid = 0
            gid = 0

        if stat.S_ISDIR(statres.st_mode):
            nlink = 2
        else:
            nlink = 1

        if stat.S_ISREG(statres.st_mode) or stat.S_ISLNK(statres.st_mode):
            size = statres.st_size
        else:
            size = 0

        newstatres = MyStat(
            st_uid=uid,
            st_gid=gid,
            st_ino=ino,
            st_mtime=mtime,
            st_mode=statres.st_mode,
            st_nlink=nlink,
            st_dev=0,
            st_rdev=statres.st_rdev,
            st_size=size,
        )

        if (statres.st_nlink == 1) or stat.S_ISDIR(statres.st_mode):
            self._write_file_contents(newstatres, path)
        else:
            # hardlinks will be handled later, as we can not know if it is intermediate item or last
            htuple = self.ino2htuple.setdefault(ino, (newstatres, []))
            htuple[1].append(path)

    def _hardlinks_handle(self):
        # handle hardlinks
        if self.ino2htuple:
            log.debug('Writing hardlinks')
        for (statres, fullpaths) in self.ino2htuple.itervalues():
            statres._replace(st_nlink=len(fullpaths))
            fake_statres = MyStat(statres[:])
            fake_statres._replace(st_size=0)
            # all fullpaths except last
            for fullpath in fullpaths[:-1]:
                self._write_file_contents(fake_statres, fullpath)
            self._write_file_contents(statres, fullpaths[-1])

    def _write_trailer(self):
        statres = MyStat(
            st_uid=0,
            st_gid=0,
            st_ino=0,
            st_mtime=0,
            st_mode=0,
            st_nlink=0,
            st_dev=0,
            st_rdev=0,
            st_size=0,
        )
        self._write_header(statres, b'TRAILER!!!')
        # for really buggy cpio unpacker implementations...
        self._align()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.finalize()

    def finalize(self):
        self._hardlinks_handle()
        self._write_trailer()


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
