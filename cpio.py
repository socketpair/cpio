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
    'symlink_path', # bytes (!)
    'host_filename', # unicode or bytes
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

    def _write_file_contents(self, statres, cpio_filename):
        """
        :type statres: MyStat
        :type cpio_filename: bytes
        """

        if stat.S_ISLNK(statres.st_mode):
            size = len(statres.symlink_path)
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

        if cpio_filename == b'TRAILER!!!':
            raise CPIOException('Attempt to pass reserved filename', cpio_filename)

        self._write_header(statres, cpio_filename)

        # hardlinks, empty files and directories fall here
        if not size:
            return

        if stat.S_ISLNK(statres.st_mode):
            self._align()
            self._outwrite(statres.symlink_path)
            return

        #TODO: splice
        if stat.S_ISREG(statres.st_mode):
            self._align()
            with open(statres.host_filename, 'rbe') as xxx:
                while size:
                    chunk = xxx.read(65536)
                    if not chunk:
                        break
                    self._outwrite(chunk)
                    size -= len(chunk)
            if size:
                raise CPIOException('File was changed while reading', statres.host_filename)
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

    def inject_path(self, path, root='/'):
        """
        :type path: basestring
        """
        # TODO: check that:
        # new file will not be written by existing symlink
        # archive contains all needed dirs
        # is not duplicate of another file in archive

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
            nlink = statres.st_nlink

        if stat.S_ISREG(statres.st_mode) or stat.S_ISLNK(statres.st_mode):
            size = statres.st_size
        else:
            size = 0

        if stat.S_ISLNK(statres.st_mode):
            symlink_path = os.readlink(path)
            if not isinstance(symlink_path, unicode):
                symlink_path = symlink_path.decode(self.input_encoding)
            symlink_path = symlink_path.encode(self.output_encoding)
        else:
            symlink_path = None

        nnn = os.path.normpath(root)
        if nnn != root:
            raise ValueError('Please normalize path before passing it to CPIO %r vs %r', nnn, root)

        if not path.startswith(root):
            raise ValueError('Invalid root or path value', path, root)

        cpio_filename = path[len(root):]
        if not cpio_filename:
            cpio_filename = u'.'

        if not isinstance(cpio_filename, unicode):
            cpio_filename = cpio_filename.decode(self.input_encoding)

        if cpio_filename.startswith(u'/'):
            cpio_filename = cpio_filename[1:]

        cpio_filename = cpio_filename.encode(self.output_encoding)

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
            symlink_path=symlink_path,
            host_filename=path,
        )

        # TODO: check if OS lie about hardlink count
        if (nlink == 1) or stat.S_ISDIR(statres.st_mode):
            self._write_file_contents(newstatres, cpio_filename)
        else:
            # hardlinks will be handled later, as we can not know if it is intermediate item or last
            log.debug('Detected potential hardlink %r (%r)', path, cpio_filename)
            htuple = self.ino2htuple.setdefault(ino, (newstatres, []))
            htuple[1].append(cpio_filename)

    def _hardlinks_handle(self):
        # handle hardlinks
        if self.ino2htuple:
            log.debug('Writing hardlinks')
        for (statres, cpio_filenames) in self.ino2htuple.itervalues():
            lnk_count = len(cpio_filenames)
            if lnk_count > statres.st_nlink:
                raise CPIOException('Found more hardlinks (%r) than host FS reports (%r). See %r', cpio_filenames,
                                    statres.st_nlink, statres.host_filename)
            if lnk_count < statres.st_nlink:
                log.info('Found fewer hardlinks: %r than host FS reports (%r). See %r', cpio_filenames,
                         statres.st_nlink, statres.host_filename)
            statres._replace(st_nlink=lnk_count)
            fake_statres = MyStat(*statres)
            fake_statres._replace(st_size=0)

            last_cpio_filename = cpio_filenames.pop()
            for cpio_filename in cpio_filenames:
                self._write_file_contents(fake_statres, cpio_filename)
            self._write_file_contents(statres, last_cpio_filename)

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
            symlink_path=None,
            host_filename=None,
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

    def superinject(self, src):
        def _walkhandler(error):
            raise error

        if isinstance(src, basestring):
            src = [src]

        for root in src:
            if os.path.islink(root):
                raise ValueError('Attempt to super-inject by symlink', root)
            if not os.path.isdir(root):
                raise ValueError('Attempt to super-inject by non-dir', root)
            self.inject_path(root, root)
            for (prefix, dirs, files) in os.walk(root, onerror=_walkhandler):
                for item in itertools.chain(files, dirs):
                    self.inject_path(os.path.join(prefix, item), root)

#from gzip import GzipFile
#
#with GzipFile('test.gz', 'wbe', 9, dst) as dst:
#    with CPIO(dst) as cpio:
#        cpio.superibject(src, True)
