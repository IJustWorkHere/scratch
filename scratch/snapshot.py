#!/usr/bin/env python
# Based on the Watchdog PollingObserver
# Will take a snapshot of a given directory and compare it to a historical snapshot
# if available and return the difference

# Python Imports
import logging
import argparse
import inspect
import hashlib
import os
import shutil
import errno
from stat import S_ISDIR
import cPickle as pickle

logging.basicConfig(level=logging.INFO,
                    filename='log_file_name',
                    format='%(asctime)s - %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)

class Stat(object):

    def __init__(self, path):
        st = os.stat(path)
        self.st_mode = st.st_mode
        self.st_ino = st.st_ino
        self.st_dev = st.st_dev
        self.st_fhash = self._hash(path)

    def _hash(self, file):
        if S_ISDIR(self.st_mode):
            return
        BLOCKSIZE = 65536
        hash = hashlib.md5()
        with open(file, 'rb') as hash_file:
            buf = hash_file.read(BLOCKSIZE)
            while len(buf) > 0:
                hash.update(buf)
                buf = hash_file.read(BLOCKSIZE)
            return hash.hexdigest()

class DirectorySnapshotDiff(object):

    def __init__(self, ref, snapshot):
        created = snapshot.paths - ref.paths
        deleted = ref.paths - snapshot.paths

        for path in ref.paths & snapshot.paths:
            if ref.inode(path) != snapshot.inode(path):
                created.add(path)
                deleted.add(path)

        moved = set()
        for path in set(deleted):
            inode = ref.inode(path)
            new_path = snapshot.path(inode)
            if new_path:
                deleted.remove(path)
                moved.add((path, new_path))

        for path in set(created):
            inode = snapshot.inode(path)
            old_path = ref.path(inode)
            if old_path:
                created.remove(path)
                moved.add((old_path, path))

        modified = set()
        for path in ref.paths & snapshot.paths:
            if ref.inode(path) == snapshot.inode(path):
                if ref.fhash(path) != snapshot.fhash(path):
                    modified.add(path)

        for (old_path, new_path) in moved:
            if ref.fhash(old_path) != snapshot.fhash(new_path):
                modified.add(old_path)

        self._dirs_created = [path for path in created if snapshot.isdir(path)]
        self._dirs_deleted = [path for path in deleted if ref.isdir(path)]
        self._dirs_modified = [path for path in modified if ref.isdir(path)]
        self._dirs_moved = [(frm, to) for (frm, to) in moved if ref.isdir(frm)]

        self._files_created = list(created - set(self._dirs_created))
        self._files_deleted = list(deleted - set(self._dirs_deleted))
        self._files_modified = list(modified - set(self._dirs_modified))
        self._files_moved = list(moved - set(self._dirs_moved))

    @property
    def files_created(self):
        return self._files_created

    @property
    def files_deleted(self):
        return self._files_deleted

    @property
    def files_modified(self):
        return self._files_modified

    @property
    def files_moved(self):
        return self._files_moved

    @property
    def dirs_modified(self):
        return self._dirs_modified

    @property
    def dirs_moved(self):
        return self._dirs_moved

    @property
    def dirs_deleted(self):
        return self._dirs_deleted

    @property
    def dirs_created(self):
        return self._dirs_created

class DirectorySnapshot(object):

    def __init__(self, path):
        self._stat_info = {}
        self._inode_to_path = {}

        st = Stat(path)
        self._stat_info[path] = st
        self._inode_to_path[(st.st_ino, st.st_dev)] = path

        def walk(root):
            try:
                paths = [os.path.join(root, name) for name in os.listdir(root)]
            except OSError as e:
                if e.errno == errno.ENOENT:
                    return
                else:
                    raise

            entries = []
            for p in paths:
                try:
                    entries.append((p, Stat(p)))
                except OSError:
                    continue

            for _ in entries:
                yield _

            for path, st in entries:
                if S_ISDIR(st.st_mode):
                    for _ in walk(path):
                        yield _

        for p, st in walk(path):
            i = (st.st_ino, st.st_dev)
            self._inode_to_path[i] = p
            self._stat_info[p] = st

    @property
    def paths(self):
        return set(self._stat_info.keys())

    def path(self, id):
        return self._inode_to_path.get(id)

    def inode(self, path):
        st = self._stat_info[path]
        return (st.st_ino, st.st_dev)

    def isdir(self, path):
        return S_ISDIR(self._stat_info[path].st_mode)

    def fhash(self, path):
        return self._stat_info[path].st_fhash

    def stat_info(self, path):
        return self._stat_info[path]

    def __sub__(self, previous_dirsnap):
        return DirectorySnapshotDiff(previous_dirsnap, self)

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return str(self._stat_info)

class Main(object):

    def __init__(self):
        self._changed = False
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        for name in dir(self):
            if not name.startswith("_"):
                p = subparsers.add_parser(name)
                method = getattr(self, name)
                argnames = inspect.getargspec(method).args[1:]
                for argname in argnames:
                    p.add_argument(argname)
                p.set_defaults(func=method, argnames=argnames)
        self.args = parser.parse_args()

    def __call__(self):
        a = self.args
        callargs = [getattr(a, name) for name in a.argnames]
        try:
            return self.args.func(*callargs)
        except Exception as e:
            logger.exception(e)
            print e

    def _file_name(self, path):
        base = '/some/path'
        file = '.' + str(path).replace(os.path.sep, "_")
        return os.path.join(base, file)

    def _write_pickle(self, file, data):
        tmp = file + '.tmp'
        with open(tmp, 'wb') as f:
            pickle.dump(data, f)
        shutil.move(tmp, file)

    def _read_pickle(self, file):
        try:
            with open(file, 'rb') as f:
                return pickle.load(f)
        except (ValueError, EOFError, IOError) as e:
            logger.error("Unable to load {0}. {1}".format(file, e))

    def _log_changes(self, snapshotdiff):
        for name in dir(snapshotdiff):
            if not name.startswith("_"):
                attr = getattr(snapshotdiff, name)
                if len(attr) > 0:
                    self._changed = True
                    [logger.info("{0}: {1}".format(name, str(path))) for path in attr]

    def check(self, path):
        file = self._file_name(path)
        ref = self._read_pickle(file)
        snapshot = DirectorySnapshot(path)
        snapshotdiff = DirectorySnapshotDiff(ref, snapshot)
        self._log_changes(snapshotdiff)
        self._write_pickle(file, snapshot)
        print self._changed

if __name__ == '__main__':
    main = Main()
    main()