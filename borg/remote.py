import errno
import fcntl
import inspect, functools
import logging
import os
import select
import shlex
from subprocess import Popen, PIPE
import sys
import tempfile

from . import __version__

from .helpers import Error, IntegrityError, sysinfo
from .repository import Repository

import msgpack

RPC_PROTOCOL_VERSION = 2
BORG_VERSION = (1, 0, 7)

BUFSIZE = 10 * 1024 * 1024


class ConnectionClosed(Error):
    """Connection closed by remote host"""


class ConnectionClosedWithHint(ConnectionClosed):
    """Connection closed by remote host. {}"""


class PathNotAllowed(Error):
    """Repository path not allowed"""


class InvalidRPCMethod(Error):
    """RPC method {} is not valid"""


# Protocol compatibility:
# In general the server is responsible for rejecting too old clients and the client it responsible for rejecting
# too old servers. This ensures that the knowleadge what is compatible is always held by the newer component.
#
# The server can do checks for the client version in RepositoryServer.negotiate. If the client_data is 2 then then
# client is in the version range [0.29.0, 1.0.6] inclusiv. For newer clients client_data is a dict which contains
# client_version.
#
# For the client the return of the negotiate method is either 2 if the server is in the version range [0.29.0, 1.0.6]
# inclusiv, or it is a dict which includes the server version.
#
# All method calls on the remote repository object must be whitelisted in RepositoryServer.rpc_methods and have api
# stubs in RemoteRepository. The @api decorator on these stubs is used to set server version requirements.
#
# Method parameters are identfied only by name and never by position. Unknown parameters are ignored by the server side.
# If a new parameter is important and may not be ignored, on the client a parameter specific version requirement needs
# to be added.
# When parameters are removed, they need to be preserved  as defaulted parameters on the client stubs so that older
# servers still get the from them still needed parameters.


compatMap = {
    'check' : ['repair', 'save_space'],
    'commit': ["save_space"],
    'rollback': [],
    'destroy': [],
    '__len__': [],
    'list': ["limit", "marker"],
    'put': ["id_", "data"],
    'get': ["id_"],
    'delete': ["id_"],
    'save_key': ["keydata"],
    'load_key': [],
    'break_lock': [],
    'negotiate': ['client_data'],
    'open': ['path', 'create', 'lock_wait', 'lock']
}


def decodeKeys(d):
    r = {}
    for (k, v) in d.items():
        r[k.decode("utf-8")] = v
    return r

class RepositoryServer:  # pragma: no cover
    rpc_methods = (
        '__len__',
        'check',
        'commit',
        'delete',
        'destroy',
        'get',
        'list',
        'negotiate',
        'open',
        'put',
        'rollback',
        'save_key',
        'load_key',
        'break_lock',
    )

    def __init__(self, restrict_to_paths, append_only):
        self.repository = None
        self.restrict_to_paths = restrict_to_paths
        self.append_only = append_only
        self.client_version = (1, 0, 6)

    def positionalToNamed(self, method, argv):
        kwargs = {}
        for (pos, name) in enumerate(compatMap[method]):
            kwargs[name] = argv[pos]

        return kwargs

    def filterArgs(self, f, kwargs):
        filtered = {}
        known = set(inspect.signature(f).parameters)
        for (name, value) in kwargs.items():
            if name in known:
                filtered[name] = value
        return filtered

    def serve(self):
        stdin_fd = sys.stdin.fileno()
        stdout_fd = sys.stdout.fileno()
        stderr_fd = sys.stdout.fileno()
        # Make stdin non-blocking
        fl = fcntl.fcntl(stdin_fd, fcntl.F_GETFL)
        fcntl.fcntl(stdin_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        # Make stdout blocking
        fl = fcntl.fcntl(stdout_fd, fcntl.F_GETFL)
        fcntl.fcntl(stdout_fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
        # Make stderr blocking
        fl = fcntl.fcntl(stderr_fd, fcntl.F_GETFL)
        fcntl.fcntl(stderr_fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
        unpacker = msgpack.Unpacker(use_list=False)
        while True:
            r, w, es = select.select([stdin_fd], [], [], 10)
            if r:
                data = os.read(stdin_fd, BUFSIZE)
                if not data:
                    self.repository.close()
                    return
                unpacker.feed(data)
                for unpacked in unpacker:
                    if isinstance(unpacked, dict):
                        dictFormat = True
                        msgid = unpacked[b"i"]
                        method = unpacked[b"m"].decode('ascii')
                        args = decodeKeys(unpacked[b"a"])
                    elif isinstance(unpacked, tuple) and len(unpacked) == 4:
                        dictFormat = False
                        type, msgid, method, args = unpacked
                        method = method.decode('ascii')
                        args = self.positionalToNamed(method, args)
                    else:
                        self.repository.close()
                        raise Exception("Unexpected RPC data format.")
                    try:
                        if method not in self.rpc_methods:
                            raise InvalidRPCMethod(method)
                        try:
                            f = getattr(self, method)
                        except AttributeError:
                            f = getattr(self.repository, method)
                        args = self.filterArgs(f, args)
                        res = f(**args)
                    except BaseException as e:
                        # These exceptions are reconstructed on the client end in RemoteRepository.call_many(),
                        # and will be handled just like locally raised exceptions. Suppress the remote traceback
                        # for these, except ErrorWithTraceback, which should always display a traceback.
                        if not isinstance(e, (Repository.DoesNotExist, Repository.AlreadyExists, PathNotAllowed)):
                            logging.exception('Borg %s: exception in RPC call:', __version__)
                            logging.error(sysinfo())
                        exc = "Remote Exception (see remote log for the traceback)"
                        if dictFormat:
                            os.write(stdout_fd, msgpack.packb({b'i': msgid, b'exception_class': e.__class__.__name__, b'exception_args': e.args}))
                        else:
                            os.write(stdout_fd, msgpack.packb((1, msgid, e.__class__.__name__, exc)))
                    else:
                        if dictFormat:
                            os.write(stdout_fd, msgpack.packb({b'i': msgid, b'r': res}))
                        else:
                            os.write(stdout_fd, msgpack.packb((1, msgid, None, res)))
            if es:
                self.repository.close()
                return

    def negotiate(self, client_data):
        if client_data == RPC_PROTOCOL_VERSION:
            return RPC_PROTOCOL_VERSION
        elif isinstance(client_data, dict):
            self.client_version = client_data[b"client_version"]
            return { "server_version": BORG_VERSION }

    def open(self, path, create=False, lock_wait=None, lock=True):
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        if path.startswith('/~'):
            path = path[1:]
        path = os.path.realpath(os.path.expanduser(path))
        if self.restrict_to_paths:
            for restrict_to_path in self.restrict_to_paths:
                if path.startswith(os.path.realpath(restrict_to_path)):
                    break
            else:
                raise PathNotAllowed(path)
        self.repository = Repository(path, create, lock_wait=lock_wait, lock=lock, append_only=self.append_only)
        self.repository.__enter__()  # clean exit handled by serve() method
        return self.repository.id


def api(*, since, **kwargs):
    def decorator(f):
        @functools.wraps(f)
        def do_rpc(self, *args, **kwargs):
            sig = inspect.signature(f)
            bound_args = sig.bind(self, *args, **kwargs)
            named = {}
            for name, param in sig.parameters.items():
                if name == 'self':
                    continue
                if name in bound_args.arguments:
                    named[name] = bound_args.arguments[name]
                else:
                    if param.default is not param.empty:
                        named[name] = param.default

            if self.server_version < since:
                raise self.RPCError("Server too old. Need at least: " + ".".join([str(c) for c in since]))

            for name, restriction in kwargs.items():
                if 'previously' in restriction and named[name] == restriction['previously']:
                    continue

                raise self.RPCError("Server too old. Need at least: " + ".".join([str(c) for c in restriction['since']]))

            return self.call(f.__name__, named)
        return do_rpc
    return decorator


class RemoteRepository:
    extra_test_args = []

    class RPCError(Exception):
        def __init__(self, name):
            self.name = name

    def __init__(self, location, create=False, lock_wait=None, lock=True, args=None):
        self.location = self._location = location
        self.preload_ids = []
        self.msgid = 0
        self.to_send = b''
        self.get_cache = {}
        self.ignore_responses = set()
        self.responses = {}
        self.unpacker = msgpack.Unpacker(use_list=False)
        self.dictFormat = False
        self.server_version = (1, 0, 6)
        self.p = None
        testing = location.host == '__testsuite__'
        borg_cmd = self.borg_cmd(args, testing)
        env = dict(os.environ)
        if not testing:
            borg_cmd = self.ssh_cmd(location) + borg_cmd
            # pyinstaller binary adds LD_LIBRARY_PATH=/tmp/_ME... but we do not want
            # that the system's ssh binary picks up (non-matching) libraries from there
            env.pop('LD_LIBRARY_PATH', None)
        env.pop('BORG_PASSPHRASE', None)  # security: do not give secrets to subprocess
        self.p = Popen(borg_cmd, bufsize=0, stdin=PIPE, stdout=PIPE, stderr=PIPE, env=env)
        self.stdin_fd = self.p.stdin.fileno()
        self.stdout_fd = self.p.stdout.fileno()
        self.stderr_fd = self.p.stderr.fileno()
        fcntl.fcntl(self.stdin_fd, fcntl.F_SETFL, fcntl.fcntl(self.stdin_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        fcntl.fcntl(self.stdout_fd, fcntl.F_SETFL, fcntl.fcntl(self.stdout_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        fcntl.fcntl(self.stderr_fd, fcntl.F_SETFL, fcntl.fcntl(self.stderr_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        self.r_fds = [self.stdout_fd, self.stderr_fd]
        self.x_fds = [self.stdin_fd, self.stdout_fd, self.stderr_fd]

        try:
            version = self.call('negotiate', { 'client_data': { b'client_version': BORG_VERSION } } )
        except ConnectionClosed:
            raise ConnectionClosedWithHint('Is borg working on the server?') from None
        if version == RPC_PROTOCOL_VERSION:
            self.dictFormat = False
        elif isinstance(version, dict) and b"server_version" in version:
            self.dictFormat = True
            self.server_version = version[b"server_version"]
        else:
            raise Exception('Server insisted on using unsupported protocol version %s' % version)
        try:
            self.id = self.open(path=self.location.path, create=create, lock_wait=lock_wait, lock=lock)
        except Exception:
            self.close()
            raise

    def __del__(self):
        if self.p:
            self.close()
            assert False, "cleanup happened in Repository.__del__"

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.location.canonical_path())

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type is not None:
                self.rollback()
        finally:
            # in any case, we want to cleanly close the repo, even if the
            # rollback can not succeed (e.g. because the connection was
            # already closed) and raised another exception:
            self.close()

    def borg_cmd(self, args, testing):
        """return a borg serve command line"""
        # give some args/options to "borg serve" process as they were given to us
        opts = []
        if args is not None:
            opts.append('--umask=%03o' % args.umask)
            root_logger = logging.getLogger()
            if root_logger.isEnabledFor(logging.DEBUG):
                opts.append('--debug')
            elif root_logger.isEnabledFor(logging.INFO):
                opts.append('--info')
            elif root_logger.isEnabledFor(logging.WARNING):
                pass  # warning is default
            elif root_logger.isEnabledFor(logging.ERROR):
                opts.append('--error')
            elif root_logger.isEnabledFor(logging.CRITICAL):
                opts.append('--critical')
            else:
                raise ValueError('log level missing, fix this code')
        if testing:
            return [sys.executable, '-m', 'borg.archiver', 'serve'] + opts + self.extra_test_args
        else:  # pragma: no cover
            remote_path = args.remote_path or os.environ.get('BORG_REMOTE_PATH', 'borg')
            return [remote_path, 'serve'] + opts

    def ssh_cmd(self, location):
        """return a ssh command line that can be prefixed to a borg command line"""
        args = shlex.split(os.environ.get('BORG_RSH', 'ssh'))
        if location.port:
            args += ['-p', str(location.port)]
        if location.user:
            args.append('%s@%s' % (location.user, location.host))
        else:
            args.append('%s' % location.host)
        return args

    def namedToPositional(self, method, kwargs):
        argv = []
        for name in compatMap[method]:
            argv.append(kwargs[name])
        return argv

    def call(self, cmd, args, **kw):
        for resp in self.call_many(cmd, [args], **kw):
            return resp

    def call_many(self, cmd, calls, wait=True):
        if not calls:
            return

        def fetch_from_cache(args):
            msgid = self.get_cache[args].pop(0)
            if not self.get_cache[args]:
                del self.get_cache[args]
            return msgid

        def handle_error(error, args):
            if error == b'DoesNotExist':
                raise Repository.DoesNotExist(self.location.orig)
            elif error == b'AlreadyExists':
                raise Repository.AlreadyExists(self.location.orig)
            elif error == b'CheckNeeded':
                raise Repository.CheckNeeded(self.location.orig)
            elif error == b'IntegrityError':
                raise IntegrityError(args)
            elif error == b'PathNotAllowed':
                raise PathNotAllowed(*args)
            elif error == b'ObjectNotFound':
                raise Repository.ObjectNotFound(args[0], self.location.orig)
            elif error == b'InvalidRPCMethod':
                raise InvalidRPCMethod(*args)
            else:
                if isinstance(args, bytes):
                    raise self.RPCError(args.decode('utf-8'))
                else:
                    raise self.RPCError(args[0].decode('utf-8'))

        calls = list(calls)
        waiting_for = []
        w_fds = [self.stdin_fd]
        while wait or calls:
            while waiting_for:
                try:
                    unpacked = self.responses.pop(waiting_for[0])
                    waiting_for.pop(0)
                    if b'exception_class' in unpacked:
                        handle_error(unpacked[b'exception_class'], unpacked[b'exception_args'])
                    else:
                        yield unpacked[b'r']
                        if not waiting_for and not calls:
                            return
                except KeyError:
                    break
            r, w, x = select.select(self.r_fds, w_fds, self.x_fds, 1)
            if x:
                raise Exception('FD exception occurred')
            for fd in r:
                if fd is self.stdout_fd:
                    data = os.read(fd, BUFSIZE)
                    if not data:
                        raise ConnectionClosed()
                    self.unpacker.feed(data)
                    for unpacked in self.unpacker:
                        if isinstance(unpacked, dict):
                            msgid = unpacked[b'i']
                        elif isinstance(unpacked, tuple) and len(unpacked) == 4:
                            type, msgid, error, res = unpacked
                            if error:
                                unpacked = {b'i': msgid, b'exception_class': error, b'exception_args': res }  # res is totally wrong, but that is what the old code did
                            else:
                                unpacked = {b'i': msgid, b'r': res }
                        else:
                            raise Exception("Unexpected RPC data format.")
                        if msgid in self.ignore_responses:
                            self.ignore_responses.remove(msgid)
                            if b'exception_class' in unpacked:
                                handle_error(unpacked[b'exception_class'], unpacked[b'exception_args'])
                        else:
                            self.responses[msgid] = unpacked
                elif fd is self.stderr_fd:
                    data = os.read(fd, 32768)
                    if not data:
                        raise ConnectionClosed()
                    data = data.decode('utf-8')
                    for line in data.splitlines(keepends=True):
                        if line.startswith('$LOG '):
                            _, level, msg = line.split(' ', 2)
                            level = getattr(logging, level, logging.CRITICAL)  # str -> int
                            logging.log(level, msg.rstrip())
                        else:
                            sys.stderr.write("Remote: " + line)
            if w:
                while not self.to_send and (calls or self.preload_ids) and len(waiting_for) < 100:
                    if calls:
                        args = calls.pop(0)
                        if cmd == 'get' and args['id_'] in self.get_cache:
                            waiting_for.append(fetch_from_cache(args['id_']))
                        else:
                            self.msgid += 1
                            waiting_for.append(self.msgid)
                            if self.dictFormat:
                                self.to_send = msgpack.packb({b'i': self.msgid, b'm': cmd, b'a': args})
                            else:
                                self.to_send = msgpack.packb((1, self.msgid, cmd, self.namedToPositional(cmd, args)))
                    if not self.to_send and self.preload_ids:
                        args = {'id_': self.preload_ids.pop(0)}
                        self.msgid += 1
                        self.get_cache.setdefault(args['id_'], []).append(self.msgid)
                        if self.dictFormat:
                            self.to_send = msgpack.packb({b'i': self.msgid, b'm': 'get', b'a': args})
                        else:
                            self.to_send = msgpack.packb((1, self.msgid, 'get', self.namedToPositional(cmd, args)))

                if self.to_send:
                    try:
                        self.to_send = self.to_send[os.write(self.stdin_fd, self.to_send):]
                    except OSError as e:
                        # io.write might raise EAGAIN even though select indicates
                        # that the fd should be writable
                        if e.errno != errno.EAGAIN:
                            raise
                if not self.to_send and not (calls or self.preload_ids):
                    w_fds = []
        self.ignore_responses |= set(waiting_for)

    @api(since=(1, 0, 0),
         append_only={'since':(1.0.7), 'prevously':False})
    def open(self, path, create=False, lock_wait=None, lock=True, append_only=False):
        pass

    @api(since=(1, 0, 0))
    def check(self, repair=False, save_space=False):
        pass

    @api(since=(1, 0, 0))
    def commit(self, save_space=False):
        pass

    @api(since=(1, 0, 0))
    def rollback(self, *args):
        pass

    @api(since=(1, 0, 0))
    def destroy(self):
        pass

    @api(since=(1, 0, 0))
    def __len__(self):
        pass

    @api(since=(1, 0, 0))
    def list(self, limit=None, marker=None):
        pass

    def get(self, id_):
        for resp in self.get_many([id_]):
            return resp

    def get_many(self, ids):
        for resp in self.call_many('get', [{'id_': id_} for id_ in ids]):
            yield resp

    @api(since=(1, 0, 0))
    def put(self, id_, data, wait=True):
        pass

    @api(since=(1, 0, 0))
    def delete(self, id_, wait=True):
        pass

    @api(since=(1, 0, 0))
    def save_key(self, keydata):
        pass

    @api(since=(1, 0, 0))
    def load_key(self):
        pass

    @api(since=(1, 0, 0))
    def break_lock(self):
        pass

    def close(self):
        if self.p:
            self.p.stdin.close()
            self.p.stdout.close()
            self.p.wait()
            self.p = None

    def preload(self, ids):
        self.preload_ids += ids


class RepositoryNoCache:
    """A not caching Repository wrapper, passes through to repository.

    Just to have same API (including the context manager) as RepositoryCache.
    """
    def __init__(self, repository):
        self.repository = repository

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get(self, key):
        return next(self.get_many([key]))

    def get_many(self, keys):
        for data in self.repository.get_many(keys):
            yield data


class RepositoryCache(RepositoryNoCache):
    """A caching Repository wrapper

    Caches Repository GET operations using a local temporary Repository.
    """
    # maximum object size that will be cached, 64 kiB.
    THRESHOLD = 2**16

    def __init__(self, repository):
        super().__init__(repository)
        tmppath = tempfile.mkdtemp(prefix='borg-tmp')
        self.caching_repo = Repository(tmppath, create=True, exclusive=True)
        self.caching_repo.__enter__()  # handled by context manager in base class

    def close(self):
        if self.caching_repo is not None:
            self.caching_repo.destroy()
            self.caching_repo = None

    def get_many(self, keys):
        unknown_keys = [key for key in keys if key not in self.caching_repo]
        repository_iterator = zip(unknown_keys, self.repository.get_many(unknown_keys))
        for key in keys:
            try:
                yield self.caching_repo.get(key)
            except Repository.ObjectNotFound:
                for key_, data in repository_iterator:
                    if key_ == key:
                        if len(data) <= self.THRESHOLD:
                            self.caching_repo.put(key, data)
                        yield data
                        break
        # Consume any pending requests
        for _ in repository_iterator:
            pass


def cache_if_remote(repository):
    if isinstance(repository, RemoteRepository):
        return RepositoryCache(repository)
    else:
        return RepositoryNoCache(repository)
