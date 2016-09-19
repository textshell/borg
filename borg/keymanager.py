from binascii import hexlify, unhexlify, a2b_base64, b2a_base64
import binascii
import textwrap
from hashlib import sha256

from .key import KeyfileKey, RepoKey, PassphraseKey, KeyfileNotFoundError, PlaintextKey
from .helpers import Manifest, NoManifestError, Error
from .repository import Repository


class UnencryptedRepo(Error):
    """Keymanagement not available for unencrypted repositories."""


class UnknownKeyType(Error):
    """Keytype {0} is unknown."""


class RepoIdMismatch(Error):
    """This key backup seems to be for a different backup repository, aborting."""


class NotABorgKeyFile(Error):
    """This file is not a borg key backup, aborting."""


def sha256_truncated(data, num):
    h = sha256()
    h.update(data)
    return h.hexdigest()[:num]


KEYBLOB_LOCAL = 'local'
KEYBLOB_REPO = 'repo'


class KeyManager:
    def __init__(self, repository):
        self.repository = repository
        self.keyblob = None
        self.keyblob_storage = None

        try:
            cdata = self.repository.get(Manifest.MANIFEST_ID)
        except Repository.ObjectNotFound:
            raise NoManifestError

        key_type = cdata[0]
        if key_type == KeyfileKey.TYPE:
            self.keyblob_storage = KEYBLOB_LOCAL
        elif key_type == RepoKey.TYPE or key_type == PassphraseKey.TYPE:
            self.keyblob_storage = KEYBLOB_REPO
        elif key_type == PlaintextKey.TYPE:
            raise UnencryptedRepo()
        else:
            raise UnknownKeyType(key_type)

    def load_keyblob(self):
        if self.keyblob_storage == KEYBLOB_LOCAL:
            k = KeyfileKey(self.repository)
            target = k.find_key()
            with open(target, 'r') as fd:
                self.keyblob = ''.join(fd.readlines()[1:])

        elif self.keyblob_storage == KEYBLOB_REPO:
            self.keyblob = self.repository.load_key()

    def store_keyblob(self, args):
        if self.keyblob_storage == KEYBLOB_LOCAL:
            k = KeyfileKey(self.repository)
            try:
                target = k.find_key()
            except KeyfileNotFoundError:
                target = k.get_new_target(args)

            self.store_keyfile(target)
        elif self.keyblob_storage == KEYBLOB_REPO:
            self.repository.save_key(self.keyblob)

    def store_keyfile(self, target):
        with open(target, 'w') as fd:
            fd.write('%s %s\n' % (KeyfileKey.FILE_ID, hexlify(self.repository.id).decode('ascii')))
            fd.write(self.keyblob)
            if not self.keyblob.endswith('\n\n'):
                fd.write('\n')

    def export(self, path):
        self.store_keyfile(path)

    def export_paperkey(self, path):
        def grouped(s):
            ret = ''
            i = 0
            for ch in s:
                if i and i % 6 == 0:
                    ret += ' '
                ret += ch
                i += 1
            return ret

        export = 'To restore key use borg key-import --paper /path/to/repo\n\n'

        binary = a2b_base64(self.keyblob)
        export += 'BORG PAPER KEY v1\n'
        lines = (len(binary) + 17) // 18
        repoid = hexlify(self.repository.id).decode('ascii')[:18]
        complete_checksum = sha256_truncated(binary, 12)
        export += 'id: {0:d} / {1} / {2} - {3}\n'.format(lines,
                                       grouped(repoid),
                                       grouped(complete_checksum),
                                       sha256_truncated((str(lines) + '/' + repoid + '/' + complete_checksum).encode('ascii'), 2))
        idx = 0
        while len(binary):
            idx += 1
            binline = binary[:18]
            checksum = sha256_truncated(idx.to_bytes(2, byteorder='big') + binline, 2)
            export += '{0:2d}: {1} - {2}\n'.format(idx, grouped(hexlify(binline).decode('ascii')), checksum)
            binary = binary[18:]

        if path:
            with open(path, 'w') as fd:
                fd.write(export)
        else:
            print(export)

    def import_keyfile(self, args):
        file_id = KeyfileKey.FILE_ID
        first_line = file_id + ' ' + hexlify(self.repository.id).decode('ascii') + '\n'
        with open(args.path, 'r') as fd:
            file_first_line = fd.read(len(first_line))
            if file_first_line != first_line:
                if file_first_line.startswith(file_id):
                    raise NotABorgKeyFile()
                else:
                    raise RepoIdMismatch()
            self.keyblob = fd.read()

        self.store_keyblob(args)

    def import_paperkey(self, args):
        # imported here because it has global side effects
        import readline

        try:
            repoid = hexlify(self.repository.id).decode('ascii')[:18]

            while True:
                idline = input('id: ')
                try:
                    (data, checksum) = idline.replace(' ', '').split('-')
                except ValueError:
                    print('each line must contain exactly one \'-\', try again')
                    continue

                try:
                    (id_lines, id_repoid, id_complete_checksum) = data.split('/')
                except ValueError:
                    print('the id line contains three \'/\', try again')

                if sha256_truncated(data.lower().encode('ascii'), 2) != checksum:
                    print('checksum did not match, try same line again')
                    continue

                try:
                    lines = int(id_lines)
                except ValueError:
                    print('internal error while parsing length')

                break

            if repoid != id_repoid:
                raise RepoIdMismatch()

            result = b''

            idx = 1
            while True:
                inline = input('{0:2d}: '.format(idx))
                inline = inline.replace(' ', '')
                try:
                    (data, checksum) = inline.split('-')
                except ValueError:
                    print('each line must contain exactly one \'-\', try again')
                    continue

                try:
                    part = unhexlify(data)
                except binascii.Error:
                    print('only characters 0-9 and a-f and \'-\' are valid, try again')
                    continue

                if sha256_truncated(idx.to_bytes(2, byteorder='big') + part, 2) != checksum:
                    print('checksum did not match, try line {0} again'.format(idx))
                    continue

                result += part
                if idx == lines:
                    break
                idx += 1

        except EOFError:
            print('\n - aborted')
            return

        if sha256_truncated(result, 12) != id_complete_checksum:
            print('The complete checksum did not match, aborting.')
            return

        self.keyblob = '\n'.join(textwrap.wrap(b2a_base64(result).decode('ascii'))) + '\n'

        self.store_keyblob(args)
