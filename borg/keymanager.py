import argparse
from binascii import hexlify, unhexlify, a2b_base64, b2a_base64
import binascii
import textwrap
from hashlib import sha256

from .key import KeyfileKey, RepoKey, PassphraseKey, KeyfileNotFoundError, PlaintextKey
from .helpers import Manifest, NoManifestError, Error, EXIT_SUCCESS, EXIT_WARNING, EXIT_ERROR, location_validator
from .repository import Repository
from .archiver import with_repository
from .logger import create_logger, setup_logging


logger = create_logger()


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
                    print('line checksum did not match, try same line again')
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
                    print('line checksum did not match, try line {0} again'.format(idx))
                    continue

                result += part
                if idx == lines:
                    break
                idx += 1

        except EOFError:
            print('\n - aborted')
            return

        if sha256_truncated(result, 12) != id_complete_checksum:
            print('The overall checksum did not match, aborting.')
            return

        self.keyblob = '\n'.join(textwrap.wrap(b2a_base64(result).decode('ascii'))) + '\n'

        self.store_keyblob(args)


class KeyParser:
    @with_repository(lock=False, exclusive=False, manifest=False, cache=False)
    def do_key_export(self, args, repository):
        """Export the repository key for backup"""
        manager = KeyManager(repository)
        manager.load_keyblob()
        if args.paper:
            manager.export_paperkey(args.path)
        else:
            if not args.path:
                logger.error("output file to export key to expected")
                return EXIT_ERROR
            manager.export(args.path)
        return EXIT_SUCCESS

    @with_repository(lock=False, exclusive=False, manifest=False, cache=False)
    def do_key_import(self, args, repository):
        """Export the repository key for backup"""
        manager = KeyManager(repository)
        if args.paper:
            if args.path:
                logger.error("with --paper import from file is not supported")
                return EXIT_ERROR
            manager.import_paperkey(args)
        else:
            if not args.path:
                logger.error("input file to import key from expected")
                return EXIT_ERROR
            manager.import_keyfile(args)
        return EXIT_SUCCESS


    def build_subparser(self, key_parsers, common_parser):
        subparser = key_parsers.add_parser('export', parents=[common_parser],
                                        description=self.do_key_export.__doc__,
                                        epilog="",
                                        formatter_class=argparse.RawDescriptionHelpFormatter,
                                        help='export repository key for backup')
        subparser.set_defaults(func=self.do_key_export)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                            type=location_validator(archive=False))
        subparser.add_argument('path', metavar='PATH', nargs='?', type=str,
                            help='where to store the backup')
        subparser.add_argument('--paper', dest='paper', action='store_true',
                            default=False,
                            help='Create an export suitable for printing and later type-in')

        subparser = key_parsers.add_parser('import', parents=[common_parser],
                                        description=self.do_key_import.__doc__,
                                        epilog="",
                                        formatter_class=argparse.RawDescriptionHelpFormatter,
                                        help='import repository key from backup')
        subparser.set_defaults(func=self.do_key_import)
        subparser.add_argument('location', metavar='REPOSITORY', nargs='?', default='',
                            type=location_validator(archive=False))
        subparser.add_argument('path', metavar='PATH', nargs='?', type=str,
                            help='path to the backup')
        subparser.add_argument('--paper', dest='paper', action='store_true',
                            default=False,
                            help='interactively import from a backup done with --paper')
