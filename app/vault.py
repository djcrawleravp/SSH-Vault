#!/usr/bin/env python3
"""SSH Vault's KDBX4 persistence, migration, and isolated export.

All durable private material lives in an encrypted KDBX 4 database.  The
legacy keys/ directory is an import INBOX, never runtime configuration.
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
KDBX = ROOT / 'vault.kdbx'
INBOX = ROOT / 'keys'
EXPORT = ROOT / 'exported_keys'
BACKUPS = ROOT / '.vault-backups'
ALIAS_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]*$')
FILE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')
USER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_-]*$')
HOST_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.:-]*$')
ENTRY_NAME = 'SSH Vault data v1'


class VaultError(Exception):
    pass


def ensure_safe_dir(directory: Path, create=False) -> None:
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise VaultError(f'Unsafe directory: {directory}')
    if create:
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)


def safe_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def save_file(path: Path, content: bytes, mode=0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def data_default() -> dict:
    return {'version': 1, 'servers': {}, 'known_hosts': '', 'last_user': 'root'}


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode('ascii')


def unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_server(record: dict) -> None:
    if not isinstance(record, dict):
        raise VaultError('Invalid server record')
    if (not HOST_RE.fullmatch(record.get('host', '')) or
        not USER_RE.fullmatch(record.get('user', '')) or
        not str(record.get('port', '')).isdigit() or
        not 1 <= int(record['port']) <= 65535 or
        not FILE_RE.fullmatch(record.get('key_name', ''))):
        raise VaultError('Invalid host/user/port/key in vault')
    for field in ('private', 'public'):
        if not isinstance(record.get(field), str):
            raise VaultError('Missing SSH key material')
        unb64(record[field])


def verify_pair(private: bytes, public: bytes) -> bool:
    """Compare actual SSH public-key blobs; refuse encrypted private keys."""
    try:
        with tempfile.TemporaryDirectory(prefix='ssh-vault-verify-') as temp:
            key = Path(temp) / 'key'
            save_file(key, private)
            result = subprocess.run(['ssh-keygen', '-y', '-P', '', '-f', str(key)],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=12, check=False)
            if result.returncode:
                return False
            a, b = result.stdout.split()[:2], public.split()[:2]
            return a == b and len(a) == 2 and a[0] in (b'ssh-ed25519', b'ssh-rsa',
                    b'ecdsa-sha2-nistp256', b'ecdsa-sha2-nistp384', b'ecdsa-sha2-nistp521')
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        return False


def parse_blocks(content: str) -> list[tuple[str | None, str]]:
    """Retain original blocks byte-for-byte, including unsupported directives."""
    blocks = []
    current = []
    alias = None
    for line in content.splitlines(keepends=True):
        match = re.match(r'^\s*(Host|Match)\s+(.+?)\s*(?:#.*)?$', line, re.I)
        if match:
            if current:
                blocks.append((alias, ''.join(current)))
            current = []
            names = match.group(2).split() if match.group(1).lower() == 'host' else []
            alias = names[0] if len(names) == 1 and ALIAS_RE.fullmatch(names[0]) else None
        current.append(line)
    if current:
        blocks.append((alias, ''.join(current)))
    return blocks


def fields(block: str) -> dict[str, str]:
    result = {}
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        match = re.match(r'^(\w+)\s*(?:=\s*|\s+)(.*)$', stripped)
        if match:
            key = match.group(1).lower()
            if key not in result:
                result[key] = match.group(2).split(' #')[0].strip().strip('"')
    return result


def identity_basename(value: str) -> str | None:
    name = Path(value).name
    return name if FILE_RE.fullmatch(name) else None


def record_from_block(alias: str, block: str, priv: Path, pub: Path):
    opts = fields(block)
    keyname = identity_basename(opts.get('identityfile', ''))
    try:
        record = {'host': opts['hostname'], 'user': opts.get('user', 'root'),
                  'port': str(opts.get('port', '22')), 'key_name': keyname,
                  'private': '', 'public': ''}
        if keyname is None:
            return None, 'identity file is not configured'
        validate_server({**record, 'private': '', 'public': ''})
        pvt, pbc = priv / keyname, pub / (keyname + '.pub')
        if not safe_file(pvt) or not safe_file(pbc):
            return None, 'missing private/public key pair'
        raw_private, raw_public = pvt.read_bytes(), pbc.read_bytes()
        if not verify_pair(raw_private, raw_public):
            return None, 'private/public key mismatch or locked key'
        record['private'], record['public'] = b64(raw_private), b64(raw_public)
        return record, None
    except (KeyError, ValueError, OSError, VaultError):
        return None, 'invalid configuration or unreadable key'


def host_alias_known_matches(record: dict, alias: str) -> set[str]:
    port = str(record['port'])
    items = {alias, record['host']}
    if port != '22':
        items.update({f'[{alias}]:{port}', f'[{record["host"]}]:{port}'})
    return items


class VaultStore:
    """Save KDBX atomically, reopen with master key, then authorize cleanup."""
    def __init__(self, password: str, path: Path = KDBX):
        self.password = password
        self.path = path
        self.data: dict = data_default()

    def _read(self, path: Path) -> dict:
        from pykeepass import PyKeePass
        kp = PyKeePass(str(path), password=self.password)
        if (kp.version < (4, 0) or kp.kdf_algorithm != 'argon2id'
                or kp.encryption_algorithm != 'aes256'):
            raise VaultError('Vault must be KDBX 4 with Argon2id and AES-256')
        entry = kp.find_entries(title=ENTRY_NAME, first=True)
        if entry is None:
            raise VaultError('Vault data entry missing')
        data = json.loads(entry.password)
        if (not isinstance(data, dict) or data.get('version') != 1
                or not isinstance(data.get('servers'), dict)
                or not isinstance(data.get('known_hosts'), str)):
            raise VaultError('Unrecognized vault schema')
        for alias, record in data['servers'].items():
            if not ALIAS_RE.fullmatch(alias):
                raise VaultError('Invalid alias stored in vault')
            validate_server(record)
        return data

    def open(self) -> None:
        if not safe_file(self.path):
            raise VaultError('Vault is missing or is a symbolic link')
        self.data = self._read(self.path)

    def create(self) -> None:
        from pykeepass import create_database
        from pykeepass.kdbx_parsing import kdf_uuids
        if self.path.exists() or self.path.is_symlink():
            raise VaultError('Vault already exists')
        ensure_safe_dir(self.path.parent)
        temp = self.path.with_name('.vault-creation-' + os.urandom(8).hex() + '.kdbx')
        try:
            kp = create_database(str(temp), password=self.password)
            if kp.version < (4, 0) or kp.encryption_algorithm != 'aes256':
                raise VaultError('pykeepass template must support KDBX4 AES-256')
            params = kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
            if kp.kdf_algorithm == 'aeskdf':
                # Convert pykeepass's bundled template to standard KDBX4 Argon2id.
                # VariantDictionary type tags are defined by the KDBX4 spec.
                from construct import Container
                params.clear()
                for key, tag, value in (
                    ('$UUID', 0x42, kdf_uuids['argon2id']),
                    ('S', 0x42, os.urandom(32)),
                    ('I', 0x05, 3),
                    ('M', 0x05, 64 * 1024 * 1024),
                    ('P', 0x04, 2),
                    ('V', 0x04, 0x13),
                ):
                    params[key] = Container(type=tag, key=key, value=value)
            elif kp.kdf_algorithm in ('argon2', 'argon2id'):
                params['$UUID'].value = kdf_uuids['argon2id']
                params['I'].value = max(3, params['I'].value)
                params['M'].value = max(64 * 1024 * 1024, params['M'].value)
                params['V'].value = 0x13
            if kp.kdf_algorithm != 'argon2id':
                raise VaultError('KDBX template cannot use Argon2id')
            kp.add_entry(kp.root_group, ENTRY_NAME, '', json.dumps(data_default()),
                         notes='Encrypted SSH Vault data. Do not edit this entry manually.')
            kp.save(str(temp))
            os.chmod(temp, 0o600)
            if self._read(temp) != data_default():
                raise VaultError('Cannot verify the initial vault')
            os.replace(temp, self.path)
            self.data = data_default()
        finally:
            temp.unlink(missing_ok=True)

    def save(self, updated: dict) -> None:
        """Reopen and compare ciphertext before touching durable vault path."""
        ensure_safe_dir(self.path.parent)
        for alias, record in updated['servers'].items():
            if not ALIAS_RE.fullmatch(alias):
                raise VaultError('Invalid alias')
            validate_server(record)
        from pykeepass import PyKeePass
        kp = PyKeePass(str(self.path), password=self.password)
        entry = kp.find_entries(title=ENTRY_NAME, first=True)
        if entry is None:
            raise VaultError('Vault data entry missing')
        entry.password = json.dumps(updated, separators=(',', ':'), sort_keys=True)
        temp = self.path.with_name('.vault-save-' + os.urandom(8).hex() + '.kdbx')
        try:
            kp.save(str(temp))
            os.chmod(temp, 0o600)
            with temp.open('rb') as fh:
                os.fsync(fh.fileno())
            if self._read(temp) != updated:
                raise VaultError('Vault round-trip verification failed; no changes saved')
            os.replace(temp, self.path)
            self.data = copy.deepcopy(updated)
        finally:
            temp.unlink(missing_ok=True)

    def backup_verified(self) -> Path:
        ensure_safe_dir(BACKUPS, create=True)
        # Store encrypted KDBX only, never legacy decrypted materials.
        path = BACKUPS / ('vault-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
                          + '-' + os.urandom(4).hex() + '.kdbx')
        save_file(path, self.path.read_bytes())
        if self._read(path) != self.data:
            path.unlink(missing_ok=True)
            raise VaultError('Backup verification failed, refusing cleanup')
        return path

    def change_password(self, new_password: str):
        from pykeepass import PyKeePass
        kp = PyKeePass(str(self.path), password=self.password)
        kp.password = new_password
        temp = self.path.with_name('.vault-rekey-' + os.urandom(8).hex() + '.kdbx')
        old = self.password
        try:
            kp.save(str(temp))
            os.chmod(temp, 0o600)
            self.password = new_password
            if self._read(temp) != self.data:
                raise VaultError('Master password change verification failed')
            self.password = old
            self.backup_verified()
            os.replace(temp, self.path)
            self.password = new_password
        except Exception:
            self.password = old
            raise
        finally:
            temp.unlink(missing_ok=True)


def cleanup_empty_inbox(root: Path = INBOX) -> None:
    """Prune an import inbox only when it has NO remaining user data.

    Finder's .DS_Store is metadata, not a credential, and may be discarded
    only from a directory which is otherwise empty. Unknown dotfiles, symlinks,
    AppleDouble resources and any orphan keys are deliberately preserved.
    """
    for directory in (root / 'priv', root / 'pub', root):
        if directory.is_symlink() or not directory.is_dir():
            continue
        contents = list(directory.iterdir())
        metadata = [item for item in contents if item.name == '.DS_Store' and
                    item.is_file() and not item.is_symlink()]
        others = [item for item in contents if item not in metadata]
        if others:
            continue
        for item in metadata:
            # Recheck conditions to reduce accidental deletion after changes.
            if item.is_file() and not item.is_symlink():
                item.unlink()
        try:
            directory.rmdir()
        except OSError:
            pass


def migrate(store: VaultStore, root: Path = INBOX) -> dict:
    """Import configured pairs. Verified & backed-up matches are cleaned.

    Unexpected blocks, orphan files, duplicates with different bytes and
    unknown known_hosts entries remain untouched. Never traverse symlinks.
    """
    report = {'imported': [], 'duplicates': [], 'preserved': [], 'removed_keys': [],
              'problems': [], 'backup': None}
    if not root.exists():
        return report
    ensure_safe_dir(root)
    priv, pub = root / 'priv', root / 'pub'
    for folder in (priv, pub):
        if folder.exists():
            ensure_safe_dir(folder)
    conf = root / 'config'
    if not conf.exists():
        # With no configuration, every existing key is orphaned and MUST stay.
        # Remove only empty legacy scaffolding that has nothing to preserve.
        old_hosts = root / 'known_hosts'
        if safe_file(old_hosts) and old_hosts.stat().st_size == 0:
            old_hosts.unlink()
        cleanup_empty_inbox(root)
        if root.exists():
            report['preserved'].append('keys/ exists without config; all orphan data preserved')
        return report
    if not safe_file(conf):
        raise VaultError('Unsafe keys/config: refusing import')
    config_bytes = conf.read_bytes()
    text = config_bytes.decode('utf-8')
    blocks = parse_blocks(text)
    updated = copy.deepcopy(store.data)
    accepted = {}
    all_refs = {}
    repeated = {a for a, block in blocks if a is not None and sum(1 for name, _ in blocks if name == a) > 1}
    for index, (alias, block) in enumerate(blocks):
        opts = fields(block)
        key = identity_basename(opts.get('identityfile', ''))
        if key:
            all_refs.setdefault(key, set()).add(alias if alias is not None else f'__unmanaged_{index}')
        if alias is None:
            continue
        supported = {'host', 'hostname', 'user', 'port', 'identityfile', 'identitiesonly'}
        unknown = set(opts) - supported
        if unknown:
            report['problems'].append(f'{alias}: unsupported SSH directives ({", ".join(sorted(unknown))}); preserved')
            continue
        if alias in repeated:
            if not any(msg.startswith(f'{alias}: repeated') for msg in report['problems']):
                report['problems'].append(f'{alias}: repeated Host alias')
            continue
        entry, error = record_from_block(alias, block, priv, pub)
        if error:
            report['problems'].append(f'{alias}: {error}')
            continue
        if alias in updated['servers']:
            if updated['servers'][alias] != entry:
                report['problems'].append(f'{alias}: vault already contains different data')
                continue
            report['duplicates'].append(alias)
        else:
            updated['servers'][alias] = entry
            report['imported'].append(alias)
        accepted[alias] = entry
    # Collect only host keys we can confidently match. Hashed/wildcard and
    # unrecognized lines stay in the legacy inbox.
    known = root / 'known_hosts'
    old_known = None
    consumed = set()
    if known.exists():
        if not safe_file(known):
            report['problems'].append('known_hosts: unsafe file, preserved')
        else:
            old_known = known.read_bytes()
            candidates = set()
            for alias, record in accepted.items():
                candidates |= host_alias_known_matches(record, alias)
            old_lines = old_known.splitlines(keepends=True)
            vault_lines = updated['known_hosts'].splitlines()
            for i, line in enumerate(old_lines):
                try:
                    plain = line.decode('utf-8').rstrip('\r\n')
                except UnicodeDecodeError:
                    continue  # preserve unknown binary/non-UTF8 records exactly
                parts = plain.split()
                if parts and not parts[0].startswith(('#', '|', '@')):
                    hosts = parts[0].split(',')
                    if hosts and all(h in candidates for h in hosts):
                        consumed.add(i)
                        if plain not in vault_lines:
                            vault_lines.append(plain)
            updated['known_hosts'] = ('\n'.join(vault_lines) + '\n') if vault_lines else ''
    if not accepted and not consumed:
        report['preserved'].append('No importable connections; source left unchanged')
        return report
    # 1. Persist, 2. reopen, 3. backup ciphertext, 4. compare source unchanged,
    # only THEN remove precisely verified originals.
    if updated != store.data:
        store.save(updated)
    else:
        store.open()  # independently verify duplicate source is still in vault
    report['backup'] = str(store.backup_verified())
    if conf.read_bytes() != config_bytes:
        raise VaultError('Source config changed during import; no cleanup performed')
    # Keep any key shared by a Host entry that was NOT successfully imported.
    refs_in_use = {k for k, aliases in all_refs.items() if aliases - accepted.keys()}
    # Only remove imported blocks; keep unknown/failed blocks byte-for-byte.
    remaining = ''.join(block for alias, block in blocks if alias not in accepted)
    if remaining.strip():
        tmp = conf.with_name('.config-migration-' + os.urandom(4).hex())
        try:
            save_file(tmp, remaining.encode('utf-8'))
            if conf.read_bytes() == config_bytes:
                os.replace(tmp, conf)
        finally:
            tmp.unlink(missing_ok=True)
    elif conf.read_bytes() == config_bytes:
        conf.unlink()
    for name in {r['key_name'] for r in accepted.values()}:
        if name in refs_in_use:
            report['preserved'].append(f'{name}: referenced by an unresolved connection')
            continue
        aliases = [a for a, r in accepted.items() if r['key_name'] == name]
        record = accepted[aliases[0]]
        pair = ((priv / name, unb64(record['private'])),
                (pub / (name + '.pub'), unb64(record['public'])))
        if all(safe_file(path) and path.read_bytes() == raw for path, raw in pair):
            for path, _ in pair:
                path.unlink()
            report['removed_keys'].append(name)
        else:
            report['preserved'].append(f'{name}: file changed since validation')
    if known.exists() and old_known == b'' and safe_file(known):
        known.unlink()
    if known.exists() and old_known is not None and consumed and known.read_bytes() == old_known:
        remaining_known = b''.join(line for i, line in enumerate(old_lines) if i not in consumed)
        if remaining_known.strip():
            tmp = known.with_name('.hosts-migration-' + os.urandom(4).hex())
            try:
                save_file(tmp, remaining_known)
                os.replace(tmp, known)
            finally:
                tmp.unlink(missing_ok=True)
        else:
            known.unlink()
    for folder in (priv, pub):
        if folder.exists() and folder.is_dir():
            for file in folder.iterdir():
                report['preserved'].append(str(file.relative_to(root)))
    if conf.exists():
        report['preserved'].append('config (unmigrated directives)')
    if known.exists():
        report['preserved'].append('known_hosts (unmatched host keys)')
    cleanup_empty_inbox(root)
    return report


def export_vault(store: VaultStore, root: Path = ROOT) -> Path:
    """Export to NEW directory; NEVER modify legacy keys/ or prior exports."""
    ensure_safe_dir(root)
    target = root / 'exported_keys'
    if target.exists() or target.is_symlink():
        suffix = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        target = root / ('exported_keys-' + suffix + '-' + os.urandom(3).hex())
    staged = Path(tempfile.mkdtemp(prefix='.ssh-vault-export-', dir=root))
    try:
        (staged / 'priv').mkdir(mode=0o700)
        (staged / 'pub').mkdir(mode=0o700)
        entries = []
        filenames = {}
        for alias, rec in sorted(store.data['servers'].items()):
            validate_server(rec)
            name = rec['key_name']
            pair = (unb64(rec['private']), unb64(rec['public']))
            if name in filenames and filenames[name] != pair:
                raise VaultError('Two servers use the same key filename with different material')
            filenames[name] = pair
            if not verify_pair(*pair):
                raise VaultError(f'Invalid key pair in vault: {alias}')
            entries.append(f'Host {alias}\n    HostName {rec["host"]}\n'
                           f'    User {rec["user"]}\n    Port {rec["port"]}\n'
                           f'    IdentityFile priv/{name}\n    IdentitiesOnly yes\n')
        for name, (private, public) in filenames.items():
            save_file(staged / 'priv' / name, private)
            save_file(staged / 'pub' / (name + '.pub'), public, 0o644)
        save_file(staged / 'config', ('\n'.join(entries) + '\n').encode())
        save_file(staged / 'known_hosts', store.data['known_hosts'].encode())
        staged.replace(target)
        return target
    finally:
        if staged.exists():
            shutil.rmtree(staged)


def ask_master_password(path: Path = KDBX) -> str:
    if path.exists() or path.is_symlink():
        return getpass.getpass('SSH Vault master password: ')
    while True:
        first = getpass.getpass('Create master password: ')
        again = getpass.getpass('Confirm master password: ')
        if first != again:
            print('Passwords did not match. Try again.')
        elif len(first) < 12:
            print('Use a master password with at least 12 characters.')
        else:
            return first
