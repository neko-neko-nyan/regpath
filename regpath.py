import enum
import typing
import weakref
import winreg


# REG_WHOLE_HIVE_VOLATILE = 1 for RegRestoreKeyA
# REG_REFRESH_HIVE = 2 REG_RESTORE_KEY_INFORMATION
# REG_NO_LAZY_FLUSH = 4 for BaseRegRestoreKey

class NotifyChange(enum.IntFlag):
    NAME = winreg.REG_NOTIFY_CHANGE_NAME
    ATTRIBUTES = winreg.REG_NOTIFY_CHANGE_ATTRIBUTES
    LAST_SET = winreg.REG_NOTIFY_CHANGE_LAST_SET
    SECURITY = winreg.REG_NOTIFY_CHANGE_SECURITY


class Option(enum.IntFlag):
    NON_VOLATILE = winreg.REG_OPTION_NON_VOLATILE
    VOLATILE = winreg.REG_OPTION_VOLATILE
    CREATE_LINK = winreg.REG_OPTION_CREATE_LINK
    BACKUP_RESTORE = winreg.REG_OPTION_BACKUP_RESTORE
    OPEN_LINK = winreg.REG_OPTION_OPEN_LINK


class Access(enum.IntFlag):
    QUERY_VALUE = winreg.KEY_QUERY_VALUE
    SET_VALUE = winreg.KEY_SET_VALUE
    CREATE_SUB_KEY = winreg.KEY_CREATE_SUB_KEY
    ENUMERATE_SUB_KEYS = winreg.KEY_ENUMERATE_SUB_KEYS
    NOTIFY = winreg.KEY_NOTIFY
    CREATE_LINK = winreg.KEY_CREATE_LINK

    WOW64_64KEY = winreg.KEY_WOW64_64KEY
    WOW64_32KEY = winreg.KEY_WOW64_32KEY

    READ = winreg.KEY_READ
    WRITE = winreg.KEY_WRITE
    EXECUTE = winreg.KEY_EXECUTE

    ALL_ACCESS = winreg.KEY_ALL_ACCESS


class Type(enum.IntEnum):
    BINARY = winreg.REG_BINARY

    DWORD = winreg.REG_DWORD
    DWORD_LITTLE_ENDIAN = winreg.REG_DWORD_LITTLE_ENDIAN
    DWORD_BIG_ENDIAN = winreg.REG_DWORD_BIG_ENDIAN

    EXPAND_SZ = winreg.REG_EXPAND_SZ
    LINK = winreg.REG_LINK
    MULTI_SZ = winreg.REG_MULTI_SZ

    NONE = winreg.REG_NONE

    QWORD = winreg.REG_QWORD
    QWORD_LITTLE_ENDIAN = winreg.REG_QWORD_LITTLE_ENDIAN

    SZ = winreg.REG_SZ

    # unused?
    RESOURCE_LIST = winreg.REG_RESOURCE_LIST
    FULL_RESOURCE_DESCRIPTOR = winreg.REG_FULL_RESOURCE_DESCRIPTOR
    RESOURCE_REQUIREMENTS_LIST = winreg.REG_RESOURCE_REQUIREMENTS_LIST


def _normalize_type(typ, value):
    if typ is None:
        if isinstance(value, str):
            return Type.SZ
        if value is None:
            return Type.NONE
        if isinstance(value, int):
            if -0x8000_0000 < value < 0xffff_ffff:
                return Type.DWORD

            if -0x8000_0000_0000_0000 < value < 0xffff_ffff_ffff_ffff:
                return Type.QWORD

        elif hasattr(value, '__iter__') and all((isinstance(i, str) for i in value)):
            return Type.MULTI_SZ

    if isinstance(typ, int):
        return typ
    if isinstance(typ, str):
        return Type[typ]

    raise RuntimeError("Unknown type")


class RegPath:
    __slots__ = ('_parts', '_remote_host', 'key')
    _CACHE = weakref.WeakValueDictionary()

    def __new__(cls, parts: typing.Union[typing.Iterable[str], str], remote_host: typing.Optional[str] = None):
        if isinstance(parts, str):
            parts = parts.split('\\')

            if len(parts) >= 3 and not parts[0] and not parts[1]:
                if remote_host is not None:
                    raise ValueError("Remote host given using argument, but path already has remote host")

                del parts[0]
                del parts[0]
                remote_host = '\\\\' + parts.pop(0)

            elif parts and not parts[0]:
                del parts[0]

            if not parts:
                raise RuntimeError("Empty path or missing component")

        parts = (HK_ALIASES.get(parts[0], parts[0]), *parts[1:])

        if len(parts) == 1 and remote_host is None:
            obj = HIVES.get(parts[0])
            if obj is not None:
                return obj

        obj = cls._CACHE.get((remote_host, parts))
        if obj is not None:
            return obj

        obj = super().__new__(cls)
        obj._parts = parts
        obj._remote_host = remote_host
        obj.key = _HIVES[parts[0]] if len(parts) == 1 and remote_host is None else None
        return obj

    def _invoke_api(self, method, *args):
        self.open()
        return getattr(winreg, method)(self.key, *args)

    def delete_child(self, name: str):
        self._invoke_api('DeleteKey', name)

    def open(self):
        if self.is_opened:
            return

        if self.is_remote:
            hive_key = winreg.ConnectRegistry(self.remote_host, self.hive_key)
            if self.is_hive:
                self.key = hive_key
            else:
                self.key = getattr(winreg, 'OpenKeyEx')(hive_key, '\\'.join(self.parts[1:]), 0, Access.READ)

        else:
            self.key = self.hive._invoke_api('OpenKeyEx', '\\'.join(self.parts[1:]), 0, Access.READ)

    def close(self):
        if self.is_opened and (not self.is_hive or self.is_remote):
            try:
                self._invoke_api('CloseKey')
                self.key = None
            except OSError:
                pass

    # ==============================

    def __truediv__(self, other: str):
        return RegPath(list(self.parts) + list(other.split('\\')), self.remote_host)

    def __repr__(self):
        return "<RegPath '{}\\{}'>".format(('\\\\' + self.remote_host) if self.is_remote else '',
                                           '\\'.join(self._parts))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # ==============================
    # =    Информация об объекте   =
    # ==============================

    @property
    def is_remote(self):
        return self.remote_host is not None

    @property
    def is_hive(self):
        return len(self._parts) == 1

    @property
    def is_opened(self):
        return self.key is not None

    # ==============================

    @property
    def name(self):
        return self._parts[-1]

    @property
    def hive_name(self):
        return self._parts[0]

    @property
    def hive(self) -> 'RegPath':
        return HIVES[self._parts[0]]

    @property
    def hive_key(self):
        return _HIVES[self._parts[0]]

    @property
    def parts(self):
        return self._parts

    @property
    def remote_host(self):
        return self._remote_host

    @property
    def parent(self):
        return RegPath(self.parts[:-1], self.remote_host)

    # ==============================
    # =   Работа как с каталогом   =
    # ==============================

    def exists(self):
        if self.is_opened:
            return True

        try:
            self.open()
        except OSError as e:
            if e.winerror == 2:  # File not found
                return False
            raise

        return True

    def mkdir(self, *, parents=True, exist_ok=True):
        if not exist_ok and self.exists():
            raise ValueError("Already exists")

        if not parents and not self.parent.exists():
            raise ValueError("Parent not exists")

        self.key = self.hive._invoke_api('CreateKeyEx', '\\'.join(self.parts[1:]), 0, Access.READ)

    def clear(self):
        cc, vc, lm = self._invoke_api('QueryInfoKey')
        for i in range(cc):
            name = self / self._invoke_api('EnumKey', i)
            name.rmtree()

        for i in range(vc):
            name, data, typ = self._invoke_api('EnumKey', i)
            self.delete_value(name)

    def rmtree(self):
        self.clear()
        self.rmdir()

    def rmdir(self):
        self.close()
        self.parent.delete_child(self.name)

    # ==============================

    def iter_names(self):
        cc, vc, lm = self._invoke_api('QueryInfoKey')
        for i in range(cc):
            yield self._invoke_api('EnumKey', i)

    def iter_dir(self):
        for i in self.iter_names():
            yield self / i

    def list_names(self):
        return list(self.iter_names())

    def list_dir(self):
        return list(self.iter_dir())

    # ==============================
    # =   Вспомогательные методы   =
    # ==============================

    def flush(self):
        self._invoke_api('FlushKey')

    # ==============================

    def load_from(self, name: str, file: str):
        self._invoke_api('LoadKey', name, file)

    def save_to(self, file: str):
        self._invoke_api('SaveKey', file)

    # ==============================

    @property
    def reflection(self):
        return bool(self._invoke_api('QueryReflectionKey'))

    @reflection.setter
    def reflection(self, value):
        if value:
            self._invoke_api('EnableReflectionKey')
        else:
            self._invoke_api('DisableReflectionKey')

    # ==============================
    # =    Работа со значениями    =
    # ==============================

    def __getitem__(self, item):
        return self.get_value(item)

    def __setitem__(self, key, value):
        self.set_value(key, value)

    def __delitem__(self, key):
        self.delete_value(key)

    # ==============================

    @property
    def default(self):
        return self.get_value(None)

    @default.setter
    def default(self, value):
        self.set_value(None, value)

    # ==============================

    def keys(self):
        return (k for k, v in self.items())

    def values(self):
        return (v for k, v in self.items())

    def to_dict(self):
        return dict(self.items())

    # ==============================

    def set_value(self, name: typing.Optional[str], value, typ=None):
        self._invoke_api('SetValueEx', name, 0, _normalize_type(typ, value), value)

    def get_value(self, name: typing.Optional[str]):
        return self._invoke_api('QueryValueEx', name)[0]

    def delete_value(self, name: str):
        self._invoke_api('DeleteValue', name)

    def items(self):
        cc, vc, lm = self._invoke_api('QueryInfoKey')
        for i in range(vc):
            name, data, typ = self._invoke_api('EnumValue', i)
            yield name, data


_HIVES = {
    'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
    'HKEY_CURRENT_CONFIG': winreg.HKEY_CURRENT_CONFIG,
    'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
    'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
    'HKEY_USERS': winreg.HKEY_USERS,
    'HKEY_DYN_DATA': winreg.HKEY_DYN_DATA,
    'HKEY_PERFORMANCE_DATA': winreg.HKEY_PERFORMANCE_DATA,

}

HK_ALIASES = {
    'HKCR': 'HKEY_CLASSES_ROOT',
    'HKCC': 'HKEY_CURRENT_CONFIG',
    'HKCU': 'HKEY_CURRENT_USER',
    'HKLM': 'HKEY_LOCAL_MACHINE',
    'HKU': 'HKEY_USERS',
    'HKDD': 'HKEY_DYN_DATA',
    'HKPD': 'HKEY_PERFORMANCE_DATA',
}

HIVES = {}
HKEY_CLASSES_ROOT = HKCR = HIVES['HKEY_CLASSES_ROOT'] = HIVES['HKCR'] = RegPath('HKEY_CLASSES_ROOT')
HKEY_CURRENT_CONFIG = HKCC = HIVES['HKEY_CURRENT_CONFIG'] = HIVES['HKCC'] = RegPath('HKEY_CURRENT_CONFIG')
HKEY_CURRENT_USER = HKCU = HIVES['HKEY_CURRENT_USER'] = HIVES['HKCU'] = RegPath('HKEY_CURRENT_USER')
HKEY_LOCAL_MACHINE = HKLM = HIVES['HKEY_LOCAL_MACHINE'] = HIVES['HKLM'] = RegPath('HKEY_LOCAL_MACHINE')
HKEY_USERS = HKU = HIVES['HKEY_USERS'] = HIVES['HKU'] = RegPath('HKEY_USERS')
HKEY_DYN_DATA = HKDD = HIVES['HKEY_DYN_DATA'] = HIVES['HKDD'] = RegPath('HKEY_DYN_DATA')
HKEY_PERFORMANCE_DATA = HKPD = HIVES['HKEY_PERFORMANCE_DATA'] = HIVES['HKPD'] = RegPath('HKEY_PERFORMANCE_DATA')
