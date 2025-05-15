"""MIT License

Copyright (c) 2022 The Singularity

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""

import os, psutil, platform, shutil
import bson, orjson
import rich, rich.console, rich.theme
import asyncio, io
import re
import threading
from importlib.metadata import version
from datetime import datetime as dt
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from typing import Callable, List, Any, Union, Tuple, Optional, TypeVar, Literal


# typing vars
JO = TypeVar('JO', bound='JSONObject')
O = TypeVar('O', bound='YAMLObject')
P = TypeVar('P', bound='Protocol')

# vars
__version__ = "0.0.2b1.dev1"

# classes
# - YAML object
class YAMLObject(object):
    """:class:`YAMLObject` - YAML Object class
    
    :param data: YAML Data
    :param default: Default items,
        defaults to `{}`
    :type data: :class:`ruamel.yaml.comments.CommentedMap`
    :type default: dict,
        optional"""
    def __init__(self, data: CommentedMap, default: dict={}):
        self.data = {**default, **data}

    def __getattr__(self, name: str) -> Union[Any, O, List[Union[Any, O]]]:
        value = self.data[name]
        if isinstance(value, (CommentedMap, dict)): value = YAMLObject(value)
        elif isinstance(value, list): value = [YAMLObject(x) if isinstance(x, (CommentedMap, dict)) else x for x in value]
        return value

    def __getitems__(self, key: str) -> Union[Any, O, List[Union[Any, O]]]:
        value = self.data[key]
        if isinstance(value, (CommentedMap, dict)): value = YAMLObject(value)
        elif isinstance(value, list): value = [YAMLObject(x) if isinstance(x, (CommentedMap, dict)) else x for x in value]
        return value

# - group
class Group:
    """:class:`Group` - Operations group
    
    :param byte: Group byte
    :param name: Group name
    :type byte: bytes
    :type name: str"""
    def __init__(self, byte: bytes, name: str):
        self.byte = byte
        self.name = name
        self.__operations = []

    # add op
    def add_op(self, func: Callable, byte: bytes, required_vars: List[str]=[], required_perms: List[str]=[], check_db_access: Union[str, None]=None):
        """:func:`Group.add_op` - Add operation to this group
        
        :param func: Operation functions
        :param byte: Operation byte
        :param required_vars: Required request vars to run this operation,
            defaults to `[]`
        :param required_perms: Required user permissions to run this operation,
            defaults to `[]`
        :param check_db_access: Check user access ti this db, value - query variable pointing to the database,
            defaults to `None`
        :type func: :class:`typing.Callable`
        :type byte: bytes
        :type required_vars: :class:`typing.List[str]`,
            optional
        :type required_perms: :class:`typing.List[str]`,
            optional
        :type check_db_access: :class:`typing.Union[str, None]`,
            optional"""
        required_perms.append('admin')
        self.__operations.append((byte, func, required_vars, required_perms, check_db_access))

    # run operation
    async def run_op(self, op: int, content: Union[int, str, bool, dict], protocol: P, writer: asyncio.StreamWriter, headers: dict) -> Tuple[int, int, Optional[Any], Optional[Any]]:
        """:func:`Group.run_op` - Run a operation
        
        :param op: Operation id
        :param content: Request content
        :param protocol: SyrDB Protocol
        :param writer: Stream writer (connection)
        :param headers: Request headers
        :type op: int
        :type content: :class:`typing.Union[int, str, bool, dict]`
        :type protocol: :class:`Protocol`
        :type writer: :class:`asyncio.StreamWriter`
        :type headers: dict
        
        :return: Group number, code number [and description]
        :rtype: :class:`typing.Tuple[int, int, typing.Optional[typing.Any], typing.Optional[typing.Any]]`"""
        op = [x for x in self.__operations if x[0][0] == op]
        if not len(op): return 2, 6

        # Checks
        for var in op[0][2]:
            if not var in content: return 2, 4
        if op[0][0][0] != 0 and not protocol.connections[writer.get_extra_info('peername')]['permissions'] in op[0][3]: return 2, 5
        if op[0][4] is not None and content[op[0][4]] != protocol.connections[writer.get_extra_info('peername')]['db'] and protocol.connections[writer.get_extra_info('peername')]['db'] != "$all": return 2, 5

        # Run op
        return await op[0][1](protocol=protocol, writer=writer, headers=headers, **content)

# - headers
class Headers:
    """:class:`Headers` - SyrDB Headers class
    
    :param protocol: Protcol object
    :type protocol: :class:`Protocol`"""
    def __init__(self, protocol: P):
        self.protocol = protocol
        self.headers_types = {1: 'provider', 2: 'version', 3: 'description'}
        self.flags_names = {1: ('maxResponseSize', 0)}
        self.status_codes = {1: {1: "Operation completed", 2: "Authorization completed"}, 2: {1: "Authorization required", 2: "No <name> specified", 3: "<name> is not correct", 4: "Not enough parameters", 5: "You don't have enough rights", 6: "Unknown operation", 7: "Connection limit reached"}, 3: {1: "The server was unable to process this request", 2: "This SyrDB Protocol version not supported", 3: "Unknown error"}}

    # format
    def format(self, status: Tuple[int, int], headers: dict, content: Union[int, str, bool, dict, None]=None, flags: Union[dict, None]=None) -> bytes:
        """:func:`Headers.format` - Make a response headers
        
        :param status: Response status code
        :param headers: Response headers
        :param content: Response content,
            defaults to `None`
        :param flags: Response flags,
            defaults to `None`
        :type status: :class:`typing.Tuple[int, int]`
        :type headers: dict
        :type content: :class:`typing.Union[int, str, bool, dict, None]`,
            optional
        :type flags: :class:`typing.Union[dict, None]`,
            optional
            
        :return: Response bytes
        :rtype: bytes"""
        types = {int: b'\x00', str: b'\x01', bool: b'\x02', dict: b'\x03'}

        headers = b''.join(bytes([k2 for k2, v2 in self.headers_types.items() if v2 == k])+types[type(v)]+self.parse_as_type(len(self.parse_as_type(v, mode="encode")), mode="encode", size=30)+self.parse_as_type(v, mode="encode") for k, v in headers.items())
        content = b'' if content is None else types[type(content)]+self.parse_as_type(content, mode="encode")
        flags = b'' if flags is None else b''.join((bytes([k2 for k2, v2 in self.flags_names.items() if v2[0] == k])+self.parse_as_type(v, mode="encode", size=47)) for k, v in flags.items())

        return self.parse_as_type(len(headers), mode="encode")+self.parse_as_type(len(content), mode="encode")+self.parse_as_type(len(flags), mode="encode")+bytes(status)+headers+content+flags

    # parse as type
    def parse_as_type(self, value: Union[int, str, bool, dict, bytes], type: Union[bytes, None]=None, mode: str="decode", size: Union[int, None]=None) -> Union[int, str, bool, dict, bytes]:
        """:func:`Headers.parse_as_type` - Parse value as type
        
        :param value: Value
        :param type: Type,
            defaults to `None`
        :param mode: Parse mode,
            available `decode` or `encode`,
            defaults to `decode`
        :param size: Values size,
            defaults to `None`
        :type value: :class:`typing.Union[int, str, bool, dict, bytes]`
        :type type: :class:`typing.Union[bytes, None]`,
            optional
        :type mode: str,
            optional
        :type size: :class:`typing.Union[int, None]`,
            optional
        
        :return: Parsed value
        :rtype: :class:`typing.Union[int, str, bool, dict]`"""
        if mode == "decode":
            if type[0] == 0: return int.from_bytes(value, 'big')
            elif type[0] == 1: return value.decode('utf-8')
            elif type[0] == 2: return sum(list(value)) == 1
            elif type[0] == 3: return bson.loads(value)
        elif mode == "encode":
            if isinstance(value, int): return value.to_bytes(size or 32, 'big')
            elif isinstance(value, str): return value.encode('utf-8')+(bytes(size-len(value.encode('utf-8'))) if size is not None else b'')
            elif isinstance(value, bool): return (b'\x01' if value else b'\x00')+(bytes(size-1) if size is not None else b'')
            elif isinstance(value, dict): return bson.dumps(value)

    # parse headers
    def parse_headers(self, headers: bytes) -> dict:
        """:func:`Headers.parse_headers` - Parse headers
        
        :param headers: Headers array
        :type headers: bytes
        
        :return: Headers dict
        :rtype: dict"""
        data = io.BytesIO(headers)
        headers = {}
        while True:
            name = data.read(1)
            if not name: break
            type = data.read(1)
            length = int.from_bytes(data.read(30), 'big')
            headers[self.headers_types[name[0]]] = self.parse_as_type(data.read(length), type)
        return headers

    # parse content
    def parse_content(self, content: bytes) -> Union[int, str, bool, dict]:
        """:func:`Headers.parse_content` - Parse content
        
        :param content: Content array
        :type content: bytes
        
        :return: Parsed content
        :rtype: :class:`typing.Union[int, str, bool, dict]`"""
        type = bytes([content[0]])
        content = self.parse_as_type(content[1:], type)
        return content

    # parse flags
    def parse_flags(self, flags: bytes) -> dict:
        """:func:`Headers.parse_flags` - Parse request flags
        
        :param flags: Flags array
        :type flags: bytes
        
        :return: Flags dict
        :rtype: dict"""
        data = io.BytesIO(flags)
        flags = {}
        while True:
            name = data.read(1)
            if not name: break
            fname = self.flags_names[name[0]]
            flags[fname[0]] = self.parse_as_type(data.read(47), fname[1])
        return flags

# - protocol
class Protocol:
    """:class:`Protocol` - SyrDB Protocol
    
    :param config: SyrDB Config
    :type config: :class:`YAMLObject`"""
    __version__ = "0.2b1.dev1"

    def __init__(self, config: YAMLObject):
        self.config: YAMLObject = config
        self.headers: Headers = Headers(self)
        self.connections = {}
        self.__groups: List[Group] = []

    # add group
    def add_group(self, byte: bytes, name: str) -> Group:
        """:func:`Protocol.add_group` - Add operations group
        
        :param byte: Group byte
        :param name: Group name
        :type byte: bytes
        :type name: str
        
        :return: Group object
        :rtype: :class:`Group`"""
        group = Group(byte, name)
        self.__groups.append(group)
        return group

    # log
    def log(self, level: int, content: str):
        """:func:`Protocol.log` - Log any content
        
        :param level: Log level,
            available `0`, `1`, `2` or `3`
        :param content: Log content
        :type level: int
        :type content: str"""
        log_levels = {'info': 0, 'warn': 1, 'error': 2, 'debug': 3}
        time = dt.today()
        if self.config.logger.console.enable:
            if level <= log_levels[self.config.logger.console.level.lower()]:
                formats = {0: '[cyan]Info  ›[/cyan]', 1: '[yellow]Warn  ›[/yellow]', 2: '[red]Error ›[/red]', 3: '[blue]Debug ›[/blue]'}
                rich.print(f'[green][{time}][/green] {formats[level]} [grey78]{content}[/grey78]')
        if self.config.logger.file.enable:
            if level <= log_levels[self.config.logger.file.level.lower()]:
                levels = {0: 'Info  ›', 1: 'Warn  ›', 2: 'Error ›', 3: 'Debug ›'}
                def time_format(string: str):
                    new_string = string
                    formats = {'YYYY': time.year, 'MM': time.month, 'DD': time.day, 'ss': time.second, 'mm': time.minute, 'hh': time.hour}
                    for k, v in formats.items():
                        new_string = new_string.replace(k, str(v))
                    return new_string

                file = os.path.join(self.config.logger.file.folder, time_format(self.config.logger.file.filename))
                if not os.path.exists(file):
                    if not os.path.exists(self.config.logger.file.folder):
                        os.mkdir(self.config.logger.file.folder)
                    with open(file, 'w', encoding='UTF-8') as f:
                        f.write(f'# SyrDB Version: {self.__version__}\n# Date: {time.strftime("%d.%m.%Y")}')
                with open(file, 'a', encoding='UTF-8') as f:
                    if self.config.logger.file.loggingFormat == "sdb-journal":
                        f.write(f'\n[{time.strftime("%S:%M:%H.%f")}] {levels[level]} {content}')

    # run
    async def run(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Union[Tuple[int, int, Optional[Any], Optional[Any]], Literal[False]]:
        """:func:`Protocol.run` - Execute request
        
        :param reader: Stream reader
        :param writer: Stream writer (connection)
        :type reader: :class:`asyncio.StreamReader`
        :type writer: :class:`asyncio.StreamWriter`
        
        :return: Group number, code number [and description] or False
        :rtype: :class:`typing.Union[typing.Tuple[int, int, typing.Optional[typing.Any], typing.Optional[typing.Any]], False]`"""
        # Started parse and check disconnected
        hlength = await reader.read(32)
        clength = await reader.read(32)
        flength = await reader.read(32)
        op = await reader.read(2)

        if not hlength:
            if writer.get_extra_info('peername') in self.connections: del self.connections[writer.get_extra_info('peername')]
            connection = writer.get_extra_info('peername')
            self.log(3, f'Connection from {connection[0]}:{connection[1]} closed')
            return False

        # Final parse
        hlength = int.from_bytes(hlength, 'big')
        clength = int.from_bytes(clength, 'big')
        flength = int.from_bytes(flength, 'big')
        headers = self.headers.parse_headers(await reader.read(hlength))
        content = self.headers.parse_content(await reader.read(clength)) if clength > 0 else {}
        flags = self.headers.parse_flags(await reader.read(flength))

        if headers.get('version', self.__version__) not in [self.__version__, f'SyrDB/{self.__version__}']: return 3, 2 # Check request protocol version

        op_group = [x for x in self.__groups if x.byte[0] == op[0]]
        if not len(op_group): return 2, 6 # Check operations group exists

        self.log(3, f'Request received with opcode {op_group[0].name}:{op[1]}')

        if op_group[0].byte[0] != 0 and writer.get_extra_info('peername') not in self.connections: return 2, 1 # Check authorization
        elif len(self.connections)+1 > self.config.security.maxConnections and self.config.security.maxConnections != -1: return 2, 7 # Check max connections
        else: return await op_group[0].run_op(op[1], content, self, writer, headers) # Run operation

    # handle connection
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """:func:`Protocol.handle_connection` - Handle new connection
        
        :param reader: Stream reader
        :param writer: Stream writer (connection)
        :type reader: :class:`asyncio.StreamReader`
        :type writer: :class:`asyncio.StreamWriter`"""
        while True:
            response = await self.run(reader, writer)
            if not response: break
            writer.write(self.headers.format((response[0], response[1]), {
                "version": f"SyrDB/{self.__version__}",
                "description": response[2] if len(response) > 2 and isinstance(response[2], str) else self.headers.status_codes[response[0]][response[1]]
            }, response[3] if len(response) > 3 else response[2] if len(response) > 2 and isinstance(response[2], (dict, int, bool)) else None))

# - JSON Object
class JSONObject:
    def __init__(self, code: dict):
        self.code = code

    def get(self, key: str=None, _or: Any=None, type: str="one"):
        v: dict = self.code
        if type == "list": rv: List[JSONObject] = None
        if key is not None:
            for k in key.split("."):
                if isinstance(v, dict) and k in v:
                    if type == "one": v = v.get(k, _or)
                    elif type == "list": v = v.get(k)
            if type == "list": rv = [JSONObject(x) for x in v]
        elif type == "list": rv = [(x[0], JSONObject(x[1])) for x in v.items()]
        return v if type == "one" else rv

    def set(self, key: str, value: Any=None):
        keys = key.split('.')
        item = self.code
        for key in keys[:-1]:
            item = item[key]
        if value is not None: item[keys[-1]] = value
        else: del item[keys[-1]]

    def update(self, update: dict):
        for type in JSONObject(update).get(type='list'):
            for k, v in type[1].code.items():
                type = re.findall(r'\$([a-z]+)', type[0])
                if len(type):
                    type = type[0]
                    if type == 'set': self.set(k, v)
                    elif type == 'sum': self.set(k, self.get(k)+v)
                    elif type == 'sub': self.set(k, self.get(k)-v)
                    elif type == "add": d = self.get(k); d.append(v); self.set(k, d)
                    elif type == "rem": d = self.get(k); d.pop(d.index(v)); self.set(k, d)
                    elif type == "del": self.set(k)

# functions
# +- get database info
def get_database_info(protocol: P, name: str) -> dict:
    """:func:`database_list.get_database_info` - Get info of database with name
    
    :param protocol: SyrDB Protocol object
    :param name: Database name
    :type protocol: :class:`Protocol`
    :type name: str
    
    :return: Database info dictonary
    :rtype: dict"""
    return {'created': bson.loads(open(os.path.join(protocol.config.database.dataFolder, os.path.join(name, 'meta.bson')), 'rb').read())['created']}

# +- filtre
def filtre(filter: dict, data: List[dict], mode: str="one"):
    items: List[JSONObject] = [i.get() for i in [JSONObject(x) for x in data] if i is not None and False not in [i.get(k) == v for k, v in filter.items()]]
    if mode == "one": return items[0] if len(items) else None
    elif mode == "many": return items if len(items) else None

# Operations
# - Auth Group
# +- auth
async def auth(protocol: P, writer: asyncio.StreamWriter, headers: dict, access_token: str=None, user: dict=None, **kwargs) -> Tuple[int, int, Optional[str]]:
    """:func:`auth` - Auth op
    
    :param protocol: Protocol object
    :param writer: Stream writer
    :param headers: Request headers
    :param access_token: Access Token,
        defaults to `None`
    :param user: User object,
        defaults to `None`
    :type protocol: :class:`Protocol`
    :type writer: :class:`asyncio.StreamWriter`
    :type headers: dict
    :type access_token: str,
        optional
    :type user: dict,
        optional
    
    :return: Group number, code number and description
    :rtype: :class:`typing.Tuple[int, int, typing.Optional[str]]`"""
    if protocol.config.security.auth.enable:
        if access_token is None: return 2, 2, "No access_token specified"
        elif access_token != protocol.config.security.auth.accessToken: return 2, 3, "access_token is not correct"
        elif user is None: return 2, 2, "No user specified"
        else:
            au = None
            for u in protocol.config.security.auth.users:
                if u.username != user['name']: continue
                elif u.password != user['password']: continue
                elif u.db != user['db']: continue
                elif len([x for x in protocol.connections.values() if x['name'] == u.username])+1 > u.maxAuthentications and u.maxAuthentications != -1: continue
                else: au = u
            if au is None: return 2, 3, "user is not correct"
            else:
                protocol.connections[writer.get_extra_info('peername')] = {'name': au.username, 'permissions': au.permissions, 'db': au.db}
                protocol.log(3, f'New login to user {au.username} | Provider: {headers["provider"]["name"]} {headers["provider"]["version"]} for {headers["provider"]["lang"]["name"]} {headers["provider"]["lang"]["version"]}')
    else:
        protocol.connections[writer.get_extra_info('peername')] = {'permissions': 'admin', 'db': '$all'}
        protocol.log(3, f'New login to SyrDB | Provider: {headers["provider"]["name"]} {headers["provider"]["version"]} for {headers["provider"]["lang"]["name"]} {headers["provider"]["lang"]["version"]}')
    return 1, 2

# - Memory Storage
class MemoryStorage:
    """:class:`MemoryStorage` - Memory storage object
    
    :param protocol: Protocol object
    :type protocol: :class:`Protocol`"""
    def __init__(self, protocol: Protocol):
        self.protocol = protocol
        self.__storage = {}

    # add
    def add(self, frame: str, object: Any={}):
        """:func:`MemoryStorage.add` - Add object to memory storage
        
        :param frame: Path to frame
        :param object: Object to add to memory storage,
            defaults to `{}`
        :type frame: str
        :type object: :class:`typing.Any`,
            optional"""
        if self.protocol.config.database.memoryStorage.enable:
            db_and_coll = frame.split(':')
            db = db_and_coll[0]
            coll = db_and_coll[1] if len(db_and_coll) > 1 else None
            if db not in self.__storage:
                if len(self.__storage)+1 > self.protocol.config.database.memoryStorage.maxDatabases:
                    min_requests_key = None
                    min_requests_value = -1
                    for k, v in self.__storage.items():
                        if min_requests_value > v['m']['r'] and min_requests_value != -1:
                            min_requests_value = v['m']['r']
                            min_requests_key = k
                    del self.__storage[min_requests_key]
                self.__storage[db] = {'m': {'c': object['created'], 'r': 0}, 'c': {}}
            elif coll not in self.__storage[db]['c'] and coll is not None:
                if len(self.__storage[db]['c'])+1 > self.protocol.config.database.memoryStorage.maxCollection:
                    min_requests_key = None
                    min_requests_value = -1
                    for k, v in self.__storage[db]['c'].items():
                        if min_requests_value > v['r'] and min_requests_value != -1:
                            min_requests_value = v['r']
                            min_requests_key = k
                    del self.__storage[db]['c'][min_requests_key]
                self.__storage[db]['m']['r'] += 1
                self.__storage[db]['c'][coll] = {'r': 0, 'd': []}
            else:
                if len(self.__storage[db]['c'][coll]['d'])+1 > self.protocol.config.database.memoryStorage.maxItems:
                    min_requests_index = None
                    min_requests_value = -1
                    for item in self.__storage[db]['c'][coll]['d']:
                        if min_requests_value > item['r'] and min_requests_value != -1:
                            min_requests_value = item['r']
                            min_requests_index = self.__storage[db]['c'][coll]['d'].index(item)
                    self.__storage[db]['c'][coll]['d'].pop(min_requests_index)
                self.__storage[db]['m']['r'] += 1
                self.__storage[db]['c'][coll]['r'] += 1
                self.__storage[db]['c'][coll]['d'].append((object, 0))

    # remove
    def remove(self, frame: str):
        """:func:`MemoryStorage.remove` - Remove object from memory storage
        
        :param frame: Path to frame
        :type frame: str"""
        if self.protocol.config.database.memoryStorage.enable:
            frame = frame.split(':')
            db = frame[0]
            coll = frame[1] if len(frame) > 1 else None
            index = frame[2] if len(frame) > 2 else None

            if index is not None:
                self.__storage[db]['m']['r'] += 1
                self.__storage[db]['c'][coll]['r'] += 1
                self.__storage[db]['c'][coll]['d'].pop(int(index))
            elif coll is not None:
                self.__storage[db]['m']['r'] += 1
                del self.__storage[db]['c'][coll]
            else:
                del self.__storage[db]

    # update
    def update(self, frame: str, update: dict):
        """:func:`MemoryStorage.update` - Update object in memory storage
        
        :param frame: Path to frame
        :param update: Update data
        :type frame: str
        :type update: dict"""
        if self.protocol.config.database.memoryStorage.enable:
            frame = frame.split(':')
            db = frame[0]
            coll = frame[1] if len(frame) > 1 else None
            index = frame[2] if len(frame) > 2 else None

            if coll is not None and index is not None:
                self.__storage[db]['m']['r'] += 1
                self.__storage[db]['c'][coll]['r'] += 1
                data = JSONObject(self.__storage[db]['c'][coll]['d'][int(index)])
                data.update(update)
                self.__storage[db]['c'][coll]['d'].pop(int(index))
                self.__storage[db]['c'][coll]['d'].insert(int(index), data.code)
    
    # get index
    def get_index(self, frame: str, data: dict) -> int:
        """:func:`MemoryStorage.get_index` - Get index of object in memory storage
        
        :param frame: Path to frame
        :param data: Sea data
        :type frame: str
        :type data: dict"""

# Temp vars
server = None

# - Info Group
# +- server info
async def server_info(protocol: P, **kwargs) -> Tuple[int, int, dict]:
    """:func:`server_info` - Server info op
    
    :param protocol: Protocol object
    :type protocol: :class:`Protocol`
    
    :return: Group number, code number and json object
    :rtype: :class:`typing.Tuple[int, int, dict]`"""
    size = 0
    if os.path.exists(protocol.config.database.dataFolder):
        for e in os.scandir(protocol.config.database.dataFolder): size += os.path.getsize(e)
    return 1, 1, {"database": {"version": __version__, "protocolVersion": protocol.__version__}, "otherVersion": {"python": f"{platform.python_implementation()} {platform.python_version()}", "bson": version('bson'), "orjson": version('orjson'), "rich": version('rich'), "ruamel.yaml": version('ruamel.yaml')}, "resources": {"ram": psutil.Process().memory_full_info().uss, "dataSize": size}}

# +- server status
async def server_status(**kwargs) -> Tuple[int, int, int]:
    """:func:`server_status` - Server status op
    
    :return: Group number, code number and status code
    :rtype: :class:`typing.Tuple[int, int, int]`"""
    return 1, 1, 0 if server is None or not server.is_serving() else 1

# - Databases group
# +- database list
async def database_list(protocol: P, **kwargs) -> Tuple[int, int, dict]:
    """:func:`database_list` - Get list of databases

    :param protocol: Protocol object
    :type protocol: :class:`Protocol`

    :return: Group number, code number and json object
    :rtype: :class:`typing.Tuple[int, int, dict]`"""
    return 1, 1, {'databases': [{'name': x, **get_database_info(protocol, x)} for x in os.listdir(protocol.config.database.dataFolder)]}

# +- create database
async def create_database(protocol: P, name: str, **kwargs) -> Tuple[int, int, str]:
    """:func:`create_database` - Create database
    
    :param protocol: Protocol object
    :param name: Database name
    :type protocol: :class:`Protocol`
    :type name: str

    :return: Group number, code number and description
    :rtype: :class:`typing.Tuple[int, int, str]`"""
    database = os.path.join(protocol.config.database.dataFolder, name)
    if os.path.exists(database): return 3, 3, f'Database "{name}" is alebry created'

    os.mkdir(database)
    os.mkdir(os.path.join(database, 'collections'))
    created = dt.today().timestamp()
    open(os.path.join(database, 'meta.bson'), 'wb').write(bson.dumps({'created': created}))
    control_memory_storage('databases:add', {'name': name, 'created': created}, protocol)
    protocol.log(0, f'Database "{name}" created.')
    return 1, 1, f'Database "{name}" created'

# +- drop database
async def drop_database(protocol: P, name: str, **kwargs) -> Tuple[int, int, str]:
    """:func:`drop_database` - Drop database
    
    :param protocol: Protocol object
    :param name: Database name
    :type protocol: :class:`Protocol`
    :type name: str

    :return: Group number, code number and description
    :rtype: :class:`typing.Tuple[int, int, str]`"""
    database = os.path.join(protocol.config.database.dataFolder, name)
    if not os.path.exists(database): return 3, 3, f'Database "{name}" not found'

    shutil.rmtree(database)
    control_memory_storage('databases:drop', {'name': name}, protocol)
    protocol.log(0, f'Database "{name}" dropped.')
    return 1, 1, f'Database "{name}" dropped'

# +- database info
async def database_info(protocol: P, name: str, **kwargs) -> Tuple[int, int, dict]:
    """:func:`drop_database` - Drop database
    
    :param protocol: Protocol object
    :param name: Database name
    :type protocol: :class:`Protocol`
    :type name: str

    :return: Group number, code number and json object
    :rtype: :class:`typing.Tuple[int, int, dict]`"""
    database = os.path.join(protocol.config.database.dataFolder, name)
    if not os.path.exists(database): return 3, 3, f'Database "{name}" not found'
    returnd = {'collections': os.listdir(os.path.join(database, 'collections')), 'name': name}
    if name in memory_storage:
        memory_storage[name]['m']['r'] += 1
        returnd['created'] = memory_storage[name]['m']['c']
    else:
        returnd['created'] = get_database_info(protocol, name)['created']
        if protocol.config.database.memoryStorage.enable:
            control_memory_storage('databases:add', {'name': name, 'created': returnd['created']}, protocol)
    return 1, 1, returnd

# - Collections group
# +- collections list
async def collections_list(protocol: P, db: str, **kwargs) -> Tuple[int, int, dict]:
    """:func:`collections_list` - Get list of collections names

    :param protocol: Protocol object
    :param db: Database name
    :type protocol: :class:`Protocol`
    :type db: str

    :return: Group number, code number and json object
    :rtype: :class:`typing.Tuple[int, int, dict]`"""
    database = os.path.join(protocol.config.database.dataFolder, db)
    if not os.path.exists(database): return 3, 3, f'Database "{db}" not found'
    return 1, 1, {'collections': [x[:-5] for x in os.listdir(os.path.join(database, 'collections'))]}

# +- create collection
async def create_collection(protocol: P, db: str, name: str, **kwargs) -> Tuple[int, int, str]:
    """:func:`collections_list` - Get list of collections names

    :param protocol: Protocol object
    :param db: Database name
    :param name: Collection name
    :type protocol: :class:`Protocol`
    :type db: str
    :type name: str

    :return: Group number, code number and description
    :rtype: :class:`typing.Tuple[int, int, str]`"""
    database = os.path.join(protocol.config.database.dataFolder, db)
    collection = os.path.join(os.path.join(database, 'collections'), f'{name}.bson')
    if not os.path.exists(database): return 3, 3, f'Database "{db}" not found'
    elif os.path.exists(collection): return 3, 3, f'Collection "{db}:{name}" is alebry created'

    open(collection, 'wb').write(bson.dumps({'data': []}))
    control_memory_storage('collections:add', {'db': db, 'name': name}, protocol)
    protocol.log(0, f'Collection "{db}:{name}" created.')
    return 1, 1, f'Collection "{db}:{name}" created'

# +- drop collection
async def drop_collection(protocol: P, db: str, name: str, **kwargs) -> Tuple[int, int, str]:
    """:func:`drop_collection` - Drop any collection
    
    :param protocol: Protocol object
    :param db: Database name
    :param name: Collection name
    :type protocol: :class:`Protocol`
    :type db: str
    :type name: str
    
    :return: Group number, code number and description
    :rtype: :class:`typing.Tuple[int, int, str]`"""
    database = os.path.join(protocol.config.database.dataFolder, db)
    collection = os.path.join(os.path.join(database, 'collections'), f'{name}.bson')
    if not os.path.exists(database): return 3, 3, f'Database "{db}" not found'
    elif not os.path.exists(collection): return 3, 3, f'Collection "{db}:{name}" not found'

    os.remove(collection)
    control_memory_storage('collections:drop', {'db': db, 'name': name}, protocol)
    protocol.log(0, f'Collection "{db}:{name}" dropped.')
    return 1, 1, f'Collection "{db}:{name}" dropped'

# - Items group
# +- insert item
async def insert_item(protocol: P, db: str, coll: str, data: dict, **kwargs) -> Tuple[int, int, str]:
    """:func:`drop_collection` - Drop any collection
    
    :param protocol: Protocol object
    :param db: Database name
    :param coll: Collection name
    :param data: Item data
    :type protocol: :class:`Protocol`
    :type db: str
    :type coll: str
    :type data: dict
    
    :return: Group number, code number and description
    :rtype: :class:`typing.Tuple[int, int, str]`"""
    database = os.path.join(protocol.config.database.dataFolder, db)
    collection = os.path.join(os.path.join(database, 'collections'), f'{coll}.bson')
    if not os.path.exists(database): return 3, 3, f'Database "{db}" not found'
    elif not os.path.exists(collection): return 3, 3, f'Collection "{db}:{coll}" not found'

    _data = bson.loads(open(collection, 'rb').read())
    _data['data'].append(data)
    open(collection, 'wb').write(bson.dumps(_data))
    control_memory_storage('items:insert', {'db': db, 'coll': coll, 'item': data}, protocol)
    protocol.log(0, f'New item inserted to "{db}:{coll}" collection')
    return 1, 1, f'This item successfully inserted to "{db}:{coll}" collection'

# +- delete one
async def delete_one(protocol: P, db: str, coll: str, filter: dict, **kwargs) -> Tuple[int, int, str]:
    """:func:`delete_one` - Delete one item by filter
    
    :param protocol: Protocol object
    :param db: Database name
    :param coll: Collection name
    :param filter: Search filter
    :type protocol: :class:`Protocol`
    :type db: str
    :type coll: str
    :type filter: dict
    
    :return: Group number, code number and description
    :rtype: :class:`typing.Tuple[int, int, str]`"""
    database = os.path.join(protocol.config.database.dataFolder, db)
    collection = os.path.join(os.path.join(database, 'collections'), f'{coll}.bson')
    if not os.path.exists(database): return 3, 3, f'Database "{db}" not found'
    elif not os.path.exists(collection): return 3, 3, f'Collection "{db}:{coll}" not found'

    _data = bson.loads(open(collection, 'rb').read())
    data = filtre(filter, _data['data'])
    if data is None: return 3, 3, 'Item by this filter not found'
    _data['data'].pop(_data['data'].index(data))
    open(collection, 'wb').write(bson.dumps(_data))
    protocol.log(0, f'Item deleted from "{db}:{coll}" collection')
    return 1, 1, f'This item successfully deleted from "{db}:{coll}" collection', data

# +- delete all
async def delete_many(protocol: P, db: str, coll: str, filter: dict, **kwargs) -> Tuple[int, int, str, Optional[dict]]:
    """:func:`delete_many` - Delete many items by filter
    
    :param protocol: Protocol object
    :param db: Database name
    :param coll: Collection name
    :param filter: Search filter
    :type protocol: :class:`Protocol`
    :type db: str
    :type coll: str
    :type filter: dict
    
    :return: Group number, code number and description [and data]
    :rtype: :class:`typing.Tuple[int, int, str, typing.Optional[dict]]`"""
    database = os.path.join(protocol.config.database.dataFolder, db)
    collection = os.path.join(os.path.join(database, 'collections'), f'{coll}.bson')
    if not os.path.exists(database): return 3, 3, f'Database "{db}" not found'
    elif not os.path.exists(collection): return 3, 3, f'Collection "{db}:{coll}" not found'

    _data = bson.loads(open(collection, 'rb').read())
    data = filtre(filter, _data['data'], 'many')
    if data is None: return 3, 3, 'Items by this filter not found'
    for item in data: _data['data'].pop(_data['data'].index(item))
    open(collection, 'wb').write(bson.dumps(_data))
    protocol.log(0, f'Items deleted from "{db}:{coll}" collection')
    return 1, 1, f'This items successfully deleted from "{db}:{coll}" collection', {'items': data}

# +- update one
async def update_one(protocol: P, db: str, coll: str, filter: dict, update: dict, **kwargs) -> Tuple[int, int, str, Optional[dict]]:
    """:func:`update_one` - Update one item by filter
    
    :param protocol: Protocol object
    :param db: Database name
    :param coll: Collection name
    :param filter: Search filter
    :param update: Data to update
    :type protocol: :class:`Protocol`
    :type db: str
    :type coll: str
    :type filter: dict
    :type update: dict
    
    :return: Group number, code number and description [and data]
    :rtype: :class:`typing.Tuple[int, int, str, typing.Optional[dict]]`"""
    database = os.path.join(protocol.config.database.dataFolder, db)
    collection = os.path.join(os.path.join(database, 'collections'), f'{coll}.bson')
    if not os.path.exists(database): return 3, 3, f'Database "{db}" not found'
    elif not os.path.exists(collection): return 3, 3, f'Collection "{db}:{coll}" not found'

    _data = bson.loads(open(collection, 'rb').read())
    data = filtre(filter, _data['data'])
    if data is None: return 3, 3, 'Item by this filter not found'
    index = _data['data'].index(data)
    data = JSONObject(data)
    data.update(update)
    _data['data'].pop(index)
    _data['data'].insert(index, data.code)
    open(collection, 'wb').write(bson.dumps(_data))
    protocol.log(0, f'Item from "{db}:{coll}" collection updated')
    return 1, 1, f'This item from "{db}:{coll}" collection successfully updated', data.code

# +- update many
async def update_many(protocol: P, db: str, coll: str, filter: dict, update: dict, **kwargs) -> Tuple[int, int, str, Optional[dict]]:
    """:func:`delete_many` - Update many items by filter
    
    :param protocol: Protocol object
    :param db: Database name
    :param coll: Collection name
    :param filter: Search filter
    :param update: Data to update
    :type protocol: :class:`Protocol`
    :type db: str
    :type coll: str
    :type filter: dict
    :type update: dict
    
    :return: Group number, code number and description [and data]
    :rtype: :class:`typing.Tuple[int, int, str, typing.Optional[dict]]`"""
    database = os.path.join(protocol.config.database.dataFolder, db)
    collection = os.path.join(os.path.join(database, 'collections'), f'{coll}.bson')
    if not os.path.exists(database): return 3, 3, f'Database "{db}" not found'
    elif not os.path.exists(collection): return 3, 3, f'Collection "{db}:{coll}" not found'

    _data = bson.loads(open(collection, 'rb').read())
    data = filtre(filter, _data['data'], 'many')
    updated = []
    if data is None: return 3, 3, 'Items by this filter not found'
    for item in data:
        index = _data['data'].index(item)
        item = JSONObject(item)
        item.update(update)
        _data['data'].pop(index)
        _data['data'].insert(index, item.code)
        updated.append(item.code)
    open(collection, 'wb').write(bson.dumps(_data))
    protocol.log(0, f'Items from "{db}:{coll}" collection updated')
    return 1, 1, f'This items from "{db}:{coll}" collection successfully updated', {'items': updated}

# +- find one
async def find_one(protocol: P, db: str, coll: str, filter: dict, **kwargs) -> Tuple[int, int, str, Optional[dict]]:
    """:func:`find_one` - Find one item by filter
    
    :param protocol: Protocol object
    :param db: Database name
    :param coll: Collection name
    :param filter: Search filter
    :type protocol: :class:`Protocol`
    :type db: str
    :type coll: str
    :type filter: dict
    
    :return: Group number, code number and description [and data]
    :rtype: :class:`typing.Tuple[int, int, str, typing.Optional[dict]]`"""
    database = os.path.join(protocol.config.database.dataFolder, db)
    collection = os.path.join(os.path.join(database, 'collections'), f'{coll}.bson')
    if not os.path.exists(database): return 3, 3, f'Database "{db}" not found'
    elif not os.path.exists(collection): return 3, 3, f'Collection "{db}:{coll}" not found'

    _data = bson.loads(open(collection, 'rb').read())
    data = filtre(filter, _data['data'])
    if data is None: return 1, 1, 'Item by this filter not found'
    return 1, 1, f'Item found!', data

# Run a SyrDB Server
if __name__ == "__main__":
    async def run(config: YAMLObject):
        """:func:`run` - Run a SyrDB Server
        
        :param config: Server config
        :type config: :class:`YAMLObject`"""
        # - protocol settings -
        protocol = Protocol(config) # New protocol object

        # Auth Group
        auth_group = protocol.add_group(b'\x00', 'Auth')
        auth_group.add_op(auth, b'\x00')

        # Info group
        info_group = protocol.add_group(b'\x01', 'Info')
        info_group.add_op(server_info, b'\x01', required_perms=['info'])
        info_group.add_op(server_status, b'\x02', required_perms=['info'])

        # Databases group
        databases_group = protocol.add_group(b'\x02', 'Databases')
        databases_group.add_op(database_list, b'\x01', required_perms=['info'])
        databases_group.add_op(create_database, b'\x02', ['name'], ['manage'], 'name')
        databases_group.add_op(drop_database, b'\x03', ['name'], ['manage'], 'name')
        databases_group.add_op(database_info, b'\x04', ['name'], ['info'], 'name')

        # Collections group
        collections_group = protocol.add_group(b'\x03', 'Collections')
        collections_group.add_op(collections_list, b'\x01', ['db'], ['info'], 'db')
        collections_group.add_op(create_collection, b'\x02', ['db', 'name'], ['manage'], 'db')
        collections_group.add_op(drop_collection, b'\x03', ['db', 'name'], ['manage'], 'db')

        # Items group
        items_group = protocol.add_group(b'\x04', 'Items')
        items_group.add_op(insert_item, b'\x01', ['db', 'coll', 'data'], ['write', 'readAndWrite'], 'db')
        items_group.add_op(delete_one, b'\x02', ['db', 'coll', 'filter'], ['write', 'readAndWrite'], 'db')
        items_group.add_op(delete_many, b'\x03', ['db', 'coll', 'filter'], ['write', 'readAndWrite'], 'db')
        items_group.add_op(update_one, b'\x04', ['db', 'coll', 'filter', 'update'], ['write', 'readAndWrite'], 'db')
        items_group.add_op(update_many, b'\x05', ['db', 'coll', 'filter', 'update'], ['write', 'readAndWrite'], 'db')
        items_group.add_op(find_one, b'\x06', ['db', 'coll', 'filter'], ['write', 'readAndWrite'], 'db')
        # --------- + ---------

        rich.console.Console(theme=rich.theme.Theme({'repr.brace': 'none', 'repr.number': 'none'})).print(f'[bright_magenta] ___  _  _  ____  ____  ____ \n/ __)( \/ )(  _ \(  _ \(  _ \\     Version:            [white]{__version__}[/white]\n\__ \ \  /  )   / )(_) )) _ (     Protocol Version:   [white]{protocol.__version__}[/white]\n(___/ (__) (_)\_)(____/(____/     Release Type:       [white]{("[red]Alpha[/red]" if "a" in __version__ else "[yellow]Beta[/yellow]" if "b" in __version__ else "[green]Stable[/green]")+(" for Developers" if "dev" in __version__ else "")}[/white][/bright_magenta]')
        print()

        # - check all files -
        if not os.path.exists(config.database.dataFolder):
            protocol.log(1, 'The data folder was not found, but we have created it.')
            os.mkdir(config.database.dataFolder)
        # -------- + --------

        host, port = config.database.network.host, config.database.network.port
        global server
        server = await asyncio.start_server(protocol.handle_connection, host, port)
        protocol.log(0, f'SyrDB Server listening on syrdb://{host}:{port}')
        async with server:
            await server.serve_forever()

    try: content = open('config.yml', 'r', encoding='UTF-8').read()
    except: content = "none: null"

    asyncio.run(run(YAMLObject(YAML().load(content), {"database": {"network": {"host": "localhost", "port": 2993}, "memoryStorage": {"enable": True, "maxDatabases": 5, "maxCollection": 5, "maxItems": 10}, "dataFolder": "./data"}, "admin": {"enable": True, "users": [{"username": "root", "password": "root", "permissions": "admin"}]}, "logger": {"console": {"enable": True, "level": "DEBUG"}, "file": {"enable": False, "level": "DEBUG", "folder": "logs", "filename": "DD.MM.YYYY.log", "loggingFormat": "sdb-journal"}}, "security": {"auth": {"enable": False, "accessToken": "CHANGE ME", "users": [{"username": "root", "password": "root", "permissions": "admin", "db": "$all", "maxAuthentications": -1}]}, "maxConnections": -1}, "streams": {"enable": False, "mode": "auto", "autoSettings": {"maxThreads": 5}}})))