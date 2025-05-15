import asyncio
import hashlib
import string
import random
import rapidjson
import sys, os, platform
import re
import datetime
from typing import List, Any, Union, Tuple, Optional


# classes
# + config
class Config:
    def __init__(self, file: str):
        data = rapidjson.load(open(file, "r", encoding="UTF-8"))

        self.host = data['$main']['host']
        self.port = data['$main']['port']
        self.data_folder = data['$main']['dataFolder']

        self.auth_enable = data['$auth']['enable']
        self.access_token = data['$auth']['accessToken']
        self.users = data['$auth']['users']

# + protocol
class Protocol:
    __version__ = "0.2"

    def __init__(self, config: Config):
        self.config = config
        self.__operations = []

    # operation decorator
    def op(self, op: str, required_vars: List[str]=[], required_perms: List[str]=[], check_db_access: str=None):
        def decorator(func):
            required_perms.append('admin')
            self.__operations.append((op, func, required_vars, required_perms, check_db_access))
            return op
        return decorator

    # log
    def log(self, type: str, content: str):
        data = rapidjson.load(open(f"{self.config.data_folder}/logs/data.json", 'r', encoding="UTF-8"))
        data['logs'].append({'type': type, 'content': content, 'time': datetime.datetime.today().timestamp()})
        rapidjson.dump(data, open(f"{self.config.data_folder}/logs/data.json", 'w', encoding="UTF-8"), ensure_ascii=False)

    # run operation
    async def run_op(self, data: dict):
        if None in [data['op'], data['vars']]: return 22
        else:
            auth = 20
            if self.config.auth_enable:
                if data['auth'] is None: return 22
                for user in self.config.users:
                    if user['username'] != data['auth']['authorization']['username']: continue
                    elif user['password'] != data['auth']['authorization']['password']: continue
                    elif user['db'] != data['auth']['authorization']['db']: continue
                    else: auth = user
                if self.config.access_token != data['auth']['accessToken']: auth = 21
            else: auth = False
            if isinstance(auth, int): return auth
            elif isinstance(auth, dict) or not auth:
                if not auth: auth = {'permissions': 'admin'}
                op_found = False
                for op in self.__operations:
                    if op[0] == data['op']:
                        if True in [x in auth['permissions'] for x in op[3]]:
                            if False not in [x in data['vars'] for x in op[2]]:
                                if op[4] is not None:
                                    db = data['vars'][op[4]]
                                    if not os.path.exists(f'{config.data_folder}/{db}'): return 30, "No such database exists"
                                    elif db != auth['db'] and auth['db'] != 'all': return 23, f"You do not have access to database \"{db}\""
                                op_found = True
                                protocol.log('info', f'{op[0]} operation request received')
                                return await op[1](**{k.lower(): v for k, v in data['vars'].items()})
                            else: return 22
                        else: return 24
                if not op_found: return 25

# + headers
class Headers:
    def __init__(self, protocol: Protocol):
        self.protocol = protocol
        self.code_descriptions = {
            1: "AUTHORIZED",
            10: "SUCCESSFULLY",
            20: "AUTHORIZATION FAILED",
            22: "NOT ENOUGH PARAMETERS",
            23: "YOU DO NOT HAVE ACCESS TO THIS DATABASE",
            24: "YOU HAVE NO RIGHT TO THIS",
            25: "UNKNOWN OPERATION",
            30: "THE SERVER COULD NOT PROCESS THE REQUEST",
            31: "VERSION MAGMADB PROTOCOL IS NOT SUPPORTED",
            32: "UNKNOWN ERROR"
        }

    # format headers
    def format(self, code: int, description: str, content_type: str=None, content: Any=None, called: str=None):
        def to_json(content: Any): return rapidjson.dumps(content, ensure_ascii=False)
        def to_vars(content: Any):
            def get_content(content: Any): return {str: f'"{content}"', int: str(content), float: str(content), bool: 'true' if content else 'false', dict: rapidjson.dumps(content, ensure_ascii=False)}[content.__class__]
            return "\n".join(f':{k} {get_content(v)}' for k, v in content.items())
        ctypes = {"json": to_json, "magmadb:vars": to_vars}
        return ('MagmaDB/%s %s %s\n&Answer "%s"\n&ContentSize %s%s%s' % (self.protocol.__version__, code, self.code_descriptions[code], description, len(content) if content is not None else 0, '\n&ContentType $contentType{%s}' % content_type if content_type is not None else '', '\n&CalledMethod "%s"' % called if called is not None else ''), ctypes.get(content_type, str)(content) if content_type is not None else None)

    # parse
    def parse(self, headers: str, type: Union[str, Tuple[str, str]]="headers"):
        # --- Client request to auth:
        # MagmaDB/0.2 AUTH
        # &UserData (
        #     ^user $user{<username>:<password>}
        #     ^db "<db>"
        # )
        # &AccessToken "<accessToken>"
        # &ConnectionProvider (
        #     ^name "<provider-name>"
        #     ^description "<provider-description>"
        #     ^lang $providerLang{<provider-programming-lang>[:<provider-programming-sublang>]}
        #     ^version "<provider-version>"
        # )
        # &ContentSize 0
        #
        # --- Server response
        # MagmaDB/0.2 1 AUTHORIZED
        # &Answer "You have successfully logged in MagmaDB Server"
        # &ContentSize <content-size>
        # &ContentType $contentType{hash:authCode}
        #
        # --- Server response 2(content)
        # <auth code hash>
        def foh(header: str):
            return header.replace(header[0], header[0].lower(), 1)

        def fohc(content: str, delete_indexes: List[int]=[]):
            tokens = [
                (r'\(([\w\W\d\D\s\S]*)\)', 'class'),
                (r'\$([a-zA-Z]+)\{(.*)\}', 'specialMeaning'),
                (r'^["\'](.*)["\']$', 'string'),
                (r'[0-9]+\.[0-9]+', 'float'),
                (r'[0-9]+', 'number'),
                (r'true|false', 'boolean'),
                (r'\[([\w\W\d\D\s\S]*)\]', 'list'),
                (r'\{[\w\W\d\D\s\S]*\}', 'json')
            ]
            for i in delete_indexes: tokens.pop(i)
            for t in tokens:
                tre = re.findall(t[0], content, re.M)
                if len(tre):
                    tre: str = tre[0]; r = None
                    if t[1] == "specialMeaning": r = {"_isSpecialMeaning": True, "name": tre[0], "value": tre[1]}
                    elif t[1] == "string": r = tre
                    elif t[1] == "float": r = float(tre)
                    elif t[1] == "number": r = int(tre)
                    elif t[1] == "boolean": r = tre == "true"
                    elif t[1] == "list": r = re.split(r'\,(?:[\s\S]+)?', tre, flags=re.M)
                    elif t[1] == "json": r = rapidjson.loads(tre)
                    elif t[1] == "class": r = {x[0].lower(): fohc(x[1], [0]) for x in re.findall(r'\^([a-zA-Z0-9\-]+) (.+)', tre, re.M)}
                    return r
                else: continue
            return None

        parsed = {}
        if type == "headers":
            try:
                parsed = {'options': {}}
                mheaders: List[str] = re.findall(r'MagmaDB\/([0-9]+\.[0-9]+) ([A-Z\:\-]+)', headers)[0]
                oheaders: dict = {foh(x[0]): fohc(x[1]) for x in re.findall(r'^\&([a-zA-Z]+)\ (["\'].*["\']|[0-9]+(?:\.[0-9]+)?|(?:true|false)|\[@\]|\{@\}|\([^\(\)]*\))'.replace(r'@', r'[\w\W\d\D\s\S]*'), headers, re.M)}
                parsed['protocolVersion'] = mheaders[0]
                parsed['op'] = mheaders[1]
                parsed['contentSize'] = oheaders.pop("contentSize")
                parsed['contentType'] = oheaders.pop("contentType") if oheaders.get("contentType") is not None else None
                for k, v in oheaders.items(): parsed['options'][k] = v
                return parsed
            except: return None
        else:
            try:
                if type == "json": return rapidjson.loads(headers)
                elif type == "magmadb:vars": return {x[0]: fohc(x[1], [0,1]) for x in re.findall(r'\:([a-zA-Z0-9]+) (.*)', headers)}
                else: return str(headers)
            except: return None

# + json content
class JsonContent:
    def __init__(self, code):
        self.code = code
    def get(self, key: str=None, _or: Any=None, type: str="one"):
        v: dict = self.code
        if type == "list": rv: List[JsonContent] = None
        if key is not None:
            for k in key.split("."):
                if isinstance(v, dict) and k in v:
                    if type == "one": v = v.get(k, _or)
                    elif type == "list": v = v.get(k)
            if type == "list": rv = [JsonContent(x) for x in v]
        elif type == "list": rv = [(x[0], JsonContent(x[1])) for x in v.items()]
        return v if type == "one" else rv
    def set(self, key: str, value: Any=None):
        keys = key.split('.')
        item = self.code
        for key in keys[:-1]:
            item = item[key]
        if value is not None: item[keys[-1]] = value
        else: del item[keys[-1]]

# functions
# + parse args
def parse_args(args: List[str]):
    arg_name = None
    out = {"arguments": []}
    for arg in args:
        if arg.startswith("-"):
            out[arg[1:]] = True
            arg_name = arg[1:]
        elif arg_name:
            if arg.startswith(("'", "\"")):
                out[arg_name] = f"{arg[1:]} "
            elif not arg.endswith(("'", "\"")):
                out[arg_name] = arg
            elif arg.endswith(("'", "\"")):
                out[arg_name] += f" {arg[:-1]}"
                arg_name = None
            else:
                out[arg_name] = arg
        else:
            out["arguments"].append(arg)
    return out

# + send
async def send(headers: Headers, writer: asyncio.StreamWriter, data: Union[int, Tuple[int, str, Optional[dict]]], hdata: dict, content_type: str="json"):
    async def _send(content: bytes):
        writer.write(content)
        await writer.drain()
    if isinstance(data, int):
        headers = headers.format(data, headers.code_descriptions[data].title(), called=hdata.get('op', 'NOT SPECIFIED'))
        await _send(headers[0].encode("utf-8"))
        if data in [20, 31]: writer.close()
    elif isinstance(data, tuple):
        headers = headers.format(data[0], data[1], data[3] if len(data) == 4 else content_type, data[2] if len(data) == 3 else None, hdata.get('op', 'NOT SPECIFIED'))
        await _send(headers[0].encode("utf-8"))
        if headers[1] is not None: await _send(headers[1].encode("utf-8"))
    elif isinstance(data, str): await _send(data.encode("utf-8"))

# + filtre
def filtre(filter: dict, data: List[dict], mode: str="one"):
    items: List[JsonContent] = [i.get() for i in [JsonContent(x) for x in data] if i is not None and False not in [i.get(k) == v for k, v in filter.items()]]
    if mode == "one": return items[0] if len(items) else None
    elif mode == "many": return items if len(items) else None

# vars
args = parse_args(sys.argv)
config = Config(args.get('-config', args.get('C', 'config.json')))
protocol = Protocol(config)
headers = Headers(protocol)

# + temp
auth_ids = {}

# create default folders
if not os.path.exists(config.data_folder):
    os.mkdir(config.data_folder)
    os.mkdir(f"{config.data_folder}/logs")
    with open(f"{config.data_folder}/logs/data.json", 'w', encoding="UTF-8") as f:
        rapidjson.dump({"logs": []}, f, ensure_ascii=False)
    with open(f"{config.data_folder}/logs/info.json", 'w', encoding="UTF-8") as f:
        rapidjson.dump({"created": datetime.datetime.today().timestamp()}, f, ensure_ascii=False)

# operations
# + server info
@protocol.op('SERVER-INFO', [], ['info'])
async def server_info(**kwargs):
    """Get MagmaDB Server information"""
    return 10, "MagmaDB Server information received successfully", {
        "version": "v0.0.2b1",
        "versionArray": [0, 0, 2, 'b', 1],
        "protocolVersion": protocol.__version__,
        "testedOS": "Windows 10",
        "minSystemRequirements": {
            "os": "All Systems with the support Python 3.9.0+",
            "memory": "40 MB+",
            "disk": "21 MB+",
            "versions": {"python": "3.9.0+"}
        },
        "version-info": {
            "python": f"Python {platform.python_version()} {platform.python_revision()}({platform.python_implementation()})",
            "rapidjson": rapidjson.__version__
        },
        "operations": [{
            "op": x[0],
            "description": x[1].__doc__,
            "requiredParameters": x[2],
            "requiredRights": f" or ".join(x[3])
        } for x in protocol._Protocol__operations]
    }

# + databases
# +-- create
@protocol.op('DATABASE:CREATE', ['name'], [])
async def create_database(name: str, **kwargs):
    """Create a new database"""
    if os.path.exists(f'{config.data_folder}/{name}'): return 30, "Such a database already exists"
    
    os.mkdir(f'{config.data_folder}/{name}')
    open(f'{config.data_folder}/{name}/data.json', 'w', encoding="UTF-8").write('{}')
    created = datetime.datetime.today().timestamp()
    rapidjson.dump({"created": created}, open(f'{config.data_folder}/{name}/info.json', 'w', encoding="UTF-8"), ensure_ascii=False)
    protocol.log('info', f'Database "{name}" created')
    return 10, f"Database \"{name}\" created successfully", {"name": name, "created": created}

# +-- list
@protocol.op('DATABASE:LIST', [], ['info'])
async def list_databases(**kwargs):
    """Get a list of all databases"""
    databases = [{
        "name": x,
        "created": rapidjson.load(open(f'{config.data_folder}/{x}/info.json', 'r', encoding="UTF-8"))['created']
    } for x in os.listdir(config.data_folder)]
    return 10, "List of databases received successfully", {"databases": databases}

# +-- drop
@protocol.op('DATABASE:DROP', ['name'], ['manage'], "name")
async def drop_database(name: str, **kwargs):
    """Drop a database"""
    for file in os.listdir(f'{config.data_folder}/{name}'): os.remove(f'{config.data_folder}/{name}/{file}')
    os.rmdir(f'{config.data_folder}/{name}')
    protocol.log('info', f'Database "{name}" dropped')
    return 10, f"Database \"{name}\" successfully dropped"

# + collections
# +-- create
@protocol.op('COLLECTION:CREATE', ['name', 'database'], ['manage'], "database")
async def create_collection(name: str, database: str, **kwargs):
    """Create a new collection in the database"""
    data = rapidjson.load(open(f'{config.data_folder}/{database}/data.json', "r", encoding="UTF-8"))
    data[name] = []
    rapidjson.dump(data, open(f'{config.data_folder}/{database}/data.json', "w", encoding="UTF-8"))
    protocol.log('info', f'Collection "{name}" created in "{database}" database')
    return 10, f"Collection \"{name}\" successfully created in database \"{database}\""

# +-- list
@protocol.op('COLLECTION:LIST', ['database'], ['info'], "database")
async def list_collections(database: str, **kwargs):
    """Get a list of all collections in the database"""
    data = rapidjson.load(open(f'{config.data_folder}/{database}/data.json', "r", encoding="UTF-8"))
    return 10, f"List of collections in database \"{database}\" received successfully", {"collections": list(data.keys())}

# +-- drop
@protocol.op('COLLECTION:DROP', ['name', 'database'], ['manage'], "database")
async def drop_collection(name: str, database: str, **kwargs):
    """Drop collection in the database"""
    data = rapidjson.load(open(f'{config.data_folder}/{database}/data.json', "r", encoding="UTF-8"))
    if name not in data: return 30, f"There is no such collection in \"{database}\" database"
    del data[name]
    rapidjson.dump(data, open(f'{config.data_folder}/{database}/data.json', "w", encoding="UTF-8"))
    protocol.log('info', f'Collection "{name}" dropped in "{database}" database')
    return 10, f"Collection \"{name}\" successfully dropped in database \"{database}\""

# + items
# +-- insert
@protocol.op('ITEM:INSERT', ['data', 'collection', 'database'], ['write', 'writeAndRead', 'manage'], "database")
async def insert_item(data: str, collection: str, database: str, **kwargs):
    """Insert item to collection"""
    db_data = rapidjson.load(open(f'{config.data_folder}/{database}/data.json', "r", encoding="UTF-8"))
    if collection not in db_data: return 30, f"There is no such collection in \"{database}\" database"

    try: data = rapidjson.loads(data)
    except: return 30, 'JSON syntax was broken'
    db_data[collection].append(data)
    rapidjson.dump(db_data, open(f'{config.data_folder}/{database}/data.json', "w", encoding="UTF-8"))
    protocol.log('info', f'Inserted a new item to "{collection}" collection in "{database}" database')
    return 10, f'Item successfully inserted into "{collection}" collection in "{database}" database', {"collection": collection, "database": database, "item": data}

# +-- find one
@protocol.op('ITEM:FIND-ONE', ['filter', 'collection', 'database'], ['read', 'writeAndRead', 'manage'], "database")
async def find_one_item(filter: str, collection: str, database: str, **kwargs):
    """Find one item in collection by filter"""
    data = rapidjson.load(open(f'{config.data_folder}/{database}/data.json', "r", encoding="UTF-8"))
    if collection not in data: return 30, f"There is no such collection in \"{database}\" database"

    try: fdata = filtre(rapidjson.loads(filter), data[collection])
    except: return 30, 'JSON syntax was broken'
    if fdata is None: return 30, f'In the collection "{collection}" by this filter nothing was found'
    return 10, f'An entry was found in collection "{collection}" by the given filter', {"item": fdata}

# +-- find all
@protocol.op('ITEM:FIND-ALL', ['filter', 'collection', 'database'], ['read', 'writeAndRead', 'manage'], "database")
async def find_all_items(filter: str, collection: str, database: str, **kwargs):
    """Find all items in collection by filter"""
    data = rapidjson.load(open(f'{config.data_folder}/{database}/data.json', "r", encoding="UTF-8"))
    if collection not in data: return 30, f"There is no such collection in \"{database}\" database"

    try: fdata = filtre(rapidjson.loads(filter), data[collection], "many")
    except: return 30, 'JSON syntax was broken'
    if fdata is None: return 30, f'In the collection "{collection}" by this filter nothing was found'
    return 10, f'An entry was found in collection "{collection}" by the given filter', {"items": fdata}

# +-- update one
@protocol.op('ITEM:UPDATE-ONE', ['update', 'filter', 'collection', 'database'], ['write', 'writeAndRead', 'manage'], "database")
async def update_one_item(update: str, filter: str, collection: str, database: str, **kwargs):
    """Update one item in collection by filter"""
    data = rapidjson.load(open(f'{config.data_folder}/{database}/data.json', "r", encoding="UTF-8"))
    if collection not in data: return 30, f"There is no such collection in \"{database}\" database"

    try:
        item = filtre(rapidjson.loads(filter), data[collection])
        if item is None: return 30, f'In the collection "{collection}" by this filter nothing was found'
        payload: JsonContent = JsonContent(item)
        update: JsonContent = JsonContent(rapidjson.loads(update))
        for type in update.get(type="list"):
            for k, v in type[1].code.items():
                type = re.findall(r'\:([a-z]+)', type[0])
                if len(type):
                    type = type[0]
                    if type == "set": payload.set(k, v)
                    elif type == "sum": payload.set(k, payload.get(k)+v)
                    elif type == "sub": payload.set(k, payload.get(k)-v)
                    elif type == "add": p = payload.get(k); p.append(v); payload.set(k, p)
                    elif type == "rem": p = payload.get(k); p.pop(p.index(v)); payload.set(k, p)
                    elif type == "del": payload.set(k)
                else: continue
        index = data[collection].index(item)
        data[collection].pop(index)
        data[collection].insert(index, payload.code)
        rapidjson.dump(data, open(f'{config.data_folder}/{database}/data.json', "w", encoding="UTF-8"))
    except: return 30, 'JSON syntax was broken'

    protocol.log('info', f'Updated item in "{collection}" collection in "{database}" database')
    return 10, f'Item found by filter in collection "{collection}" was successfully updated'

# +-- update all
@protocol.op('ITEM:UPDATE-ALL', ['update', 'filter', 'collection', 'database'], ['write', 'writeAndRead', 'manage'], "database")
async def update_all_items(update: str, filter: str, collection: str, database: str, **kwargs):
    """Update all items in collection by filter"""
    data = rapidjson.load(open(f'{config.data_folder}/{database}/data.json', "r", encoding="UTF-8"))
    if collection not in data: return 30, f"There is no such collection in \"{database}\" database"

    try:
        items = filtre(rapidjson.loads(filter), data[collection], "many")
        if items is None: return 30, f'In the collection "{collection}" by this filter nothing was found'
        update: JsonContent = JsonContent(rapidjson.loads(update))
        for item in items:
            payload = JsonContent(item)
            for type in update.get(type="list"):
                for k, v in type[1].code.items():
                    type = re.findall(r'\:([a-z]+)', type[0])
                    if len(type):
                        type = type[0]
                        try:
                            if type == "set": payload.set(k, v)
                            elif type == "sum": payload.set(k, payload.get(k)+v)
                            elif type == "sub": payload.set(k, payload.get(k)-v)
                            elif type == "add": p = payload.get(k); p.append(v); payload.set(k, p)
                            elif type == "rem": p = payload.get(k); p.pop(p.index(v)); payload.set(k, p)
                            elif type == "del": payload.set(k)
                        except: continue
                    else: continue
            index = data[collection].index(item)
            data[collection].pop(index)
            data[collection].insert(index, payload.code)
            rapidjson.dump(data, open(f'{config.data_folder}/{database}/data.json', "w", encoding="UTF-8"))
    except: return 30, 'JSON syntax was broken'

    protocol.log('info', f'Updated items in "{collection}" collection in "{database}" database')
    return 10, f'Items found by filter in collection "{collection}" was successfully updated'

# +-- delete one
@protocol.op('ITEM:DELETE-ONE', ['filter', 'collection', 'database'], ['write', 'writeAndRead', 'manage'], "database")
async def delete_one_item(filter: str, collection: str, database: str, **kwargs):
    """Delete one item from collection by filter"""
    data = rapidjson.load(open(f'{config.data_folder}/{database}/data.json', "r", encoding="UTF-8"))
    if collection not in data: return 30, f"There is no such collection in \"{database}\" database"

    try: fdata = filtre(rapidjson.loads(filter), data[collection])
    except: return 30, 'JSON syntax was broken'
    if fdata is None: return 30, f'In the collection "{collection}" by this filter nothing was found'

    data[collection].pop(data[collection].index(fdata))
    rapidjson.dump(data, open(f'{config.data_folder}/{database}/data.json', "w", encoding="UTF-8"))

    protocol.log('info', f'Deleted item in "{collection}" collection in "{database}" database')
    return 10, f'Item found by filter in collection "{collection}" was successfully deleted'

# +-- delete all
@protocol.op('ITEM:DELETE-ALL', ['filter', 'collection', 'database'], ['write', 'writeAndRead', 'manage'], "database")
async def delete_all_items(filter: str, collection: str, database: str, **kwargs):
    """Delete all items from collection by filter"""
    data = rapidjson.load(open(f'{config.data_folder}/{database}/data.json', "r", encoding="UTF-8"))
    if collection not in data: return 30, f"There is no such collection in \"{database}\" database"

    try: fdata = filtre(rapidjson.loads(filter), data[collection], "many")
    except: return 30, 'JSON syntax was broken'
    if fdata is None: return 30, f'In the collection "{collection}" by this filter nothing was found'

    for item in fdata: data[collection].pop(data[collection].index(item))
    rapidjson.dump(data, open(f'{config.data_folder}/{database}/data.json', "w", encoding="UTF-8"))

    protocol.log('info', f'Deleted item in "{collection}" collection in "{database}" database')
    return 10, f'Item found by filter in collection "{collection}" was successfully deleted'

# server
if __name__ == "__main__":
    async def run():
        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            async def start_session(data: dict, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
                if False not in [x in data['options'] for x in ['userData', 'accessToken', 'connectionProvider']]:
                    auth = None
                    if False not in [x in data['options']['userData'] for x in ['user', 'db']]:
                        if data['options']['accessToken'] == hashlib.md5(config.access_token.encode("utf-8")).hexdigest():
                            for user in config.users:
                                if data['options']['userData']['user']['name'] != "user": auth = None
                                elif data['options']['userData']['user']['value'].split(":")[0] != hashlib.md5(user['username'].encode("utf-8")).hexdigest(): auth = None
                                elif data['options']['userData']['user']['value'].split(":")[1] != hashlib.md5(user['password'].encode("utf-8")).hexdigest(): auth = None
                                elif data['options']['userData']['db'] != hashlib.md5(user['db'].encode("utf-8")).hexdigest(): auth = None
                                else: auth = user
                    if auth is None: return await send(headers, writer, 20, {'op': 'AUTH'})
                    else:
                        auth_id = hashlib.md5("".join(random.choice(string.ascii_letters+string.digits) for x in range(20)).encode("utf-8")).hexdigest()
                        auth_data = (writer.get_extra_info('peername'), user['permissions'], user['db'])
                else: return await send(headers, writer, 20, {'op': 'AUTH'})
            #data = await reader.read(2048)
            #data = headers.parse(data.decode("utf-8"))
            #writer.write('1'.encode("utf-8"))
            #await writer.drain()
            #vdata = {}
            #if data['contentSize'] != 0:
            #    vdata = await reader.read(data['contentSize'])
            #    vdata = vdata.decode("utf-8")
            #    vdata = {x[0]: x[1] for x in re.findall(r'\$([a-zA-Z]+)\: (.*)', vdata)}
            #data['vars'] = vdata

            #if data['protocolVersion'] != protocol.__version__: answer = 31
            #else: answer = await protocol.run_op(data)
            #await send(headers, writer, answer, data)

            data = await reader.read(2048)
            data = headers.parse(data.decode("utf-8"))
            if data is None: return await send(headers, writer, 20, {'op': 'AUTH'})
            else: return await start_session(data, reader, writer)
        server = await asyncio.start_server(handler, config.host, config.port)
        protocol.log('info', f'MagmaDB Server listing on {config.host}:{config.port}')
        async with server:
            await server.serve_forever()
    asyncio.run(run())