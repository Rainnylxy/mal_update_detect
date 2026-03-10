import networkx as nx
import sys
SENSITIVE_SYSCALL_STRINGS = [
    'shutil.py:<module>.copyfileobj',
    'shutil.py:<module>.copyfile',
    'shutil.py:<module>.copymode',
    'shutil.py:<module>.copystat',
    'shutil.py:<module>.copy',
    'shutil.py:<module>.copy2',
    'shutil.py:<module>.copytree',
    'shutil.py:<module>.rmtree',
    'shutil.py:<module>.move',
    'tempfile.py:<module>.gettempdir',
    'tempfile.py:<module>.NamedTemporaryFile',
    'tempfile.py:<module>.TemporaryFile',
    'pkgutil.py:<module>.find_module',
    'pkgutil.py:<module>.iter_modules',
    'pkgutil.py:<module>.read_code',
    'pkgutil.py:<module>.walk_packages',
    'pkgutil.py:<module>.iter_importer_modules',
    'pkgutil.py:<module>.get_importer',
    'pkgutil.py:<module>.iter_importers',
    'pkgutil.py:<module>.get_loader',
    'pkgutil.py:<module>.find_loader',
    'pkgutil.py:<module>.extend_path',
    'pkgutil.py:<module>.get_data',
    'pkgutil.py:<module>.resolve_name',
    'pkgutil.py:<module>.load_module',
    'pkgutil.py:<module>.is_package',
    'pkgutil.py:<module>.get_code',
    'pkgutil.py:<module>.get_source',
    'pkgutil.py:<module>.get_filename',
    'pkgutil.py:<module>.iter_zipimport_modules',
    'gzip.py:<module>.compress',
    'webbrowser.py:<module>.open',
    'base64.py:<module>.b64encode',
    'base64.py:<module>.b64decode',
    'base64.py:<module>.standard_b64encode',
    'base64.py:<module>.standard_b64decode',
    'base64.py:<module>.urlsafe_b64encode',
    'base64.py:<module>.urlsafe_b64decode',
    'base64.py:<module>.b32encode',
    'base64.py:<module>.b32decode',
    'base64.py:<module>.b32hexencode',
    'base64.py:<module>.b32hexdecode',
    'base64.py:<module>.b16encode',
    'base64.py:<module>.b16decode',
    'base64.py:<module>.a85encode',
    'base64.py:<module>.a85decode',
    'base64.py:<module>.b85encode',
    'base64.py:<module>.b85decode',
    'base64.py:<module>.encode',
    'base64.py:<module>.decode',
    'base64.py:<module>.encodebytes',
    'base64.py:<module>.decodebytes',
    'bisect.py:<module>.bisect_right',
    'warnings.py:<module>.showwarning',
    'warnings.py:<module>.formatwarning',
    'warnings.py:<module>.filterwarnings',
    'warnings.py:<module>.simplefilter',
    'warnings.py:<module>.resetwarnings',
    'warnings.py:<module>.warn',
    'warnings.py:<module>.warn_explicit',
    'subprocess.py:<module>.call',
    'subprocess.py:<module>.check_call',
    'subprocess.py:<module>.check_output',
    'subprocess.py:<module>.run',
    'subprocess.py:<module>.list2cmdline',
    'subprocess.py:<module>.getstatusoutput',
    'subprocess.py:<module>.getoutput',
    'codecs.py:<module>.open',
    'os.py:<module>.copy',
    'os.py:<module>.setdefault',
    'os.py:<module>.makedirs',
    'os.py:<module>.removedirs',
    'os.py:<module>.renames',
    'os.py:<module>.walk',
    'os.py:<module>.fwalk',
    'os.py:<module>.execl',
    'os.py:<module>.execle',
    'os.py:<module>.execlp',
    'os.py:<module>.execlpe',
    'os.py:<module>.execvp',
    'os.py:<module>.execvpe',
    'os.py:<module>.get_exec_path',
    'os.py:<module>.getenv',
    'os.py:<module>.getenvb',
    'os.py:<module>.spawnv',
    'os.py:<module>.spawnve',
    'os.py:<module>.spawnvp',
    'os.py:<module>.spawnvpe',
    'os.py:<module>.spawnl',
    'os.py:<module>.spawnle',
    'os.py:<module>.spawnlp',
    'os.py:<module>.spawnlpe',
    'os.py:<module>.popen',
    'os.py:<module>.fdopen',
    'os.py:<module>.add_dll_directory',
    'os.py:<module>.close',
    'random.py:<module>.seed',
    'random.py:<module>.getstate',
    'random.py:<module>.setstate',
    'random.py:<module>.randbytes',
    'random.py:<module>.randrange',
    'random.py:<module>.randint',
    'random.py:<module>.choice',
    'random.py:<module>.shuffle',
    'random.py:<module>.sample',
    'random.py:<module>.choices',
    'random.py:<module>.uniform',
    'random.py:<module>.triangular',
    'random.py:<module>.normalvariate',
    'random.py:<module>.gauss',
    'random.py:<module>.lognormvariate',
    'random.py:<module>.expovariate',
    'random.py:<module>.vonmisesvariate',
    'random.py:<module>.gammavariate',
    'random.py:<module>.betavariate',
    'random.py:<module>.paretovariate',
    'random.py:<module>.weibullvariate',
    'random.py:<module>.random',
    'random.py:<module>.getrandbits',
    'platform.py:<module>.uname',
    'platform.py:<module>.system',
    'platform.py:<module>.node',
    'platform.py:<module>.release',
    'platform.py:<module>.version',
    'platform.py:<module>.machine',
    'platform.py:<module>.processor',
    'secrets.py:<module>.randbelow',
    'secrets.py:<module>.token_bytes',
    'secrets.py:<module>.token_hex',
    'secrets.py:<module>.token_urlsafe',
    'getpass.py:<module>.getuser',
    'pty.py:<module>.spawn',
    'socket.py:<module>.getfqdn',
    'socket.py:<module>.create_connection',
    'socket.py:<module>.create_server',
    'socket.py:<module>.getaddrinfo',
    'uuid.py:<module>.getnode',
    'uuid.py:<module>.uuid4',
    're.py:<module>.scan',
    're.py:<module>.match',
    're.py:<module>.fullmatch',
    're.py:<module>.search',
    're.py:<module>.sub',
    're.py:<module>.subn',
    're.py:<module>.split',
    're.py:<module>.findall',
    're.py:<module>.finditer',
    're.py:<module>.compile',
    're.py:<module>.purge',
    're.py:<module>.template',
    're.py:<module>.escape',
    '__init__.py:<module>.create_string_buffer',
    '__init__.py:<module>.WinError',
    '__init__.py:<module>.string_at',
    'dummy/__init__.py:<module>.Manager',
    'dummy/__init__.py:<module>.Pool',
    'context.py:<module>.Manager',
    'context.py:<module>.Pool',
    'request.py:<module>.request.urlopen',
    'request.py:<module>.urlretrieve',
    'encoder.py:<module>.py_encode_basestring',
    'encoder.py:<module>.py_encode_basestring_ascii',
    'decoder.py:<module>.py_scanstring',
    'decoder.py:<module>.JSONObject',
    'decoder.py:<module>.JSONArray',
    'tool.py:<module>.main',
    'scanner.py:<module>.py_make_scanner',
    'decoder.py:<module>.decode',
    'decoder.py:<module>.raw_decode',
    '__init__.py:<module>.dump',
    '__init__.py:<module>.dumps',
    '__init__.py:<module>.detect_encoding',
    '__init__.py:<module>.load',
    '__init__.py:<module>.loads',
    'encoder.py:<module>.default',
    'encoder.py:<module>.encode',
    'encoder.py:<module>.iterencode',
    '__init__.py:<module>.append',
    '__init__.py:<module>.insert',
    '__init__.py:<module>.pop',
    '__init__.py:<module>.remove',
    '__init__.py:<module>.clear',
    '__init__.py:<module>.copy',
    '__init__.py:<module>.count',
    '__init__.py:<module>.index',
    '__init__.py:<module>.reverse',
    '__init__.py:<module>.sort',
    '__init__.py:<module>.extend',
    '__init__.py:<module>.total',
    '__init__.py:<module>.most_common',
    '__init__.py:<module>.elements',
    '__init__.py:<module>.fromkeys',
    '__init__.py:<module>.update',
    '__init__.py:<module>.subtract',
    '__init__.py:<module>.capitalize',
    '__init__.py:<module>.casefold',
    '__init__.py:<module>.center',
    '__init__.py:<module>.removeprefix',
    '__init__.py:<module>.removesuffix',
    '__init__.py:<module>.encode',
    '__init__.py:<module>.endswith',
    '__init__.py:<module>.expandtabs',
    '__init__.py:<module>.find',
    '__init__.py:<module>.format',
    '__init__.py:<module>.format_map',
    '__init__.py:<module>.isalpha',
    '__init__.py:<module>.isalnum',
    '__init__.py:<module>.isascii',
    '__init__.py:<module>.isdecimal',
    '__init__.py:<module>.isdigit',
    '__init__.py:<module>.isidentifier',
    '__init__.py:<module>.islower',
    '__init__.py:<module>.isnumeric',
    '__init__.py:<module>.isprintable',
    '__init__.py:<module>.isspace',
    '__init__.py:<module>.istitle',
    '__init__.py:<module>.isupper',
    '__init__.py:<module>.join',
    '__init__.py:<module>.ljust',
    '__init__.py:<module>.lower',
    '__init__.py:<module>.lstrip',
    '__init__.py:<module>.partition',
    '__init__.py:<module>.replace',
    '__init__.py:<module>.rfind',
    '__init__.py:<module>.rindex',
    '__init__.py:<module>.rjust',
    '__init__.py:<module>.rpartition',
    '__init__.py:<module>.rstrip',
    '__init__.py:<module>.split',
    '__init__.py:<module>.rsplit',
    '__init__.py:<module>.splitlines',
    '__init__.py:<module>.startswith',
    '__init__.py:<module>.strip',
    '__init__.py:<module>.swapcase',
    '__init__.py:<module>.title',
    '__init__.py:<module>.translate',
    '__init__.py:<module>.upper',
    '__init__.py:<module>.zfill',
    '__init__.py:<module>.get',
    '__init__.py:<module>.new_child',
    '__init__.py:<module>.parents',
    '__init__.py:<module>.popitem',
    '__init__.py:<module>.namedtuple',
    '__init__.py:<module>.move_to_end',
    '__init__.py:<module>.keys',
    '__init__.py:<module>.items',
    '__init__.py:<module>.values',
    '__init__.py:<module>.setdefault',
    'streams.py:<module>.open_connection',
    'events.py:<module>.get_event_loop',
    '__init__.py:<module>.get_name',
    '__init__.py:<module>.set_name',
    '__init__.py:<module>.createLock',
    '__init__.py:<module>.acquire',
    '__init__.py:<module>.release',
    '__init__.py:<module>.setLevel',
    '__init__.py:<module>.emit',
    '__init__.py:<module>.handle',
    '__init__.py:<module>.setFormatter',
    '__init__.py:<module>.flush',
    '__init__.py:<module>.close',
    '__init__.py:<module>.handleError',
    'handlers.py:<module>.mapLogRecord',
    'handlers.py:<module>.getConnection',
    'handlers.py:<module>.emit',
    'handlers.py:<module>.makeSocket',
    'handlers.py:<module>.createSocket',
    'handlers.py:<module>.send',
    'handlers.py:<module>.makePickle',
    'handlers.py:<module>.handleError',
    'handlers.py:<module>.close',
    'handlers.py:<module>.doRollover',
    'handlers.py:<module>.shouldRollover',
    'handlers.py:<module>.reopenIfNeeded',
    'handlers.py:<module>.dequeue',
    'handlers.py:<module>.start',
    'handlers.py:<module>.prepare',
    'handlers.py:<module>.handle',
    'handlers.py:<module>.enqueue_sentinel',
    'handlers.py:<module>.stop',
    'handlers.py:<module>.getMessageID',
    'handlers.py:<module>.getEventCategory',
    'handlers.py:<module>.getEventType',
    '__init__.py:<module>.getLevelName',
    '__init__.py:<module>.addLevelName',
    '__init__.py:<module>.setLogRecordFactory',
    '__init__.py:<module>.getLogRecordFactory',
    '__init__.py:<module>.makeLogRecord',
    '__init__.py:<module>.setLoggerClass',
    '__init__.py:<module>.getLoggerClass',
    '__init__.py:<module>.basicConfig',
    '__init__.py:<module>.getLogger',
    '__init__.py:<module>.critical',
    '__init__.py:<module>.fatal',
    '__init__.py:<module>.error',
    '__init__.py:<module>.exception',
    '__init__.py:<module>.warning',
    '__init__.py:<module>.warn',
    '__init__.py:<module>.info',
    '__init__.py:<module>.debug',
    '__init__.py:<module>.log',
    '__init__.py:<module>.disable',
    '__init__.py:<module>.shutdown',
    '__init__.py:<module>.captureWarnings',
    '__init__.py:<module>.findCaller',
    '__init__.py:<module>.makeRecord',
    '__init__.py:<module>.addHandler',
    '__init__.py:<module>.removeHandler',
    '__init__.py:<module>.hasHandlers',
    '__init__.py:<module>.callHandlers',
    '__init__.py:<module>.getEffectiveLevel',
    '__init__.py:<module>.isEnabledFor',
    '__init__.py:<module>.getChild',
    '__init__.py:<module>.usesTime',
    '__init__.py:<module>.validate',
    'config.py:<module>.resolve',
    'config.py:<module>.ext_convert',
    'config.py:<module>.cfg_convert',
    'config.py:<module>.convert',
    'config.py:<module>.configure_custom',
    'config.py:<module>.as_tuple',
    '__init__.py:<module>.getMessage',
    'config.py:<module>.get',
    'config.py:<module>.pop',
    '__init__.py:<module>.addFilter',
    '__init__.py:<module>.removeFilter',
    '__init__.py:<module>.filter',
    'handlers.py:<module>.computeRollover',
    'handlers.py:<module>.getFilesToDelete',
    'handlers.py:<module>.shouldFlush',
    'handlers.py:<module>.setTarget',
    'handlers.py:<module>.flush',
    'handlers.py:<module>.encodePriority',
    'handlers.py:<module>.mapPriority',
    'config.py:<module>.convert_with_key',
    'handlers.py:<module>.getSubject',
    'config.py:<module>.fileConfig',
    'config.py:<module>.valid_ident',
    'config.py:<module>.dictConfig',
    'config.py:<module>.listen',
    'config.py:<module>.stopListening',
    '__init__.py:<module>.stream',
    '__init__.py:<module>.formatTime',
    '__init__.py:<module>.formatException',
    '__init__.py:<module>.formatMessage',
    '__init__.py:<module>.formatStack',
    '__init__.py:<module>.formatHeader',
    '__init__.py:<module>.formatFooter',
    'handlers.py:<module>.rotation_filename',
    'handlers.py:<module>.rotate',
    '__init__.py:<module>.process',
    '__init__.py:<module>.manager',
    '__init__.py:<module>.name',
    'handlers.py:<module>.enqueue',
    '__init__.py:<module>.setStream',
    'config.py:<module>.configure',
    'config.py:<module>.configure_formatter',
    'config.py:<module>.configure_filter',
    'config.py:<module>.add_filters',
    'config.py:<module>.configure_handler',
    'config.py:<module>.add_handlers',
    'config.py:<module>.common_logger_config',
    'config.py:<module>.configure_logger',
    'config.py:<module>.configure_root',
]

SENSITIVE_FUNCTIONS_ADDITIONAL = [
            # 网络相关
            "socket.py:<module>.socket","socket.py:<module>.socket.<returnValue>.connect","socket.py:<module>.socket.<returnValue>.recv",
            "socket.py:<module>.socket.<returnValue>.send","socket.py:<module>.gethostname","socket.py:<module>.socket.<returnValue>.bind",
            "socket.py:<module>.socket.<returnValue>.listen","socket.py:<module>.socket.<returnValue>.accept","socket.py:<module>.gethostbyname",
            "ssl.py:<module>.wrap_socket","ssl.py:<module>.create_default_context",
            "multiprocessing.connection:Listener",
            "smtplib.py:<module>.SMTP","smtplib.py:<module>.SMTP_SSL",
            "ftplib.py:<module>.FTP","ftplib.py:<module>.FTP_TLS",
            "http.client.py:<module>.HTTPConnection",
            "requests.py:<module>.get","requests.py:<module>.post", 
            "wget.py:<module>.download",
            "webbrowser.py:<module>.open","urllib.py:<module>.urlopen","websocket.py:<module>.create_connection",
            "urllib/request.py:<module>.urlopen",
            # 加密相关
            "json.py:<module>.dumps.<returnValue>.encode","json.py:<module>.loads",
            "base64.py:<module>.b64decode",
            "cryptography/fernet.py:<module>.Fernet.generate_key",
            "cryptography/fernet.py:<module>.Fernet.encrypt",
            "cryptography/fernet.py:<module>.Fernet.decrypt",
            "secrets.py:<module>.token_hex",
            "pyAesCrypt.py:<module>.encryptFile","pyAesCrypt.py:<module>.decryptFile",
            "win32crypt.py:<module>.CryptUnprotectData",
            "hashlib.py:<module>.sha256","hashlib.py:<module>.md5","hashlib.py:<module>.sha1",
            # 系统信息相关
            "os.py:<module>.getenv","os.py:<module>.environ","os.py:<module>.system","os.py:<module>.getlogin",
            "platform.py:<module>.uname","platform.py:<module>.platform","platform.py:<module>.machine",
            "getpass.py:<module>.getuser",
            # 文件操作相关
            "shutil.py:<module>.copyfile","shutil.py:<module>.move","shutil.py:<module>.rmtree",
            "os.py:<module>.makedirs","os.py:<module>.walk","os.py:<module>.chdir","os.py:<module>.remove","os.py:<module>.rename","os.py:<module>.getcwd","os.py:<module>.listdir","os.py:<module>.stat",
            "__builtin.open","__builtin.input",
            "importlib.py:<module>.<member>(machinery).SourceFileLoader.__init__","importlib.py:<module>.<member>(machinery).SourceFileLoader.get_data",
            "glob.py:<module>.glob",
            # 进程相关
            "subprocess.py:<module>.call","os.py:<module>.getuid","subprocess.py:<module>.Popen.__init__","subprocess.py:<module>.getoutput","subprocess.py:<module>.run","subprocess.py:<module>.check_output",
            "threading.py:<module>.Thread","threading.py:<module>.Thread.__init__","threading.py:<module>.Thread.start",
            "pynput.py:<module>.keyboard.Listener",
            "__builtin.exec","__builtin.eval",
            "os.py:<module>.popen",
            # keylogger相关
            "keyboard.py:<module>.on_release","keyboard.py:<module>.on_press","keyboard.py:<module>.block_key",
            # 数据库相关
            "sqlite3.py:<module>.connect",
            # 注册表相关
            "winreg.py:<module>.OpenKey","winreg.py:<module>.CreateKey",
            # 其他敏感函数
        ]

# 定义匹配规则：只有当逻辑属性完全一致时，才认为两个节点可能相同
def cpg_node_match(n1, n2):
    # 1. 首先检查节点类型 (最快排除)
    if n1.get('label') != n2.get('label'):
        return False
    
    # 2. 检查具体的函数名或操作符名
    if n1.get('file_path') != n2.get('file_path'):
        return False

    # 3. 检查NAME
    if n1.get('NAME', '') != n2.get('NAME', ''):
        return False        
    
    # 4.检查CODE
    if n1.get('CODE', '') != n2.get('CODE', ''):
        return False
    
    # 注意：LINE_NUMBER 被忽略，不作为匹配条件
    
    return True

# 定义边匹配规则 (如果你的边也有属性，比如流类型 FLOWS_TO, AST 等)
def cpg_edge_match(e1, e2):
    # 假设边有一个 'label' 属性，比如 'AST' 或 'CFG'
    return e1.get('label') == e2.get('label')


def is_isomorphic_fast(graph_a, graph_b):
    # 使用匹配器
    
    gm = nx.algorithms.isomorphism.MultiDiGraphMatcher(
        graph_a, 
        graph_b, 
        node_match=cpg_node_match,
        edge_match=cpg_edge_match # 如果边有类型，建议也加上
    )
    return gm.is_isomorphic()


class GraphHelper:
    def __init__(self, graph: nx.MultiDiGraph):
        self.graph = graph
        
    def get_nodes_by_line(self, line_number):
        nodes = []
        for node, data in self.graph.nodes(data=True):
            if 'LINE_NUMBER' in data and data['LINE_NUMBER'] == line_number:
                nodes.append((node, data))
        return nodes
    
    def get_builtin_function_call_nodes(self):
        nodes = []
        for node, data in self.graph.nodes(data=True):
            if "__builtin" in data.get("METHOD_FULL_NAME", "") or "read" in data.get("CODE", ""):
                nodes.append((node, data))
        return nodes
    
    def get_same_position_nodes(self, node_):
        nodes = []
        for node, data in self.graph.nodes(data=True):
            if data.get("COLUMN_NUMBER",-1) == self.graph.nodes[node_]["COLUMN_NUMBER"] and data.get("LINE_NUMBER",-1) == self.graph.nodes[node_]["LINE_NUMBER"]:
                nodes.append(node)
        return nodes
    
    
    
    def is_sensitive_builtin(function_name):
        
        
        # sensitive_functions_judge_code = [
        #     "os.environ","subprocess.call",
        # ]
        # sensitive_functions = [
        #     "socket.py:<module>.socket","copyfile","encrypt","Popen","create_default_context","wrap_socket","Thread","start","Listener","SMTP","FTP","HTTPConnection","starttls","sendmail",
        #     "call","check_output","getuid","IsUserAnAdmin","makedirs",
        #     "environ","walk",
        #     "input", "getpass", "open", "read", "recv", "recvfrom",
        #     "urlopen", "requests.get", "requests.post", "pandas.read_csv",
        #     "json.load", "yaml.load","write","remove","rename","connect","execute","CryptUnprotectData","getenv","mkdir","generate_key"
        # ]
        return function_name in SENSITIVE_FUNCTIONS_ADDITIONAL or function_name in SENSITIVE_SYSCALL_STRINGS
        

if __name__ == "__main__":
    cpg_path = "/home/lxy/lxy_codes/mal_update_detect/joern_workspace/commit_test_repo/e11ae/cpg/export.dot"
    graph = nx.nx_agraph.read_dot(cpg_path)
    node_a = "30064771086"
    node_b = "30064771083"

    path = nx.shortest_path(graph, node_a, node_b)
    # build a graph that contains only nodes on the path and the edges between consecutive path nodes
    new_graph = nx.MultiDiGraph()
    for n in path:
        if n in graph:
            new_graph.add_node(n, **graph.nodes[n])
            new_graph.nodes[n]['label']=n

    for u, v in zip(path, path[1:]):
        if graph.has_edge(u, v):
            for key, attrs in graph[u][v].items():
                new_graph.add_edge(u, v, **attrs)
        elif graph.has_edge(v, u):
            for key, attrs in graph[v][u].items():
                new_graph.add_edge(v, u, **attrs)

    graph = new_graph
    
    out_path = cpg_path.replace(".dot", "_path.dot")
    nx.nx_agraph.write_dot(graph, out_path)
    print("Wrote highlighted graph to:", out_path)
    print(path)

       
    
