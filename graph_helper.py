import networkx as nx
import sys
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
        sensitive_functions_v = [
            # 网络相关
            "socket.py:<module>.socket","socket.py:<module>.socket.<returnValue>.connect","socket.py:<module>.socket.<returnValue>.recv",
            "socket.py:<module>.socket.<returnValue>.send",
            "ssl.py:<module>.wrap_socket","ssl.py:<module>.create_default_context",
            "multiprocessing.connection:Listener",
            "smtplib.py:<module>.SMTP","smtplib.py:<module>.SMTP_SSL",
            "ftplib.py:<module>.FTP","ftplib.py:<module>.FTP_TLS",
            "http.client.py:<module>.HTTPConnection",
            "requests.py:<module>.get","requests.py:<module>.post", 
            "wget.py:<module>.download",
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
            "os.py:<module>.getenv","os.py:<module>.environ","os.py:<module>.system",
            # 文件操作相关
            "shutil.py:<module>.copyfile","shutil.py:<module>.move",
            "os.py:<module>.makedirs","os.py:<module>.walk","os.py:<module>.chdir","os.py:<module>.remove","os.py:<module>.rename","os.py:<module>.getcwd",
            "__builtin.open","__builtin.input",
            "importlib.py:<module>.<member>(machinery).SourceFileLoader.__init__","importlib.py:<module>.<member>(machinery).SourceFileLoader.get_data",
            
            # 进程相关
            "subprocess.py:<module>.call","os.py:<module>.getuid","subprocess.py:<module>.Popen","subprocess.py:<module>.getoutput","subprocess.py:<module>.run","subprocess.py:<module>.check_output",
            "threading.py:<module>.Thread","threading.py:<module>.Thread.__init__","threading.py:<module>.Thread.start",
            "pynput.py:<module>.keyboard.Listener",
            "__builtin.exec","__builtin.eval",
            # keylogger相关
            "keyboard.py:<module>.on_release","keyboard.py:<module>.on_press","keyboard.py:<module>.block_key"
        ]
        
        sensitive_functions_judge_code = [
            "os.environ","subprocess.call",
        ]
        # sensitive_functions = [
        #     "socket.py:<module>.socket","copyfile","encrypt","Popen","create_default_context","wrap_socket","Thread","start","Listener","SMTP","FTP","HTTPConnection","starttls","sendmail",
        #     "call","check_output","getuid","IsUserAnAdmin","makedirs",
        #     "environ","walk",
        #     "input", "getpass", "open", "read", "recv", "recvfrom",
        #     "urlopen", "requests.get", "requests.post", "pandas.read_csv",
        #     "json.load", "yaml.load","write","remove","rename","connect","execute","CryptUnprotectData","getenv","mkdir","generate_key"
        # ]
        return function_name in sensitive_functions_v
        

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

       
    
