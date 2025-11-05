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
        sensitive_functions = [
            "input", "getpass", "open", "read", "recv", "recvfrom",
            "urlopen", "requests.get", "requests.post", "pandas.read_csv",
            "json.load", "yaml.load","write","remove","rename","connect","execute","CryptUnprotectData","getuser","getenv","mkdir"
        ]
        return function_name in sensitive_functions
        

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

       
    
