import networkx as nx

def cpg_node_match(n1, n2):
    if n1.get('label') != n2.get('label'):
        return False
    if n1.get('file_path') != n2.get('file_path'):
        return False
    if n1.get('NAME', '') != n2.get('NAME', ''):
        return False
    if n1.get('CODE', '') != n2.get('CODE', ''):
        return False
    return True


def cpg_edge_match(e1, e2):
    return e1.get('label') == e2.get('label')


def is_isomorphic_fast(graph_a, graph_b):
    gm = nx.algorithms.isomorphism.MultiDiGraphMatcher(
        graph_a, graph_b,
        node_match=cpg_node_match,
        edge_match=cpg_edge_match
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
            if data.get("COLUMN_NUMBER", -1) == self.graph.nodes[node_]["COLUMN_NUMBER"] and \
               data.get("LINE_NUMBER", -1) == self.graph.nodes[node_]["LINE_NUMBER"]:
                nodes.append(node)
        return nodes

    @staticmethod
    def is_sensitive_builtin(function_name):
        # Import here to avoid circular dependency
        from .patterns import SENSITIVE_FUNCTIONS_ADDITIONAL, SENSITIVE_SYSCALL_STRINGS
        return function_name in SENSITIVE_FUNCTIONS_ADDITIONAL or function_name in SENSITIVE_SYSCALL_STRINGS
