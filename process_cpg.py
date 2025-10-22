from __future__ import annotations
from tree_sitter import Node
from common_classes.cpg_node import CPGNode
from common_classes.cpg_pdg_edge import Edge
import os
import networkx as nx
from ast_parser import ASTParser
from custom_exception import DotReadingException


class CPG:
    def __init__(self, cpg_dir: str):
        self.cpg_dir = cpg_dir
        self.nodes: dict[int, CPGNode] = {}
        self.edges: dict[tuple[int, int], Edge] = {}
        self.out_edges: dict[int, set[int]] = {}
        self.in_edges: dict[int, set[int]] = {}
        self.max_node_id = 0

        cpg_path = os.path.join(cpg_dir, 'export.dot')
        if not os.path.exists(cpg_path):
            raise FileNotFoundError(f"export.dot is not found in {cpg_path}")

        try:
            cpg: nx.MultiDiGraph = nx.nx_agraph.read_dot(cpg_path)
        except Exception:
            raise DotReadingException("Dot Reading Exception")
        for node in cpg.nodes:

            # 读取CPG中的node信息
            node_id = int(node)
            cpg_node = CPGNode(node_id)
            for key, value in cpg.nodes[node].items():
                cpg_node.set_attr(key, value)
            self.nodes[node_id] = cpg_node
            self.max_node_id = node_id

        # 读取cpg中所有边
        for head, tail, key, edge_dict in cpg.edges(data=True, keys=True):
            src = int(head)
            dst = int(tail)
            if (src, dst) not in self.edges:
                cpg_edge = Edge((src, dst))
            else:
                cpg_edge = self.edges[(src, dst)]

            # 添加到出边中
            if src not in self.out_edges:
                self.out_edges[src] = set()
                self.out_edges[src].add(dst)
            else:
                self.out_edges[src].add(dst)

            # 添加到入边中
            if dst not in self.in_edges:
                self.in_edges[dst] = set()
                self.in_edges[dst].add(src)
            else:
                self.in_edges[dst].add(src)

            for _key, _value in edge_dict.items():
                cpg_edge.set_attr(_value)
            self.edges[(src, dst)] = cpg_edge

    def get_node(self, node_id: int) -> CPGNode:
        return self.nodes[node_id]

    def get_child_ast(self, node_id: int) -> list[CPGNode]:
        """
        获取ast子节点
        """
        nodes_id = self.out_edges[node_id]
        ast = []
        for tail_id in nodes_id:
            edge = self.edges[(node_id, tail_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == 'AST':
                    ast.append(self.nodes[tail_id])

        # ascend
        return sorted(ast, key=lambda x: int(x.get_value('ORDER')))

    def get_argument(self, node_id: int, code_lines) -> list[str]:
        """
        argument 提取
        """
        cpg_node = self.nodes[node_id]
        line_number = int(cpg_node.get_value('LINE_NUMBER'))
        column_number = int(cpg_node.get_value('COLUMN_NUMBER'))
        extracted_code = []
        extracted_code.append(code_lines[line_number - 1][column_number - 1:])
        extracted_code.extend(code_lines[line_number:])
        extracted_code = ''.join(extracted_code)
        param_list = []
        parser = ASTParser(extracted_code, 'go')
        query = f"""
                (
                    call_expression
                    arguments: (argument_list)@argument_list
                )
        """
        argument_list = parser.query_oneshot(query)
        if argument_list:
            for argument in argument_list.named_children:
                argument_value = self.query_each_node(argument)
                if argument_value:
                    param_list += argument_value
            return param_list
        else:
            return []

    def query_each_node(self, node: Node):
        if node.type == 'call_expression':
            return None
        elif node.type == 'identifier':
            return [node.text.decode()]
        elif node.type == 'selector_expression':
            operand_node = node.child_by_field_name('operand')
            return self.query_each_node(operand_node)
        elif node.type == 'index_expression':
            value_node = node.child_by_field_name('operand')
            return self.query_each_node(value_node)
        else:
            named_children = node.named_children
            if len(named_children) == 0:
                return None
            else:
                param_list = []
                for named_child in named_children:
                    value = self.query_each_node(named_child)
                    if value:
                        param_list = param_list + value
                return param_list

    def get_argument_from_joern(self, node_id: int) -> list[CPGNode]:
        """
        查找cpg中边的类型为argument的
        """
        nodes_id = self.out_edges[node_id]
        ast = []
        for tail_id in nodes_id:
            edge = self.edges[(node_id, tail_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == 'ARGUMENT':
                    ast.append(self.nodes[tail_id])
        ast = sorted(ast, key=lambda x: int(x.get_value('ARGUMENT_INDEX')))
        return ast

    def get_call(self, node_id: int) -> CPGNode | None:
        """
        查找cpg中边的类型为call的
        """
        nodes_id = self.out_edges[node_id]
        call_node = None
        for tail_id in nodes_id:
            edge = self.edges[(node_id, tail_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == 'CALL':
                    call_node = self.nodes[tail_id]
        return call_node

    def get_caller(self, node_id: int) -> list[CPGNode]:
        """
        根据call查找caller节点
        """
        nodes_id = self.in_edges[node_id]
        caller_node_list = []
        for head_id in nodes_id:
            edge = self.edges[(head_id, node_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == 'CALL':
                    caller_node_list.append(self.nodes[head_id])
        return caller_node_list

    def get_max_node_id(self):
        """
        获取最大的id号，用于创建新的节点
        """
        self.max_node_id += 1
        return self.max_node_id
