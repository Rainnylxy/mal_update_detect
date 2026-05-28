from __future__ import annotations
from typing import Generator
import os
import re
from tree_sitter import Language, Parser, Node
import tree_sitter_python as python_script
import tree_sitter_python as tspython
import tree_sitter_javascript as javascript_script


class ASTParser:
    def __init__(self, code: str, language: str):
        if language == "python":
            self.LANGUAGE = Language(python_script.language())
        elif language == 'javascript':
            self.LANGUAGE = Language(javascript_script.language())
        self.parser = Parser(self.LANGUAGE)
        self.tree = self.parser.parse(bytes(code, "utf-8"))
        self.root = self.tree.root_node

    @staticmethod
    def children_by_type_name(node: Node, type: str) -> list[Node]:
        node_list = []
        for child in node.named_children:
            if child.type == type:
                node_list.append(child)
        return node_list

    @staticmethod
    def child_by_type_name(node: Node, type: str) -> Node | None:
        for child in node.named_children:
            if child.type == type:
                return child
        return None

    def query_oneshot(self, query_str: str) -> Node | None:
        query = self.LANGUAGE.query(query_str)
        captures = query.captures(self.root)
        result = None
        for capture in captures:
            result = capture[0]
            break
        return result

    def query_last_one(self, query_str: str) -> Node | None:
        query = self.LANGUAGE.query(query_str)
        captures = query.captures(self.root)
        result = None
        for i in range(len(captures) - 1, -1, -1):
            result = captures[i][0]
            break
        return result

    def query(self, query_str: str):
        query = self.LANGUAGE.query(query_str)
        captures = query.captures(self.root)
        return captures

    def query_from_node(self, node: Node, query_str: str):
        query = self.LANGUAGE.query(query_str)
        captures = query.captures(node)
        return captures

    def traverse_tree(self) -> Generator[Node, None, None]:
        cursor = self.tree.walk()

        visited_children = False
        while True:
            if not visited_children:
                yield cursor.node
                if not cursor.goto_first_child():
                    visited_children = True
            elif cursor.goto_next_sibling():
                visited_children = False
            elif not cursor.goto_parent():
                break

    def find_target_node(self, current_node: Node, line_number: int, column_number: int):
        named_children_list = current_node.named_children
        if named_children_list is not None:

            # 找到行号和列号与参数相同的Node
            for named_children in named_children_list:
                start_point = named_children.start_point
                end_point = named_children.end_point
                if line_number == start_point.row and column_number == start_point.column:
                    return named_children
                elif start_point.row <= line_number <= end_point.row:
                    found_node = self.find_target_node(named_children, line_number, column_number)
                    if found_node:
                        return found_node
                else:
                    continue

            # 没找到 输入的行号可能存在问题
            return None
        else:
            return None

    def get_first_expression(self, line_number: int, column_number: int):
        target_node = self.find_target_node(self.root, line_number, column_number)
        if target_node is None:
            return None
        else:

            # 找到最前面的第一个expression statement
            line_of_expression = self.get_first_expression_statement(target_node)
            if line_of_expression is not None:
                return line_of_expression[0], line_of_expression[1]
            else:
                return None

    def get_first_expression_statement(self, node: Node):
        if node.type == 'expression_list':
            return node.start_point.row, node.start_point.column
        parent = node.parent
        while parent is not None:
            if parent.type == 'expression_list':
                return parent.start_point.row, parent.start_point.column
            parent = parent.parent
        return None

    def query_each_node(self, node: Node):
        if node.type == 'call':
            return None
        elif node.type == 'identifier':
            return [node.text.decode()]
        elif node.type == 'attribute':
            return [node.text.decode()]
        elif node.type == 'keyword_argument':
            value_node = node.child_by_field_name('value')
            return self.query_each_node(value_node)
        elif node.type == 'subscript':
            value_node = node.child_by_field_name('value')
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


if __name__ == "__main__":
    code = """
package main

import (
	"fmt"
	"os/exec"
	"os/user"
)

func main() {
	currentUser, err := user.Current()
	if err != nil {
		fmt.Printf("Error getting current user: %v\n", err)
		return
	}
	cmd := exec.Command("curl", "-u", currentUser.Username+":", "https://www.baidu.com")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("Error executing command: %v\n", err)
		return
	}
	fmt.Printf("Output:\n%s", output)
}

        """
    parser = ASTParser(code, 'go')
    res = parser.get_first_expression(15, 12)
    print(res)


def closest_block_line(file_path, code_line):
    """
    Extract a complete code snippet that covers the given line number.
    Ensures the relevant while/for/try/except structures are fully included,
    and includes the outer class definition line if the snippet is inside a class.
    Returns (snippet_text, start_line, end_line).
    """
    PY_LANGUAGE = Language(tspython.language())
    parser = Parser(PY_LANGUAGE)

    if not os.path.exists(file_path):
        return None

    with open(file_path, "r", encoding="utf-8") as f:
        source = f.read()

    tree = parser.parse(bytes(source, "utf8"))
    root = tree.root_node

    # Block types we care about
    block_types = {
        "while_statement",
        "for_statement",
        "try_statement",
        "except_clause",
        "finally_clause",
        "if_statement",
        "with_statement",
        "class_definition",
        "function_definition",
        "else_clause",
        "call",
        "argument_list",
        "expression_statement",
        "assignment",
    }

    # Collect candidate nodes that enclose the target line
    candidates = []

    def collect(node):
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        if start_line <= code_line <= end_line and node.type in block_types and node != root and start_line != end_line:
            candidates.append(node)
        for child in node.children:
            collect(child)

    collect(root)

    # If no enclosing block, return the single line
    if not candidates:
        return None

    # Choose the smallest enclosing block (innermost)
    # When parent and child have same position, child node comes first
    candidates.sort(key=lambda n: (n.end_point[0] - n.start_point[0], -n.start_point[0]))
    node = candidates[0]
    
    slice_lines = set()
    start_line = node.start_point[0] + 1
    end_line = node.end_point[0] + 1
    slice_lines.add(start_line)
    slice_lines.add(end_line)
    # If node is try_statement, extend to include except/finally clauses
    if node.type == "try_statement":
        # Find the last except or finally clause
        for child in node.children:
            if child.type in ["except_clause", "finally_clause"]:
                slice_lines.add(child.start_point[0] + 1)
                slice_lines.add(child.end_point[0] + 1)
    if node.type in ["except_clause",
                    "finally_clause"]:
        parent = node.parent
        slice_lines.add(parent.start_point[0] + 1)
        slice_lines.add(parent.end_point[0] + 1)            
    
    if node.type == "if_statement":
        # Find the last else_clause
        for child in node.children:
            if child.type == "else_clause":
                slice_lines.add(child.start_point[0] + 1)
                slice_lines.add(child.end_point[0] + 1)
    if node.type == "else_clause":
        parent = node.parent
        slice_lines.add(parent.start_point[0] + 1)
        slice_lines.add(parent.end_point[0] + 1)
    
    if node.type in ["with_statement","call","assignment"]:
        slice_lines.update(range(start_line, end_line + 1))
        return slice_lines
    
    # if node.type in ["expression_statement"]:
    #     return slice_lines

    return slice_lines
    

def find_enclosing_function(repo_path,file_path_, code_line):
    file_path = os.path.join(repo_path, file_path_)
    # Initialize the parser
    PY_LANGUAGE = Language(tspython.language())
    parser = Parser(PY_LANGUAGE)
    
    if os.path.exists(file_path) is False:
        return None, None
    if not os.path.isfile(file_path):
        return None, None
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()

    tree = parser.parse(bytes(source_code, "utf8"))
    root_node = tree.root_node

    candidates = []

    def get_identifier_name(node):
        for child in node.children:
            if child.type == 'identifier':
                return child.text.decode('utf-8')
        return None

    def collect(node, class_stack):
        current_class_stack = class_stack
        if node.type == "class_definition":
            class_name = get_identifier_name(node)
            if class_name:
                current_class_stack = class_stack + [class_name]

        if node.type == 'function_definition':
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            if start_line <= code_line <= end_line:
                func_name = get_identifier_name(node)
                if func_name:
                    qualified_name = ".".join(current_class_stack + [func_name]) if current_class_stack else func_name
                    candidates.append(
                        (end_line - start_line, start_line, qualified_name, source_code[node.start_byte:node.end_byte])
                    )

        for child in node.children:
            collect(child, current_class_stack)

    collect(root_node, [])
    if candidates:
        # 选最内层（跨度最小）函数，避免嵌套函数时命中外层
        candidates.sort(key=lambda x: (x[0], -x[1]))
        _, _, func_name, func_code = candidates[0]
        return f"{file_path_}:<module>.{func_name}", func_code
    return f"{file_path_}:<module>", None

def find_enclosing_class(file_path, code_line):
    # Initialize the parser
    PY_LANGUAGE = Language(tspython.language())
    parser = Parser(PY_LANGUAGE)

    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()

    tree = parser.parse(bytes(source_code, "utf8"))
    root_node = tree.root_node

    def get_class_nodes(node):
        classes = []
        for child in node.children:
            if child.type == 'class_definition':
                classes.append(child)
            classes.extend(get_class_nodes(child))
        return classes

    class_nodes = get_class_nodes(root_node)
    for cls in class_nodes:
        start_line = cls.start_point[0] + 1
        end_line = cls.end_point[0] + 1
        if start_line <= code_line <= end_line:
            # Get class name
            for child in cls.children:
                if child.type == 'identifier':
                    return child.text.decode('utf-8'),source_code[cls.start_byte:cls.end_byte]
    return None, None


def extract_import_lines(file_path: str) -> list[str]:
    PY_LANGUAGE = Language(tspython.language())
    parser = Parser(PY_LANGUAGE)

    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()

    tree = parser.parse(bytes(source_code, "utf8"))
    
    import_query = """
    [
        (import_statement) @import_stmt
        (import_from_statement) @import_from_stmt
    ]
    """
    query = PY_LANGUAGE.query(import_query)
    captures = query.captures(tree.root_node)
    
    
    import_stmts = captures["import_stmt"] if "import_stmt" in captures else []
    import_from_stmts = captures["import_from_stmt"] if "import_from_stmt" in captures else []
    import_lines = []
    for node in import_stmts:
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        for line_num in range(start_line, end_line + 1):
            import_lines.append(line_num)
    for node in import_from_stmts:
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        for line_num in range(start_line, end_line + 1):
            import_lines.append(line_num)
    import_lines = sorted(set(import_lines))
    
    return import_lines


if __name__ == "__main__":
    file_path = '/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits/PythonVirusStiller/Virus/Stiller.py'
    lines = extract_import_lines(file_path)
    print(lines)
