from __future__ import annotations
from typing import Generator
from tree_sitter import Language, Parser, Node
import tree_sitter_python as python_script
import tree_sitter_javascript as javascript_script
import re


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
