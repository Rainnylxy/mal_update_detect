import os
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

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
        return None, None, False

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
        "expression_statement",
        "call",
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
        return code_line, code_line, False

    # Choose the smallest enclosing block (innermost)
    candidates.sort(key=lambda n: (n.end_point[0] - n.start_point[0], n.start_point[0]))
    node = candidates[0]
    start_line = node.start_point[0] + 1
    if node.type in ["try_statement",
                     "else_clause","expression_statement","if_statement",
                    "except_clause",
                    "finally_clause"]:
        return start_line, node.end_point[0] + 1,False
    
    if node.type in ["with_statement","call","assignment"]:
        return start_line, node.end_point[0] + 1,True
    
    return start_line, start_line,False
    



def find_enclosing_function(file_path, code_line):
    # Initialize the parser
    PY_LANGUAGE = Language(tspython.language())
    parser = Parser(PY_LANGUAGE)
    
    if os.path.exists(file_path) is False:
        return None, None
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()

    tree = parser.parse(bytes(source_code, "utf8"))
    root_node = tree.root_node

    def get_function_nodes(node):
        funcs = []
        for child in node.children:
            if child.type == 'function_definition':
                funcs.append(child)
            funcs.extend(get_function_nodes(child))
        return funcs

    function_nodes = get_function_nodes(root_node)
    for func in function_nodes:
        start_line = func.start_point[0] + 1
        end_line = func.end_point[0] + 1
        if start_line <= code_line <= end_line:
            # Get function name
            for child in func.children:
                if child.type == 'identifier':
                    return child.text.decode('utf-8'),source_code[func.start_byte:func.end_byte]
    return "&lt;module&gt;", None

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


if __name__ == "__main__":
    file_path = 'commit_test_repo/file2.py'
    code_line = 8  # Example line number
    func_name = find_enclosing_function(file_path, code_line)
    if func_name:
        print(f"The line {code_line} is inside the function: {func_name}")
    else:
        print(f"The line {code_line} is not inside any function.")