import tree_sitter_python as tspython
from tree_sitter import Language, Parser


def find_enclosing_function(file_path, code_line):
    # Initialize the parser
    PY_LANGUAGE = Language(tspython.language())
    parser = Parser(PY_LANGUAGE)

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
    return None, None

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