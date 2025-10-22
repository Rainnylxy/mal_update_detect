import json
from scalpel.call_graph.pycg import CallGraphGenerator, formats
cg_generator = CallGraphGenerator(["./commit_test_repo/file2.py"], "virus1")
cg_generator.analyze()
cg = cg_generator.output()
formatter = formats.Simple(cg_generator)
print(formatter.generate())
store_output = True
if store_output:
    with open("example_results.json", "w+") as f:
        f.write(json.dumps(formatter.generate()))