
import os
from Util.git_util import Git_Util
from typing import List, Tuple

from Util.mark_pdgs import mark_pdg_nodes
from Util.merge_marked_pdgs import Marked_Merger
from Util.pygraph_util import read_graph_from_dot, obj_dict_to_networkx
import networkx as nx

class deltaPDG(object):
    def __init__(self, base_pdg_location: str, m_fuzziness: int, n_fuzziness: int):
        self.before_pdg = nx.nx_agraph.read_dot(base_pdg_location)
        self.merger = Marked_Merger(m_fuzziness=m_fuzziness, n_fuzziness=n_fuzziness)

    def __call__(self, target_pdg_location: str, diff: List[Tuple[str, str, int, int, str]]):
        after_pdg = nx.nx_agraph.read_dot(target_pdg_location)
        marked_before = mark_pdg_nodes(self.before_pdg, '-', diff)
        marked_after = mark_pdg_nodes(after_pdg, '+', diff)
        nx.nx_agraph.write_dot(marked_before, 'marked_before.dot')
        nx.nx_agraph.write_dot(marked_after, 'marked_after.dot')
        self.deltaPDG = self.merger(before_apdg=marked_before, after_apdg=marked_after)
        return self.deltaPDG

def mark_originating_commit(dpdg, marked_diff, filename):
    dpdg = dpdg.copy()

    for node, data in dpdg.nodes(data=True):
        if 'color' in data.keys() and data['color'] != 'orange':
            start, end = [int(l) for l in data['span'].split('-')] if '-' in data['span'] else [-1, -1]

            if start == end == -1:
                continue

            change_type = '+' if data['color'] == 'green' else '-'
            masked_diff = [p for p in marked_diff if p[0] == change_type and p[1] == filename]

            label = data['label'].replace('\'\'', '"')
            if 'Entry' in label:
                label = label[len('Entry '):].split('(')[0].split('.')[-1]
            elif 'Exit' in label:
                label = label[len('Exit '):].split('(')[0].split('.')[-1]
            if 'lambda' in label:
                label = '=>'
            if '\\r' in label:
                label = label.split('\\r')[0]
            elif '\\n' in label:
                label = label.split('\\n')[0]

            community = max([cm
                             for _, _, after_coord, before_coord, line, cm in masked_diff
                             if label in line and (start <= after_coord <= end or start <= before_coord <= end)],
                            default=0)

            dpdg.node[node]['community'] = community

    return dpdg


def mark_origin(tangled_diff, atomic_diffs):
    output = list()
    for change_type, file, after_coord, before_coord, line in tangled_diff:
        if change_type != ' ':
            relevant = {i: [(ct, f, ac, bc, ln) for ct, f, ac, bc, ln in diff
                            if file == f and line.strip() == ln.strip()]
                        for i, diff in atomic_diffs.items()}
            relevant = [i for i, diff in relevant.items() if len(diff) > 0]
            label = max(relevant, default=0)
            output.append((change_type, file, after_coord, before_coord, line, label))
    return output

def worker(repo_path, from_, to_, joern_workspace_path):
    repository_name = os.path.basename(repo_path)
    method_fuzziness = 100
    node_fuzziness = 100

    git_handler = Git_Util(repo_path=repo_path)

    changes = git_handler.process_diff_between_commits(from_, to_, repo_path)
    
    files_touched = {filename for _, filename, _, _, _ in changes if
                        os.path.basename(filename).split('.')[-1] == 'py'}

    for filename in files_touched:
        delta_gen = deltaPDG(os.path.join(joern_workspace_path,repository_name,"2b4b6/pdg/0-pdg.dot"), m_fuzziness=method_fuzziness,
                                n_fuzziness=node_fuzziness)
        delta_pdg = delta_gen(os.path.join(joern_workspace_path,repository_name,"e11ae/pdg/0-pdg.dot"),
                                [ch for ch in changes if ch[1] == filename])
        # delta_pdg = mark_originating_commit(delta_pdg, mark_origin(changes, changes), filename)

        output_path = os.path.join(joern_workspace_path, repository_name, 'delta_pdg', filename.replace('/', '_') + '_delta_pdg.dot')
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        nx.drawing.nx_pydot.write_dot(delta_pdg, output_path)
  
worker("/home/lxy/lxy_codes/mal_update_detect/commit_test_repo", "2b4b6", "e11ae", "/home/lxy/lxy_codes/mal_update_detect/joern_workspace")      




