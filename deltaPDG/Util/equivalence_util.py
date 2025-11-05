from rapidfuzz import fuzz


class Eq_Utils(object):
    def __init__(self, m_fuzziness, n_fuzziness):
        self.m_fuzziness = m_fuzziness
        self.n_fuzziness = n_fuzziness

    def context_eq(self, context_a: str, context_b: str) -> bool:
        return fuzz.ratio(context_a, context_b, score_cutoff=self.m_fuzziness) > 0

    def node_label_eq(self, node_label_a: str, node_label_b: str) -> bool:
        return fuzz.ratio(node_label_a, node_label_b, score_cutoff=self.n_fuzziness) > 0

    def _get_label(self, graph, node) -> str:
        try:
            val = graph.nodes[node].get('label', '')
            # ensure string
            return '' if val is None else str(val)
        except Exception:
            return str(node)

    def node_eq(self, graph_a, node_a, graph_b, node_b):
        label_a = self._get_label(graph_a, node_a)
        label_b = self._get_label(graph_b, node_b)

        if not self.node_label_eq(label_a, label_b):
            return False

        n_a = [n for n in list(graph_a.successors(node_a)) + list(graph_a.predecessors(node_a)) if
               'color' not in graph_a.nodes[n].keys() or graph_a.nodes[n]['color'] == 'orange']

        n_b = [n for n in list(graph_b.successors(node_b)) + list(graph_b.predecessors(node_b)) if
               'color' not in graph_b.nodes[n].keys() or graph_b.nodes[n]['color'] == 'orange']

        # We check for set inclusion, make sure we have the smaller set in the outer loop!
        if len(n_a) > len(n_b):
            temp = n_b
            n_b = n_a
            n_a = temp

        for node in n_a:
            found = False
            for other_node in n_b:
                try:
                    label_node = self._get_label(graph_a, node)
                    label_other = self._get_label(graph_b, other_node)
                    if self.node_label_eq(label_node, label_other):
                        found = True
                        break
                except Exception:
                    pass
            if not found:
                return False

        return True

    def attr_eq(self, attr_a, attr_b):
        for key in attr_a.keys():
            if key not in attr_b.keys():
                return False
            elif key == 'label' and not (self.node_label_eq(str(attr_a[key]), str(attr_b[key]))):
                return False
            elif attr_a[key] != attr_b[key]:
                return False
        return True
