from collections import Counter

import networkx as nx

from graph import load, build_graph
from escalation import add_escalations, GOAL


def main():
    account = load()
    g = add_escalations(build_graph(account), account)

    def name(node):
        return g.nodes[node]["name"]

    people = [
        n for n, d in g.nodes(data=True)
        if d["kind"] != "goal" and not d["admin"]
    ]

    print("ATTACK PATHS")
    all_paths = {}
    for node in people:
        found = list(nx.all_simple_paths(g, node, GOAL))
        all_paths[node] = found
        if not found:
            print(f"  {name(node)}: no path to admin")
            continue
        for path in found:
            print("  " + " -> ".join(name(n) for n in path))

    print()
    print("BLAST RADIUS (what each identity can reach)")
    ranked = sorted(people, key=lambda n: -len(nx.descendants(g, n)))
    for node in ranked:
        reach = len(nx.descendants(g, node))
        routes = len(all_paths[node])
        print(f"  {name(node):18} reaches {reach}   routes to admin: {routes}")

    print()
    print("FIX FIRST (edges that sit on the most paths)")
    counts = Counter()
    for found in all_paths.values():
        for path in found:
            for a, b in zip(path, path[1:]):
                if not g.nodes[a]["admin"]:
                    counts[(a, b)] += 1
    for (a, b), n in counts.most_common():
        how = g[a][b]["how"]
        print(f"  {n} path(s): {name(a)} -> {name(b)}   ({how})")


main()