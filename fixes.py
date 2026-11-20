import copy

import networkx as nx

from graph import load, build_graph, arn
from escalation import add_escalations, GOAL


def attack_paths(account):
    g = add_escalations(build_graph(account), account)
    paths = []
    for node, data in g.nodes(data=True):
        if data["kind"] == "goal" or data["admin"]:
            continue
        for path in nx.all_simple_paths(g, node, GOAL):
            paths.append([g.nodes[n]["name"] for n in path])
    return paths


def find(items, name):
    return next(i for i in items if i["name"] == name)


def remove_action(identity, action):
    for stmt in identity["policies"]:
        stmt["actions"] = [a for a in stmt["actions"] if a != action]
    identity["policies"] = [s for s in identity["policies"] if s["actions"]]


def apply_fixes(account):
    fixed = copy.deepcopy(account)

    remove_action(find(fixed["roles"], "dev-role"), "iam:AttachUserPolicy")

    alice = find(fixed["users"], "alice")
    basic = arn("role", "lambda-basic-role")
    rewritten = []
    for stmt in alice["policies"]:
        if "iam:PassRole" in stmt["actions"]:
            rest = [a for a in stmt["actions"] if a != "iam:PassRole"]
            rewritten.append({"effect": "Allow", "actions": rest,
                              "resources": stmt["resources"]})
            rewritten.append({"effect": "Allow", "actions": ["iam:PassRole"],
                              "resources": [basic]})
        else:
            rewritten.append(stmt)
    alice["policies"] = rewritten

    remove_action(find(fixed["users"], "bob"), "iam:CreatePolicyVersion")
    return fixed


def show(label, paths):
    print(f"{label}: {len(paths)} path(s) to admin")
    for path in paths:
        print("  " + " -> ".join(path))


if __name__ == "__main__":
    account = load()
    show("BEFORE", attack_paths(account))
    print()
    show("AFTER", attack_paths(apply_fixes(account)))