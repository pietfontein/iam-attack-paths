import json
import json
from fnmatch import fnmatch

import networkx as nx

ACCOUNT = "111122223333"


def load(path="sample/lab_account.json"):
    with open(path) as f:
        return json.load(f)


def arn(kind, name):
    return f"arn:aws:iam::{ACCOUNT}:{kind}/{name}"


def action_allowed(identity, action, resource="*"):
    allowed = False
    for stmt in identity["policies"]:
        action_ok = any(fnmatch(action.lower(), a.lower()) for a in stmt["actions"])
        resource_ok = any(fnmatch(resource, r) for r in stmt["resources"])
        if not (action_ok and resource_ok):
            continue
        if stmt["effect"] == "Deny":
            return False
        if stmt["effect"] == "Allow":
            allowed = True
    return allowed


def is_admin(identity):
    for stmt in identity["policies"]:
        if (stmt["effect"] == "Allow"
                and "*" in stmt["actions"]
                and "*" in stmt["resources"]):
            return True
    return False


def build_graph(account):
    g = nx.DiGraph()
    people = [("user", u) for u in account["users"]]
    roles = [("role", r) for r in account["roles"]]

    for kind, ident in people + roles:
        g.add_node(arn(kind, ident["name"]),
                   name=ident["name"], kind=kind, admin=is_admin(ident))

    for kind, ident in people + roles:
        source = arn(kind, ident["name"])
        for role in account["roles"]:
            target = arn("role", role["name"])
            can_call = action_allowed(ident, "sts:AssumeRole", target)
            is_trusted = source in role["trust"]
            if can_call and is_trusted:
                g.add_edge(source, target, how="sts:AssumeRole")
    return g


if __name__ == "__main__":
    g = build_graph(load())
    print("IDENTITIES")
    for node, data in g.nodes(data=True):
        flag = "  <-- ADMIN" if data["admin"] else ""
        print(f"  {data['kind']:5} {data['name']}{flag}")
    print()
    print("CAN BECOME")
    for a, b, data in g.edges(data=True):
        print(f"  {g.nodes[a]['name']} -> {g.nodes[b]['name']}   ({data['how']})")