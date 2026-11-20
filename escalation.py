from graph import load, build_graph, action_allowed, arn

GOAL = "ACCOUNT_ADMIN"

SELF_ESCALATION = [
    "iam:CreatePolicyVersion",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
]


def all_identities(account):
    return ([("user", u) for u in account["users"]]
            + [("role", r) for r in account["roles"]])


def add_edge(g, source, target, how):
    if g.has_edge(source, target):
        how = g[source][target]["how"] + ", " + how
    g.add_edge(source, target, how=how)


def add_escalations(g, account):
    g.add_node(GOAL, name=GOAL, kind="goal", admin=True)

    for kind, ident in all_identities(account):
        source = arn(kind, ident["name"])

        if g.nodes[source]["admin"]:
            add_edge(g, source, GOAL, "already has full access")
            continue

        for action in SELF_ESCALATION:
            if action_allowed(ident, action, "*"):
                add_edge(g, source, GOAL, action)

        can_run_lambda = (
            action_allowed(ident, "lambda:CreateFunction")
            and action_allowed(ident, "lambda:InvokeFunction")
        )
        if can_run_lambda:
            for role in account["roles"]:
                if "lambda.amazonaws.com" not in role["trust"]:
                    continue
                target = arn("role", role["name"])
                if action_allowed(ident, "iam:PassRole", target):
                    add_edge(g, source, target, "PassRole + Lambda")
    return g


if __name__ == "__main__":
    account = load()
    g = add_escalations(build_graph(account), account)
    print("CAN BECOME")
    for a, b, data in g.edges(data=True):
        print(f"  {g.nodes[a]['name']} -> {g.nodes[b]['name']}   ({data['how']})")