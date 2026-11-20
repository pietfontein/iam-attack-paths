import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

from graph import load, build_graph
from escalation import add_escalations, GOAL
from fixes import apply_fixes, attack_paths

NODE = 5600

POS = {
    "carol": (0, 3.9),
    "alice": (0, 2.7),
    "bob": (0, 1.5),
    "dave": (0, 0.3),
    "dev-role": (3, 3.3),
    "lambda-admin-role": (3, 2.2),
    "lambda-basic-role": (3, 0.6),
    "ACCOUNT_ADMIN": (6, 1.5),
}


def prepare(account):
    g = add_escalations(build_graph(account), account)
    names = {n: g.nodes[n]["name"] for n in g.nodes}
    risky = set()
    for node, data in g.nodes(data=True):
        if data["kind"] == "goal" or data["admin"]:
            continue
        for path in nx.all_simple_paths(g, node, GOAL):
            risky.update((names[a], names[b]) for a, b in zip(path, path[1:]))
    h = nx.relabel_nodes(g, names)
    h.remove_edges_from([(a, b) for a, b in list(h.edges) if h.nodes[a]["admin"]])
    risky = {e for e in risky if h.has_edge(*e)}
    return h, risky


def node_color(data):
    if data["kind"] == "goal":
        return "#F09595"
    if data["admin"]:
        return "#F5C4B3"
    return "#B5D4F4" if data["kind"] == "user" else "#CECBF6"


def draw(ax, account, title):
    h, risky = prepare(account)
    colors = [node_color(h.nodes[n]) for n in h.nodes]
    edge_colors = ["#A32D2D" if e in risky else "#B4B2A9" for e in h.edges]
    widths = [2.5 if e in risky else 1.0 for e in h.edges]
    labels = {e: h.edges[e]["how"] for e in risky}

    nx.draw_networkx_edges(h, POS, ax=ax, edge_color=edge_colors, width=widths,
                           arrows=True, arrowsize=18, node_size=NODE)
    nx.draw_networkx_nodes(h, POS, ax=ax, node_color=colors,
                           node_size=NODE, edgecolors="#444441")
    nx.draw_networkx_labels(h, POS, ax=ax, font_size=7.5)
    nx.draw_networkx_edge_labels(
        h, POS, edge_labels=labels, ax=ax, font_size=7.5,
        font_color="#791F1F", rotate=False,
        bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.9))
    ax.set_title(title, fontsize=11)
    ax.set_xlim(-0.8, 6.8)
    ax.set_ylim(-0.5, 4.5)
    ax.axis("off")


account = load()
fixed = apply_fixes(account)
fig, axes = plt.subplots(1, 2, figsize=(16, 7.5))
draw(axes[0], account, f"Before: {len(attack_paths(account))} attack paths to admin")
draw(axes[1], fixed, f"After three fixes: {len(attack_paths(fixed))} attack paths")
fig.text(0.5, 0.02,
         "Red arrows are steps on a path to ACCOUNT_ADMIN. Pink nodes already have "
         "full admin access. Blue = users, purple = roles.",
         ha="center", fontsize=9)
fig.savefig("docs/attack_paths.png", dpi=150, bbox_inches="tight")
print("saved docs/attack_paths.png")
