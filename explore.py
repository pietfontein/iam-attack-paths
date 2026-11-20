import json

with open("sample/lab_account.json") as f:
    account = json.load(f)

print("Account:", account["account_id"])

for kind in ("users", "roles"):
    print()
    print(kind.upper())
    for identity in account[kind]:
        all_actions = []
        for stmt in identity["policies"]:
            all_actions.extend(stmt["actions"])
        print(f"  {identity['name']}")
        print(f"    actions: {all_actions}")
        if kind == "roles":
            print(f"    trusted by: {identity['trust']}")