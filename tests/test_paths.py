import copy

import pytest

from graph import load
from fixes import attack_paths, apply_fixes, find, remove_action

EXPECTED = {
    ("alice", "dev-role", "ACCOUNT_ADMIN"),
    ("alice", "lambda-admin-role", "ACCOUNT_ADMIN"),
    ("bob", "ACCOUNT_ADMIN"),
    ("dev-role", "ACCOUNT_ADMIN"),
}


def as_set(paths):
    return {tuple(p) for p in paths}


def test_finds_exactly_the_known_paths():
    assert as_set(attack_paths(load())) == EXPECTED


def test_safe_identities_have_no_paths():
    starts = {p[0] for p in attack_paths(load())}
    assert "dave" not in starts
    assert "lambda-basic-role" not in starts


def test_all_three_fixes_remove_every_path():
    assert attack_paths(apply_fixes(load())) == []


def test_fixing_only_the_top_choke_point_is_not_enough():
    account = copy.deepcopy(load())
    remove_action(find(account["roles"], "dev-role"), "iam:AttachUserPolicy")
    assert as_set(attack_paths(account)) == {
        ("alice", "lambda-admin-role", "ACCOUNT_ADMIN"),
        ("bob", "ACCOUNT_ADMIN"),
    }



def test_explicit_deny_blocks_a_path():
    account = copy.deepcopy(load())
    find(account["users"], "alice")["policies"].append({
        "effect": "Deny",
        "actions": ["iam:PassRole"],
        "resources": ["arn:aws:iam::111122223333:role/lambda-admin-role"],
    })
    assert ("alice", "lambda-admin-role", "ACCOUNT_ADMIN") not in as_set(attack_paths(account))