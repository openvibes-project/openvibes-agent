#!/usr/bin/env python3
"""Print the RPM License expression for the binaries of the given crates.

Usage: scripts/rpm-license.py [--extra 'SPDX expr']... <crate>...

Joins the licences of every crate the binaries link (cargo tree, normal and
build dependencies, x86_64 Linux) with AND, as Fedora's Rust packaging
guidelines ask. A dual-licensed crate stays an OR group unless a licence it
offers is already required by another crate (then the group is redundant).
--extra adds a licence verbatim, for code that cargo does not see (a bundled
C++ server, an embedded eBPF object).
"""
import re
import subprocess
import sys


def parse(tokens):
    """SPDX tokens -> ('and'|'or', [...]) tree; atoms are strings. AND binds tighter."""
    def alt():
        items = [conj()]
        while tokens and tokens[0] == "OR":
            tokens.pop(0)
            items.append(conj())
        return items[0] if len(items) == 1 else ("or", items)

    def conj():
        items = [atom()]
        while tokens and tokens[0] == "AND":
            tokens.pop(0)
            items.append(atom())
        return items[0] if len(items) == 1 else ("and", items)

    def atom():
        t = tokens.pop(0)
        if t == "(":
            node = alt()
            tokens.pop(0)  # ")"
            return node
        if tokens and tokens[0] == "WITH":
            tokens.pop(0)
            t += " WITH " + tokens.pop(0)
        return t

    return alt()


def groups(node):
    """Flatten a tree into AND-ed items: atoms or ('or', sorted atoms)."""
    if isinstance(node, str):
        return [node]
    if node[0] == "and":
        return [g for n in node[1] for g in groups(n)]
    alts = sorted({a for n in node[1] for a in (groups(n) if isinstance(n, str) else [render(n)])})
    return [("or", alts)]


def render(node):
    if isinstance(node, str):
        return node
    if node[0] == "and":
        return " AND ".join(sorted(set(map(render, groups(node)))))
    return "(" + " OR ".join(node[1]) + ")"


def spdx(expr):
    expr = expr.replace("/", " OR ").replace(" (*)", "")
    return parse(re.findall(r"\(|\)|[^\s()]+", expr))


def main(argv):
    extras, crates = [], []
    it = iter(argv)
    for a in it:
        (extras if a == "--extra" else crates).append(next(it) if a == "--extra" else a)
    atoms, ors = set(), set()
    for crate in crates:
        out = subprocess.run(
            ["cargo", "tree", "-e", "normal,build", "--target", "x86_64-unknown-linux-gnu",
             "-p", crate, "--prefix", "none", "--format", "{l}"],
            check=True, capture_output=True, text=True).stdout
        for line in set(out.splitlines()):
            if line.strip():
                for g in groups(spdx(line.strip())):
                    (atoms.add(g) if isinstance(g, str) else ors.add(tuple(g[1])))
    ors = {o for o in ors if not atoms.intersection(o)}
    parts = sorted(atoms) + sorted("(" + " OR ".join(o) + ")" for o in ors)
    parts += [f"({e})" if " OR " in e else e for e in extras if e not in parts]
    print(" AND ".join(parts))


if __name__ == "__main__":
    main(sys.argv[1:])
