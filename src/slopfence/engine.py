"""File discovery and running detectors over a project."""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Collection, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from functools import partial
from pathlib import Path

from slopfence import baseline as baselinemod
from slopfence import diff as diffmod
from slopfence.analysis import FileSummary, Options, Task, analyze_files
from slopfence.config import ignored_rules, is_excluded, selected_rules, slop002_has_no_lookups
from slopfence.detectors import FILE_DETECTORS
from slopfence.detectors.dependency import NOTEBOOK_SUFFIX, Kind, kind_of
from slopfence.detectors.duplicates import check_duplicates
from slopfence.detectors.notebooks import MAX_BYTES as MAX_NOTEBOOK_BYTES
from slopfence.detectors.packages import (
    LOCK_FILES,
    PACKAGE_RULES,
    PackageChecker,
    build_index,
    may_look_up,
)
from slopfence.models import NEW_PACKAGE_DAYS, RULES, Finding, Severity, plural
from slopfence.registry import OfflineRegistry, Registry
from slopfence.source import relative_path as _rel_to

EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    ".env",
    "node_modules",
    "__pycache__",
    "build",
    "dist",
    ".tox",
    ".nox",
    ".eggs",
    "site-packages",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    # Jupyter's autosaved copies of notebooks.
    ".ipynb_checkpoints",
}


def discover_all(paths: Sequence[Path], root: Path) -> tuple[list[Path], list[Path], list[Path]]:
    """Return (python files, dependency files, lock files) under the given paths.

    ``setup.py`` is both a Python file and a dependency file. ``root`` is the project
    root: whether a file is a dependency file can depend on its folder inside the
    project (``requirements/base.txt``, see ``dependency.kind_of``).
    """
    py_files: list[Path] = []
    dep_files: list[Path] = []
    lock_files: list[Path] = []

    def add(path: Path) -> None:
        """Put one file on the lists it belongs to."""
        if path.suffix == ".py":
            py_files.append(path)
        if kind_of(path, root) is not None:
            dep_files.append(path)
        elif path.name in LOCK_FILES:
            lock_files.append(path)

    for path in paths:
        path = path.resolve()
        if path.is_file():
            add(path)
            continue
        for dirpath, dirnames, filenames in os.walk(path):
            # Prune excluded trees (.venv, node_modules, .git...) and nested checkouts
            # before descending. A sub-folder that holds a .git file or folder is a
            # worktree, clone or submodule: another copy of a project, not this one.
            # Its files must not count as this project's code (SLOP030 would
            # double-report; SLOP001 would treat its modules as local and its
            # dependency files as this project's, see #58). The path passed on the
            # command line is the walk root and is never pruned, so an explicitly
            # named checkout is still checked.
            dirnames[:] = [
                d
                for d in dirnames
                if d not in EXCLUDED_DIRS
                and not d.endswith(".egg-info")
                and not (Path(dirpath, d) / ".git").exists()
            ]
            for filename in filenames:
                add(Path(dirpath, filename))
    return sorted(set(py_files)), sorted(set(dep_files)), sorted(set(lock_files))


def _not_excluded(files: list[Path], root: Path, exclude: Sequence[str]) -> list[Path]:
    """``files`` without the ones that match an ``exclude`` pattern."""
    if not exclude:
        return files  # the usual case, and no relative path has to be worked out
    return [p for p in files if not is_excluded(_rel_to(p, root), exclude)]


def _dependency_files_to_read(
    project: list[Path], checked: list[Path], root: Path, exclude: Sequence[str], imports: bool
) -> list[Path]:
    """The dependency files that SLOP001 reads: the checked ones, and more of the project.

    Every file of the project but a notebook is read, wherever it is: a private
    index, or the name of one of the project's own packages, counts for the whole
    project. A notebook says less and costs more. It is read when it is checked.
    With ``imports`` the others are read too, for the packages they install, unless
    they are excluded.
    """
    notebooks = _not_excluded(project, root, exclude) if imports else []
    return sorted(
        {
            *checked,
            *(p for p in project if p.suffix != NOTEBOOK_SUFFIX),
            *(p for p in notebooks if p.suffix == NOTEBOOK_SUFFIX),
        }
    )


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    files_checked: int = 0
    parse_errors: list[str] = field(default_factory=list)
    # Things the user should know about the run, e.g. why lookups were skipped.
    notes: list[str] = field(default_factory=list)
    # The severities the config sets (rule ID -> severity), for reports that list rules.
    severities: dict[str, Severity] = field(default_factory=dict)
    # The findings the baseline hid. With --diff, only the ones on changed lines.
    baselined: list[Finding] = field(default_factory=list)
    # The package rules (SLOP001...) that ran without all their answers from PyPI: the
    # run was offline, the environment has a private index, or PyPI did not answer.
    # Their findings may be incomplete.
    unchecked_rules: list[str] = field(default_factory=list)


# How many file names a note lists before it only counts the rest.
NOTE_FILE_LIMIT = 3
# The note of a run that leaves SLOP002 out because SLOP001 is ignored.
SLOP002_NEEDS_SLOP001 = (
    "SLOP002 did not run: it uses SLOP001's PyPI lookups, and SLOP001 is ignored, so no "
    "package names were sent. To run SLOP002 without SLOP001, name it in 'select'."
)


def _listed(files: Sequence[str]) -> str:
    """File names for a note: the first few, then how many more there are."""
    shown = ", ".join(files[:NOTE_FILE_LIMIT])
    more = len(files) - NOTE_FILE_LIMIT
    return f"{shown} and {plural(more, 'more file')}" if more > 0 else shown


def _per_file_matcher(
    per_file_ignores: Mapping[str, Iterable[str]],
) -> Callable[[str, str], bool]:
    """A function that says whether ``per-file-ignores`` switches a rule off for a file.

    It takes a rule ID and a project-relative POSIX path. The patterns are matched
    once per file, however many findings the file has.
    """
    off: dict[str, frozenset[str]] = {}

    def switched_off(rule: str, rel: str) -> bool:
        """Whether ``rule`` is switched off for the file ``rel``."""
        if rel not in off:
            off[rel] = ignored_rules(rel, per_file_ignores)
        return rule in off[rel]

    return switched_off


def _with_severities(findings: list[Finding], severity: Mapping[str, Severity]) -> list[Finding]:
    """``findings``, each with the severity the config sets for its rule.

    A finding whose rule keeps its own severity is not touched, so it stays equal to
    the finding of a run without the config.
    """
    return [
        replace(f, severity_override=level)
        if (level := severity.get(f.rule)) not in (None, RULES[f.rule].severity)
        else f
        for f in findings
    ]


def _on_changed_lines(findings: list[Finding], changed: diffmod.ChangedLines) -> list[Finding]:
    """The findings that ``--diff`` reports: the ones that touch a changed line."""
    return [f for f in findings if diffmod.touches(changed, f.path, f.line, f.end_line)]


def _not_ignored(
    findings: Iterable[Finding], ignores: Mapping[tuple[int, int], Collection[str]]
) -> Iterator[Finding]:
    """The findings about the imports of a notebook that no ignore comment covers.

    ``ignores`` maps the (line, column) of an import to the rules its comment switches
    off (``DependencyFile.import_ignores``). The ignore comments of a source file
    are applied by line, in ``_finish``. That won't do for a notebook: one line of
    the file can hold a whole cell, with a ``pip install`` line and many imports.
    """
    return (f for f in findings if f.rule not in ignores.get((f.line, f.col), ()))


def _finish(
    result: Result,
    findings: Iterable[Finding],
    sources: Iterable[FileSummary],
    switched_off: Callable[[str, str], bool],
    *,
    severity: Mapping[str, Severity],
    baseline: baselinemod.Baseline | None,
    changed: diffmod.ChangedLines | None,
    rules: set[str],
    scope: baselinemod.Scope,
    root: Path,
) -> None:
    """Filter, order and label the findings of every rule, and put them in ``result``.

    The filters, always in this order: ignore comments, per-file ignores, severities
    from the config (they only change a label), the baseline, then ``--diff``. A new
    rule needs nothing here: it only hands in its findings.

    ``sources`` are the files that were checked and ``switched_off`` says where
    ``per-file-ignores`` switch a rule off. ``rules`` are the rules that ran and
    ``scope`` is what the run set out to check (see ``baseline.scope_of``): the two
    say which baselined findings the run should have found again.
    """
    by_rel = {s.rel: s for s in sources}
    findings = [
        f
        for f in findings
        if not (f.path in by_rel and by_rel[f.path].is_ignored(f.rule, f.line))
        and not switched_off(f.rule, f.path)
    ]
    # The one sort. The message breaks ties: ``import a, b`` gives two findings at one
    # position, and without it their order would be the set's, which changes with the
    # hash seed.
    findings = sorted(set(findings), key=lambda f: (f.path, f.line, f.col, f.rule, f.message))
    if severity:
        findings = _with_severities(findings, severity)
    if baseline is not None:
        # Before --diff: an old finding outside the diff must use up its entry, or a
        # new one like it on a changed line would be hidden in its place.
        matched = baselinemod.match(findings, baseline, changed)
        findings, result.baselined = matched.new, matched.hidden
        # With --diff some rules only look at changed code, so an entry that nothing
        # used says nothing. Nor does one of a package rule: PyPI may not have answered.
        if changed is None:
            note = baselinemod.stale_note(
                baseline, matched.unused, rules - PACKAGE_RULES, by_rel.keys(), scope, root
            )
            if note:
                result.notes.append(note)
    if changed is not None:
        findings = _on_changed_lines(findings, changed)
        result.baselined = _on_changed_lines(result.baselined, changed)
    result.findings = findings


def run(
    paths: Sequence[Path],
    root: Path,
    registry: Registry,
    select: Iterable[str] | None = None,
    ignore: Iterable[str] = (),
    changed: diffmod.ChangedLines | None = None,
    exclude: Sequence[str] = (),
    known_packages: Sequence[str] = (),
    check_imports: bool = False,
    private_index: str | None = None,
    jobs: int = 1,
    per_file_ignores: Mapping[str, Iterable[str]] | None = None,
    severity: Mapping[str, Severity] | None = None,
    baseline: baselinemod.Baseline | None = None,
    inherit_index: bool = True,
    min_package_age: int = NEW_PACKAGE_DAYS,
    now: float | None = None,
) -> Result:
    """Check ``paths`` and return the findings.

    The package rules, SLOP001 and SLOP002, always check dependency files. Imports in
    source code are only looked up on PyPI with ``check_imports``, because that sends
    their names to pypi.org and can reveal private package names. SLOP002 reads the
    answers to SLOP001's lookups. Without SLOP001 it only runs when ``select`` names
    it (see ``config.slop002_has_no_lookups``).

    ``private_index`` says where the environment configures a non-PyPI package
    index (see ``indexes.find_private_index``); the package rules then make no lookups.

    SLOP002 reports a package whose oldest file on PyPI is less than
    ``min_package_age`` days old at ``now`` (Unix seconds; default: the clock).

    A private index in a project file covers that file. With ``inherit_index`` it also
    covers the dependency files that name no index of their own (``setup.py``,
    ``setup.cfg``, ``Pipfile``, notebooks, and requirements files that v0.2 did not
    read), unless the file that names it is excluded.

    Files are parsed and checked in up to ``jobs`` worker processes when there are
    enough of them (see ``analysis.analyze_files``). The result does not depend on
    ``jobs``. Registry lookups always happen in this process.

    ``per_file_ignores`` maps patterns (the kind ``exclude`` takes) to the rules that
    are switched off in the matching files. ``severity`` gives rules another severity.
    ``baseline`` holds findings that were accepted earlier: they are left out of
    ``Result.findings`` and listed in ``Result.baselined``.
    """
    ignore = set(ignore)  # read once: it may be an iterator, and it is needed twice
    rules = selected_rules(select, ignore)
    root = root.resolve()

    found_py, found_deps, found_locks = discover_all(paths, root)
    # Excluded files are not checked, but still count as project modules below.
    py_files = _not_excluded(found_py, root, exclude)
    dep_files = _not_excluded(found_deps, root, exclude)

    # SLOP030 and SLOP001 look at the whole project, not just the checked paths. When
    # pre-commit passes only changed files, their functions and imports are still
    # compared with the rest. And a private index, or the name of one of the project's
    # own packages, counts wherever in the project it is written.
    project = (found_py, found_deps, found_locks)
    whole_project_given = any(Path(p).resolve() == root for p in paths)
    package_rules = rules & PACKAGE_RULES
    if (package_rules or "SLOP030" in rules) and not whole_project_given:
        project = discover_all([root], root)

    tasks: list[Task] = [(str(p), True) for p in py_files]
    if "SLOP030" in rules and not whole_project_given:
        # The rest of the project is only fingerprinted, to compare checked functions with.
        checked_paths = {p.resolve() for p in py_files}
        tasks += [
            (str(p), False)
            for p in _not_excluded(project[0], root, exclude)
            if p.resolve() not in checked_paths
        ]
    options = Options(
        root=str(root),
        rules=frozenset(rules & set(FILE_DETECTORS)),
        functions="SLOP030" in rules,
        imports=bool(package_rules) and check_imports,
    )
    summaries = analyze_files(tasks, options, jobs)
    checked, compared_with = summaries[: len(py_files)], summaries[len(py_files) :]

    result = Result(severities=dict(severity or {}))
    switched_off = _per_file_matcher(per_file_ignores or {})
    result.parse_errors = [s.rel for s in checked if not s.parsed]
    sources = [s for s in checked if s.parsed]
    # setup.py is a Python file and a dependency file: it is counted once.
    result.files_checked = len(sources) + sum(p.suffix != ".py" for p in dep_files)

    findings = [f for s in sources for f in s.findings]

    if package_rules:
        to_read = _dependency_files_to_read(project[1], dep_files, root, exclude, check_imports)
        index = build_index(root, project[0], to_read, project[2], imports=check_imports)
        checker = PackageChecker(
            index,
            registry,
            known_packages=known_packages,
            private_index=private_index,
            # A private index in an excluded file is the user's to leave out.
            inherited_from=[
                rel
                for rel in index.install_index_files
                if inherit_index and not is_excluded(rel, exclude)
            ],
            now=time.time() if now is None else now,
            rules=package_rules,
            min_package_age=min_package_age,
        )
        # The names of these files, and of no other file, may go to PyPI. A file where
        # per-file-ignores switch SLOP001 off is left out here, where the two collections
        # are made: the batch below and both checks are fed from them (``may_look_up``
        # says which rules must be on). So is a file outside the diff: its findings
        # would be dropped.
        checked_deps = {
            rel
            for p in dep_files
            if may_look_up(partial(switched_off, rel=(rel := _rel_to(p, root))), package_rules)
            and (changed is None or rel in changed)
        }
        # Imports are only sent to PyPI when the user opts in (they can reveal private
        # names), and never for files outside the diff. Nor is an import under an ignore
        # comment: its finding would be dropped, so there is nothing to ask for.
        imports = {
            s.rel: [
                found
                for found in s.imports
                if may_look_up(partial(s.is_ignored, line=found[1]), package_rules)
            ]
            for s in sources
            if check_imports
            and (changed is None or s.rel in changed)
            and may_look_up(partial(switched_off, rel=s.rel), package_rules)
        }
        # The imports in the code cells of checked notebooks, under the same opt-in.
        # Only notebooks: a setup.py is a dependency file too, and its imports are
        # already in the list. Each import of a notebook has ignore comments of its own.
        import_ignores = {
            f.rel: f.import_ignores
            for f in index.files
            if check_imports and f.kind is Kind.NOTEBOOK and f.rel in checked_deps
        }
        for file in index.files:
            if (off := import_ignores.get(file.rel)) is not None:
                imports[file.rel] = [
                    found
                    for found in file.imports
                    if may_look_up(off.get(found[1:], frozenset()).__contains__, package_rules)
                ]
        imported = [name for found in imports.values() for name, _, _ in found]
        # One batch with every name the two checks below will ask about.
        checker.prefetch(checked_deps, imported)
        findings.extend(checker.check_dependencies(only_paths=checked_deps))
        named = " and ".join(sorted(package_rules))
        if private_index:
            result.notes.append(
                f"{named} made no PyPI lookups: a private package index is configured in "
                f"{private_index}, so packages missing from PyPI may be private. If that "
                "index only mirrors PyPI, set detect-private-index = false."
            )
        elif check_imports and checker.imports_may_be_private:
            result.notes.append(
                f"{named} didn't look up imports on PyPI: {_listed(index.private_index_files)} "
                "uses a private package index, so unknown imports may be private packages."
            )
        if skipped := checker.inherited_files(checked_deps):
            result.notes.append(
                f"{named} didn't look up the dependencies in {_listed(sorted(skipped))}: a "
                f"private package index is set in {_listed(checker.inherited_from)}, so "
                "names missing from PyPI may be private packages. If that index only "
                "mirrors PyPI, set detect-private-index = false."
            )
        if too_large := sorted(f.rel for f in index.files if f.too_large and f.rel in checked_deps):
            result.notes.append(
                f"{named} didn't read {_listed(too_large)}: a notebook larger than "
                f"{MAX_NOTEBOOK_BYTES // 2**20} MB is skipped."
            )
        for rel, found in imports.items():
            reported = checker.check_imports(rel, found)
            findings.extend(_not_ignored(reported, import_ignores.get(rel, {})))
        if checker.lookups_unanswered(checked_deps, imported):
            result.unchecked_rules = sorted(package_rules)
    elif (
        slop002_has_no_lookups(select, ignore)
        # A run that could not look anything up has nothing to say about it.
        and not private_index
        and not isinstance(registry, OfflineRegistry)
    ):
        result.notes.append(SLOP002_NEEDS_SLOP001)

    if "SLOP030" in rules:
        project_files = (*sources, *compared_with)
        findings.extend(
            check_duplicates(
                [f for s in project_files for f in s.functions],
                {s.rel for s in sources},
                changed,
                # A copy of code from a file where SLOP030 is off is still reported.
                ignored={s.rel for s in project_files if switched_off("SLOP030", s.rel)},
                # With --diff, a baseline must also see what did not change.
                report_unchanged=baseline is not None,
            )
        )

    _finish(
        result,
        findings,
        sources,
        switched_off,
        severity=severity or {},
        baseline=baseline,
        changed=changed,
        rules=rules,
        scope=baselinemod.scope_of(paths, root, exclude, rules),
        root=root,
    )
    return result
