"""What every dependency parser shares (SLOP001).

* ``kind_of`` decides, from a file's name and folder, whether it declares
  dependencies and which parser reads it.
* ``Dependency`` is one declared package with its place in the file, and
  ``DependencyFile`` is everything one file declares.
* ``parse_requirement`` reads the package name out of a requirement string, and
  refuses everything that is not a requirement (URLs, paths, file names, prose).

Nothing here reads a file or asks the registry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePath, PurePosixPath
from typing import NamedTuple

from slopfence.source import IGNORE_RE


class Kind(str, Enum):
    """The kinds of file that declare dependencies. Each has its own parser."""

    PYPROJECT = "pyproject.toml"
    SETUP_CFG = "setup.cfg"
    SETUP_PY = "setup.py"
    PIPFILE = "Pipfile"
    NOTEBOOK = "notebook"
    REQUIREMENTS = "requirements file"


# The kinds that are known by their exact file name, in any folder.
_KIND_BY_NAME = {
    kind.value: kind for kind in (Kind.PYPROJECT, Kind.SETUP_CFG, Kind.SETUP_PY, Kind.PIPFILE)
}
NOTEBOOK_SUFFIX = ".ipynb"

REQUIREMENTS_SUFFIXES = (".txt", ".in")
REQUIREMENTS_WORDS = ("requirements", "constraints")
REQUIREMENTS_DIR = "requirements"
# "apt-requirements.txt" and "requirements/conda.txt" list packages for another
# package manager. Their names are not PyPI names, and nothing in the file tells.
OTHER_PACKAGE_MANAGERS = frozenset(
    {
        "apk",
        "apt",
        "brew",
        "choco",
        "conda",
        "cran",
        "dnf",
        "gem",
        "npm",
        "pacman",
        "port",
        "rpm",
        "snap",
        "yum",
        "zypper",
    }
)
# Text files of other tools that a folder named "requirements" may hold.
NOT_REQUIREMENTS = frozenset({"CMakeLists.txt"})
_WORDS = re.compile(r"[a-z]+")

_OPERATOR = r"(?:===|==|~=|!=|<=|>=|<|>)"
# A PEP 508 requirement: a name, optional extras, then nothing, a version specifier
# (which may stand in brackets), a marker or a direct reference. Anything else is not
# a requirement ("https://x/y.whl", "this is prose", "add_test(NAME x)", "2>&1"). A
# version may start with "$" or "{": pip expands ${VAR}, and templates fill in
# {{ version }}.
_REQUIREMENT = re.compile(
    rf"""^\s*
    (?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)
    \s*(?P<extras>\[[^\]]*\])?
    \s*(?P<rest>$|[;@].*$|\(?\s*{_OPERATOR}\s*[A-Za-z0-9*${{].*$)""",
    re.X | re.S,
)
# pip treats "#" as a comment only at line start or after whitespace (URLs contain "#egg=").
REQ_COMMENT = re.compile(r"(^|\s)#.*$")
# The name a URL gives its package: "git+https://host/repo.git#egg=name".
_EGG = re.compile(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)")
# A checksum on a line of its own is not a package name.
_DIGEST = re.compile(r"[0-9a-fA-F]{32,}")
_LETTER = re.compile(r"[A-Za-z]")
# A name with one of these endings is a file: "vendor.tar.gz", "requirements-dev.txt",
# "mypkg-1.0-py3-none-any.whl". ".py", ".egg" and ".yaml" are not here, because
# "discord.py", "zc.recipe.egg" and "ruamel.yaml" are packages.
_FILE_ENDINGS = (".whl", ".zip", ".gz", ".bz2", ".xz", ".tgz", ".txt", ".in", ".toml", ".cfg")


# The variables a PEP 508 marker may test (``python_version < "3.11"``). They are
# never package names.
MARKER_NAMES = frozenset(
    {
        "os_name",
        "sys_platform",
        "platform_machine",
        "platform_python_implementation",
        "platform_release",
        "platform_system",
        "platform_version",
        "python_version",
        "python_full_version",
        "implementation_name",
        "implementation_version",
        "extra",
    }
)


@dataclass
class Dependency:
    """One declared package and where it is declared."""

    name: str
    path: str
    line: int
    # False for packages that don't come from PyPI (URLs, paths, git, private indexes).
    validate: bool = True
    # True when an ignore directive covers SLOP001 on this line or file.
    suppressed: bool = False
    # 1-based column of the requirement. Files with one requirement per line report 1.
    col: int = 1


@dataclass
class DependencyFile:
    """Everything one dependency file declares."""

    rel: str
    kind: Kind
    dependencies: list[Dependency] = field(default_factory=list)
    # What the file calls the project itself (``[project] name``, ``setup(name=...)``).
    project_names: set[str] = field(default_factory=set)
    # The file says that packages may come from a package index other than PyPI.
    private_index: bool = False
    # Requirements files only: no line uses pip's own syntax (a version, an extra, a
    # marker, an option). Such a file may be a list for another tool.
    plain_list: bool = False
    # Notebooks only: (top-level module, line, column) of every import in a code cell.
    # Empty unless they were asked for.
    imports: list[tuple[str, int, int]] = field(default_factory=list)
    # Notebooks only: the file is too large to be read (see ``notebooks.MAX_BYTES``).
    too_large: bool = False

    @property
    def read_by_v02(self) -> bool:
        """Whether v0.2 already read this file: ``pyproject.toml`` and ``requirements*.txt``.

        Every file that is read since v0.3 is treated with more care, so that the new
        version never sends a name the old one kept on the machine.
        """
        name = PurePosixPath(self.rel).name
        return self.kind is Kind.PYPROJECT or (
            self.kind is Kind.REQUIREMENTS
            and name.startswith("requirements")
            and name.endswith(".txt")
        )

    @property
    def inherits_index(self) -> bool:
        """Whether a private index in another project file also covers this file.

        The files v0.2 read speak for themselves: a private index counts for them when
        they name it. Every other file may be installed together with a file that
        names one (``pip install -r requirements.txt -c constraints.txt``), and most
        can't name an index at all. So one private index in the project covers them.
        """
        return not self.read_by_v02

    @property
    def may_be_for_another_tool(self) -> bool:
        """Whether the file may list packages for apt, R or another tool, not for pip.

        ``requirements/system.txt`` with one apt package per line looks exactly like
        a pip file. Only a plain list in a file that v0.2 did not read is doubted.
        """
        return self.plain_list and not self.read_by_v02


def is_requirements_file(path: PurePath) -> bool:
    """Whether a project-relative path is named like a pip requirements or constraints file.

    The name must end in ``.txt`` or ``.in``, and either

    * the name without that ending starts or ends with ``requirements`` or
      ``constraints`` (``requirements-dev.txt``, ``dev-requirements.txt``,
      ``requirements.in``, ``constraints.txt``), or
    * the file is inside a folder named ``requirements``, at any depth
      (``requirements/base.txt``, ``requirements/testing/all.in``).

    Matching is case-sensitive: ``REQUIREMENTS.txt`` is usually prose. A name that
    contains another package manager as a word (``apt-requirements.txt``,
    ``requirements/conda.txt``) never counts, and neither does ``CMakeLists.txt``.
    """
    name = path.name
    if not name.endswith(REQUIREMENTS_SUFFIXES) or name in NOT_REQUIREMENTS:
        return False
    stem = name.rsplit(".", 1)[0]
    if OTHER_PACKAGE_MANAGERS.intersection(_WORDS.findall(stem.lower())):
        return False
    if stem.startswith(REQUIREMENTS_WORDS) or stem.endswith(REQUIREMENTS_WORDS):
        return True
    return REQUIREMENTS_DIR in path.parts[:-1]


def _kind_by_name(name: str) -> Kind | None:
    """The kind of a file whose folder doesn't matter: every kind but requirements files."""
    return Kind.NOTEBOOK if name.endswith(NOTEBOOK_SUFFIX) else _KIND_BY_NAME.get(name)


def dependency_kind(path: PurePath) -> Kind | None:
    """Which kind of dependency file a project-relative path is, or None if it is none."""
    kind = _kind_by_name(path.name)
    if kind is None and is_requirements_file(path):
        return Kind.REQUIREMENTS
    return kind


def kind_of(path: Path, root: Path) -> Kind | None:
    """``dependency_kind`` of a file, judged by its path inside the project ``root``.

    Folders above the project never count, so a project that lives in
    ``~/requirements/app`` doesn't turn every text file into a requirements file.
    A file outside ``root`` is judged by its name alone.
    """
    name = path.name
    if not name.endswith(REQUIREMENTS_SUFFIXES):
        # The folder doesn't matter, and most files of a project end up here. So no
        # relative path is worked out: on a big project that would double the walk.
        return _kind_by_name(name)
    try:
        rel = path.relative_to(root)
    except ValueError:
        try:
            rel = path.resolve().relative_to(root.resolve())
        except ValueError:
            rel = Path(name)
    return dependency_kind(rel)


class Requirement(NamedTuple):
    """What a requirement string says about the package it names."""

    name: str
    # ``name @ https://...``: the package never comes from an index.
    direct: bool
    # The string is the name and nothing else: no extra, version, marker or URL.
    bare: bool


def parse_requirement(spec: str) -> Requirement | None:
    """Read a PEP 508 requirement string. None when ``spec`` is not a requirement.

    Not a requirement: a URL, a path, prose, a call like ``project(x)``, a file name
    (``vendor.tar.gz``), a checksum, a number or date, and ``python>=3.9`` (the
    interpreter is not a package).
    """
    m = _REQUIREMENT.match(spec)
    if not m:
        return None
    name = m.group("name")
    if (
        not _LETTER.search(name)
        or _DIGEST.fullmatch(name)
        or name.lower() == "python"
        or name.lower().endswith(_FILE_ENDINGS)
    ):
        return None
    rest = m.group("rest")
    return Requirement(name, rest.startswith("@"), not (rest or m.group("extras")))


def egg_name(url: str) -> str | None:
    """The package name in the ``#egg=`` part of a URL, or None if it has none."""
    m = _EGG.search(url)
    return m.group(1) if m else None


def suppresses_slop001(comment: str) -> bool:
    """Whether a comment holds a ``slopfence: ignore`` directive that covers SLOP001."""
    m = IGNORE_RE.search(comment)
    if not m:
        return False
    rules = m.group("rules")
    return rules is None or "SLOP001" in {r.strip().upper() for r in rules.split(",")}


def requirements_comment(line: str) -> str:
    """The comment part of a requirements-style line ("" if none)."""
    m = REQ_COMMENT.search(line)
    return m.group(0) if m else ""
