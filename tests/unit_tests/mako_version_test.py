# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Regression tests guarding the ``mako`` security floor.

CVE-2026-44307 (backslash path traversal in ``mako.template.Template``) is
fixed in mako 1.3.12. Every place the dependency is pinned or constrained
must stay at or above that version, and the pins must agree with each other.
"""

import re
from importlib.metadata import version
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

MAKO_SECURITY_FLOOR = Version("1.3.12")
REPO_ROOT = Path(__file__).resolve().parents[2]


def _lower_bound(specifier: SpecifierSet) -> Version:
    bounds = [
        Version(spec.version) for spec in specifier if spec.operator in (">=", "==")
    ]
    assert bounds, f"no lower bound in {specifier!r}"
    return max(bounds)


def _lockfile_pin() -> Version:
    text = (REPO_ROOT / "requirements/base.txt").read_text()
    match = re.search(r"^mako==(\S+)$", text, flags=re.IGNORECASE | re.MULTILINE)
    assert match, "mako is not pinned in requirements/base.txt"
    return Version(match.group(1))


def _pyproject_specifier() -> SpecifierSet:
    text = (REPO_ROOT / "pyproject.toml").read_text()
    for match in re.finditer(r'^\s*"(mako[^"]*)",?\s*$', text, flags=re.I | re.M):
        return Requirement(match.group(1)).specifier
    pytest.fail("mako is not declared in pyproject.toml")


def test_pyproject_lower_bound_meets_security_floor() -> None:
    assert _lower_bound(_pyproject_specifier()) >= MAKO_SECURITY_FLOOR


def test_lockfile_pin_meets_security_floor() -> None:
    assert _lockfile_pin() >= MAKO_SECURITY_FLOOR


def test_lockfile_pin_satisfies_pyproject_constraint() -> None:
    assert str(_lockfile_pin()) in _pyproject_specifier()


def test_installed_mako_meets_security_floor() -> None:
    assert Version(version("mako")) >= MAKO_SECURITY_FLOOR
