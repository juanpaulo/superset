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
import tomllib
from importlib.metadata import version
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

MAKO_SECURITY_FLOOR = Version("1.3.12")
REPO_ROOT = Path(__file__).resolve().parents[2]
LOCKFILES = ("requirements/base.txt", "requirements/development.txt")


def _lower_bound(specifier: SpecifierSet) -> Version:
    bounds = [
        Version(spec.version) for spec in specifier if spec.operator in (">=", "==")
    ]
    assert bounds, f"no lower bound in {specifier!r}"
    return max(bounds)


def _lockfile_pin(path: str) -> Version:
    text = (REPO_ROOT / path).read_text()
    match = re.search(r"^mako==(\S+)$", text, flags=re.IGNORECASE | re.MULTILINE)
    assert match, f"mako is not pinned in {path}"
    return Version(match.group(1))


def _pyproject_specifier() -> SpecifierSet:
    with (REPO_ROOT / "pyproject.toml").open("rb") as fp:
        deps = tomllib.load(fp)["project"]["dependencies"]
    for dep in deps:
        req = Requirement(dep)
        if req.name.lower() == "mako":
            return req.specifier
    pytest.fail("mako is not declared in pyproject.toml")


def _base_in_specifier() -> SpecifierSet:
    for line in (REPO_ROOT / "requirements/base.in").read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        req = Requirement(line)
        if req.name.lower() == "mako":
            return req.specifier
    pytest.fail("mako is not declared in requirements/base.in")


def test_pyproject_lower_bound_meets_security_floor() -> None:
    assert _lower_bound(_pyproject_specifier()) >= MAKO_SECURITY_FLOOR


def test_base_in_lower_bound_meets_security_floor() -> None:
    assert _lower_bound(_base_in_specifier()) >= MAKO_SECURITY_FLOOR


@pytest.mark.parametrize("path", LOCKFILES)
def test_lockfile_pin_meets_security_floor(path: str) -> None:
    assert _lockfile_pin(path) >= MAKO_SECURITY_FLOOR


def test_lockfile_pins_are_consistent_with_constraints() -> None:
    pins = {_lockfile_pin(path) for path in LOCKFILES}
    assert len(pins) == 1, f"lockfiles disagree on mako version: {pins}"
    (pin,) = pins
    assert str(pin) in _pyproject_specifier()
    assert str(pin) in _base_in_specifier()


def test_installed_mako_meets_security_floor() -> None:
    assert Version(version("mako")) >= MAKO_SECURITY_FLOOR
