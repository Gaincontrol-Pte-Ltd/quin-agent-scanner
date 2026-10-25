from __future__ import annotations

from collections.abc import Callable

from quin_scanner.models import SkillFinding
from quin_scanner.scanners.skills.bundle import SkillBundle

Analyzer = Callable[[SkillBundle], list[SkillFinding]]
