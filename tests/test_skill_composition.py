"""Tests for skill composition DAG and curator."""

from pathlib import Path

import pytest

from js.skills.composer import CompositionNode, SkillComposer
from js.skills.curator import SkillCurator
from js.skills.spec import SkillSpec, SkillType, TrustLevel


class TestSkillComposer:
    @pytest.fixture
    def composer(self, tmp_path: Path) -> SkillComposer:
        return SkillComposer(tmp_path)

    def test_create_chain(self, composer: SkillComposer) -> None:
        chain = composer.create_chain(
            "Test Chain",
            "A test composition",
            [
                CompositionNode(skill_id="skill_a"),
                CompositionNode(skill_id="skill_b", args_mapping={"input": "output"}),
            ],
        )
        assert chain.id.startswith("chain_")
        assert len(chain.steps) == 2

    def test_record_transition(self, composer: SkillComposer) -> None:
        composer.record_transition("skill_a", "skill_b", "session_1")
        composer.record_transition("skill_a", "skill_b", "session_2")
        composer.record_transition("skill_a", "skill_b", "session_3")

    def test_discover_chains(self, composer: SkillComposer) -> None:
        for i in range(5):
            composer.record_transition("skill_a", "skill_b", f"session_{i}")
        discovered = composer.discover_chains(min_frequency=3)
        assert len(discovered) >= 1

    def test_list_chains(self, composer: SkillComposer) -> None:
        composer.create_chain("Chain 1", "Desc", [CompositionNode(skill_id="s1")])
        chains = composer.list_chains()
        assert len(chains) >= 1
        assert chains[0]["name"] == "Chain 1"

    def test_record_chain_result(self, composer: SkillComposer) -> None:
        chain = composer.create_chain("Test", "Desc", [CompositionNode(skill_id="s1")])
        composer.record_chain_result(chain.id, True)
        composer.record_chain_result(chain.id, False)

    def test_build_meta_skill_spec(self, composer: SkillComposer) -> None:
        chain = composer.create_chain("Meta", "Meta skill", [CompositionNode(skill_id="s1")])
        spec = composer.build_meta_skill_spec(chain)
        assert spec.type == SkillType.META
        assert spec.dependencies == ["s1"]


class TestSkillCurator:
    @pytest.fixture
    def curator(self, tmp_path: Path) -> SkillCurator:
        return SkillCurator(tmp_path)

    def test_should_run(self, curator: SkillCurator) -> None:
        assert curator.should_run(interval_seconds=0)  # Always run with 0 interval
        curator._last_run = __import__("time").time()
        assert not curator.should_run(interval_seconds=3600)

    def test_curate_empty(self, curator: SkillCurator) -> None:
        report = curator.curate({}, force=True)
        assert report["total_skills"] == 0

    def test_curate_healthy_skills(self, curator: SkillCurator) -> None:
        skills = {
            "skill_1": SkillSpec(id="skill_1", name="Skill 1", trust_level=TrustLevel.BUILTIN),
        }
        report = curator.curate(skills, force=True)
        assert report["healthy"] == 1

    def test_find_duplicates(self, curator: SkillCurator) -> None:
        skills = {
            "skill_a": SkillSpec(id="skill_a", name="My Skill"),
            "skill_b": SkillSpec(id="skill_b", name="My Skill"),  # Same normalized name
        }
        report = curator.curate(skills, force=True)
        assert report["duplicates"] >= 1

    def test_promote_skills(self, curator: SkillCurator) -> None:
        import sqlite3
        # Create skills DB with usage records
        db_path = curator.db_path
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS skill_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    skill_id TEXT NOT NULL,
                    skill_type TEXT,
                    success INTEGER NOT NULL,
                    latency_ms REAL NOT NULL,
                    used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            for _ in range(25):
                conn.execute(
                    "INSERT INTO skill_usage (skill_id, skill_type, success, latency_ms) VALUES (?, ?, ?, ?)",
                    ("good_skill", "code", 1, 100.0),
                )
            conn.commit()

        skills = {
            "good_skill": SkillSpec(id="good_skill", name="Good Skill", trust_level=TrustLevel.COMMUNITY),
        }
        report = curator.curate(skills, force=True)
        assert skills["good_skill"].trust_level == TrustLevel.TRUSTED
        assert any(a["action"] == "promoted_to_trusted" for a in report["actions_taken"])

    def test_quarantine_underperforming(self, curator: SkillCurator) -> None:
        import sqlite3
        import time
        db_path = curator.db_path
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS skill_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    skill_id TEXT NOT NULL,
                    skill_type TEXT,
                    success INTEGER NOT NULL,
                    latency_ms REAL NOT NULL,
                    used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            for _ in range(10):
                conn.execute(
                    "INSERT INTO skill_usage (skill_id, skill_type, success, latency_ms, used_at) VALUES (?, ?, ?, ?, ?)",
                    ("bad_skill", "code", 0, 100.0, time.strftime("%Y-%m-%d %H:%M:%S")),
                )
            conn.commit()

        skills = {
            "bad_skill": SkillSpec(id="bad_skill", name="Bad Skill", trust_level=TrustLevel.COMMUNITY),
        }
        report = curator.curate(skills, force=True)
        assert skills["bad_skill"].trust_level == TrustLevel.QUARANTINE
        assert any(a["action"] == "quarantined" for a in report["actions_taken"])
