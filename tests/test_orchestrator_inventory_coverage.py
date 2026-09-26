from quin_scanner.config import ScannerConfig
from quin_scanner.orchestrator import ScanOrchestrator
from quin_scanner.repo_accessor import LocalRepoAccessor


def test_scan_reports_complete_scanner_observations_and_coverage(tmp_path):
    source = tmp_path / "agent.py"
    source.write_text(
        'system_prompt = "You are an assistant that researches and summarizes topics."\n'
        'agent = Agent(name="researcher")\n'
    )
    config = ScannerConfig(
        enabled_scanners=["prompt_discovery", "agent_instance"],
        no_llm=True,
        vuln_check_enabled=False,
    )

    report = ScanOrchestrator().run(LocalRepoAccessor(tmp_path), config, verbose=False)

    assert {item["scanner_name"] for item in report.inventory} == {
        "PromptDiscoveryScanner", "AgentInstanceScanner"
    }
    assert report.coverage == {
        "files_discovered": 1,
        "files_indexed": 1,
        "files_excluded_vendor_or_generated": 0,
        "file_read_attempts": 3,
        "files_read": 1,
        "files_failed_to_read": 0,
        "scanners_enabled": 2,
        "scanners_completed": 2,
        "scanners_with_findings": 2,
    }
