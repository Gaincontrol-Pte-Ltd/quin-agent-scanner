from quin_scanner.file_index import FileIndex
from quin_scanner.repo_accessor import LocalRepoAccessor


def test_coverage_counts_indexed_and_vendor_files(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "pkg.js").write_text("module.exports = {}")

    index = FileIndex(LocalRepoAccessor(tmp_path))
    index.build()

    assert index.coverage() == {
        "files_discovered": 2,
        "files_indexed": 1,
        "files_excluded_vendor_or_generated": 1,
    }
    assert index.all_files() == ["app.py"]
