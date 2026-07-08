import importlib.util
from pathlib import Path


def _load_ad_hoc_cheating_prevention():
    module_path = (
        Path(__file__).parents[2]
        / 'openhands'
        / 'runtime'
        / 'utils'
        / 'ad_hoc_cheating_prevention.py'
    )
    spec = importlib.util.spec_from_file_location(
        'ad_hoc_cheating_prevention', module_path
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ad_hoc_cheating_prevention = _load_ad_hoc_cheating_prevention()


def test_blocks_remote_git_commands_wrapped_by_timeout():
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'cd /workspace/repo && timeout 20 git ls-remote '
        'https://github.com/astropy/astropy.git HEAD 2>&1 | tail -5'
    )
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'cd /tmp && timeout 60 git clone --depth 1 '
        'https://github.com/astropy/astropy.git astro_ref'
    )
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'cd /workspace/repo && timeout 90 git fetch '
        'https://github.com/django/django.git '
        'stable/3.0.x:refs/remotes/origin/stable/3.0.x'
    )


def test_blocks_remote_git_commands_wrapped_by_common_launchers():
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'env GIT_TERMINAL_PROMPT=0 git clone https://github.com/django/django.git'
    )
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'command git fetch origin'
    )
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'stdbuf -oL git pull upstream main'
    )


def test_allows_local_git_history_inspection_without_remote_lookup():
    assert not ad_hoc_cheating_prevention.command_has_cheating_signal(
        'git show 67faffbc:astropy/io/ascii/rst.py | head -180'
    )
    assert not ad_hoc_cheating_prevention.command_has_cheating_signal(
        'git log --oneline -S "test_rst_with_header_rows" | head'
    )
