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
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'cd /tmp/djg && timeout 120 git fetch --depth 200 origin 2>&1 '
        '| tail -3; git log --oneline --all | wc -l'
    )
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'cd /tmp/sphinx_git && timeout 300 git fetch '
        '--shallow-since="2021-06-01" origin 2>&1 | tail -3; '
        'git log --oneline --all --since="2021-07-01" | head'
    )
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'cd /tmp/django_ref && timeout 180 git fetch --deepen=8000 '
        'origin 2>&1 | tail -2; git log --all | tail -3'
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
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'nice -n 10 timeout --preserve-status 30 git ls-remote '
        'https://github.com/django/django.git'
    )


def test_allows_local_git_history_inspection_without_remote_lookup():
    assert not ad_hoc_cheating_prevention.command_has_cheating_signal(
        'git show 67faffbc:astropy/io/ascii/rst.py | head -180'
    )
    assert not ad_hoc_cheating_prevention.command_has_cheating_signal(
        'git log --oneline -S "test_rst_with_header_rows" | head'
    )


def test_blocks_python_target_package_downloads(monkeypatch):
    monkeypatch.setenv(
        'OPENHANDS_AD_HOC_BLOCKED_PACKAGE_NAMES', 'django,scikit-learn,sklearn'
    )

    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'cd /tmp && pip download django==4.2 --no-deps --no-binary :all:'
    )
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'python -m pip install "Django>=4.0"'
    )
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'timeout 30 uv pip install scikit_learn==1.4.0'
    )
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'conda install -y sklearn'
    )


def test_allows_python_dependency_setup_without_target_package(monkeypatch):
    monkeypatch.setenv('OPENHANDS_AD_HOC_BLOCKED_PACKAGE_NAMES', 'django')

    assert not ad_hoc_cheating_prevention.command_has_cheating_signal(
        'pip install -e .'
    )
    assert not ad_hoc_cheating_prevention.command_has_cheating_signal(
        'pip install -r requirements.txt'
    )
    assert not ad_hoc_cheating_prevention.command_has_cheating_signal(
        'pip install pytest'
    )


def test_blocks_multilingual_target_package_requests(monkeypatch):
    monkeypatch.setenv(
        'OPENHANDS_AD_HOC_BLOCKED_PACKAGE_NAMES',
        '@babel/core,laravel/framework,github.com/caddyserver/caddy/v2,'
        'tokio,org.projectlombok:lombok',
    )

    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'npm install @babel/core@latest'
    )
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'composer require laravel/framework:^11'
    )
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'go install github.com/caddyserver/caddy/v2/cmd/caddy@latest'
    )
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'cargo add tokio --features full'
    )
    assert ad_hoc_cheating_prevention.command_has_cheating_signal(
        'mvn dependency:get -Dartifact=org.projectlombok:lombok:1.18.30'
    )


def test_allows_multilingual_dependency_setup_without_target_package(monkeypatch):
    monkeypatch.setenv(
        'OPENHANDS_AD_HOC_BLOCKED_PACKAGE_NAMES',
        'axios,fastlane,phpoffice/phpspreadsheet,tokio',
    )

    assert not ad_hoc_cheating_prevention.command_has_cheating_signal('npm install')
    assert not ad_hoc_cheating_prevention.command_has_cheating_signal(
        'bundle install'
    )
    assert not ad_hoc_cheating_prevention.command_has_cheating_signal(
        'composer install'
    )
    assert not ad_hoc_cheating_prevention.command_has_cheating_signal('cargo fetch')
    assert not ad_hoc_cheating_prevention.command_has_cheating_signal(
        'go mod download'
    )
