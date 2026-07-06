from __future__ import annotations

import os
import re
import shlex


BLOCKED_COMMAND_MESSAGE = (
    'We cannot execute the commands which potentially leak the solutions.'
)

_URL_RE = re.compile(r'https?://([^/"\'\s)]+)', re.IGNORECASE)
_BENIGN_NETWORK_HOSTS = {
    '127.0.0.1',
    'localhost',
    '0.0.0.0',
    '::1',
    'example.com',
    '.example.com',
    'sub.example.com',
}
_CHEAT_LOOKUP_HOST_RE = re.compile(
    r'(^|\.)(github\.com|raw\.githubusercontent\.com|api\.github\.com|'
    r'gitlab\.com|bitbucket\.org|stackoverflow\.com|stackexchange\.com|'
    r'pypi\.org|files\.pythonhosted\.org|readthedocs\.io|readthedocs\.org)$',
    re.I,
)
_CHEAT_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ('git_remote', re.compile(r'\bgit\s+(clone|fetch|pull|ls-remote|remote\s+add)\b', re.I)),
    ('web_download', re.compile(r'\b(curl|wget|aria2c)\b', re.I)),
    ('python_network', re.compile(r'\b(urllib\.request|requests\.get|httpx|aiohttp|http\.client)\b', re.I)),
    ('package_download', re.compile(r'\b(pip|pip3|uv|poetry|conda|npm|yarn|pnpm|cargo|go)\b.*\b(download|install|get|add|update)\b', re.I)),
)
_SHELL_GIT_CMD_PREFIX = r'(?:^|(?<!\\)(?:&&|\|\||[;|])\s*)git\s+'
_SHELL_GIT_COMMAND_RE = re.compile(_SHELL_GIT_CMD_PREFIX + r'([^\n;&|]*)', re.I)
_GIT_REMOTE_URL_ARG_RE = re.compile(r'^(?:https?://|ssh://|git@|[^/\s]+:[^/\s].*)', re.I)
_GIT_LOCAL_REMOTE_ARG_RE = re.compile(r'^(?:\.{1,2}(?:/|$)|/|file://)', re.I)


def ad_hoc_cheating_prevention_enabled() -> bool:
    value = os.environ.get('OPENHANDS_AD_HOC_CHEATING_PREVENTION', '')
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


def _external_urls_from_text(text: str) -> list[str]:
    hosts: list[str] = []
    for match in _URL_RE.finditer(text or ''):
        host = match.group(1).split(':', 1)[0].lower().strip('[]')
        host_ascii = _idna_host(host)
        host_cmp = host_ascii or host
        if host_cmp.startswith('.'):
            host_cmp = host_cmp[1:]
        if (
            host_cmp
            and host_cmp not in _BENIGN_NETWORK_HOSTS
            and not host_cmp.endswith('.example.com')
        ):
            hosts.append(host)
    return hosts


def _idna_host(host: str) -> str:
    try:
        return host.encode('idna').decode('ascii')
    except UnicodeError:
        return host


def _has_cheat_lookup_host(hosts: list[str]) -> bool:
    for host in hosts:
        host_ascii = _idna_host(host)
        if _CHEAT_LOOKUP_HOST_RE.search(host_ascii or host):
            return True
    return False


def _shlex_split_best_effort(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def _is_shell_redirection_arg(arg: str) -> bool:
    return bool(re.match(r'^\d*(?:<>|>>|>|<|&>|>\&|<\&)', arg))


def _first_non_option_arg(args: list[str], start: int = 0) -> str | None:
    i = start
    while i < len(args):
        arg = args[i]
        if arg == '--':
            return args[i + 1] if i + 1 < len(args) else None
        if _is_shell_redirection_arg(arg):
            i += 1
            continue
        if not arg.startswith('-'):
            return arg
        if arg in {
            '-b',
            '--branch',
            '-o',
            '--origin',
            '--depth',
            '--shallow-since',
            '--shallow-exclude',
            '-c',
            '-j',
            '--jobs',
        }:
            i += 2
        else:
            i += 1
    return None


def _is_remote_git_arg(arg: str | None) -> bool:
    if not arg or _GIT_LOCAL_REMOTE_ARG_RE.search(arg):
        return False
    return bool(_GIT_REMOTE_URL_ARG_RE.search(arg))


def _is_named_git_remote(arg: str | None) -> bool:
    if not arg or _is_remote_git_arg(arg) or _GIT_LOCAL_REMOTE_ARG_RE.search(arg):
        return False
    return bool(re.match(r'^[A-Za-z0-9._-]+$', arg))


def _has_git_remote_lookup(shell: str) -> bool:
    for match in _SHELL_GIT_COMMAND_RE.finditer(shell):
        args = _shlex_split_best_effort(match.group(1))
        if not args:
            continue
        subcmd = args[0].lower()
        if subcmd in {'clone', 'ls-remote'}:
            if _is_remote_git_arg(_first_non_option_arg(args, 1)):
                return True
            continue
        if subcmd in {'fetch', 'pull'}:
            remote = _first_non_option_arg(args, 1)
            if remote is None or _is_remote_git_arg(remote) or _is_named_git_remote(remote):
                return True
            continue
        if subcmd == 'remote' and len(args) >= 3 and args[1].lower() == 'add':
            if _is_remote_git_arg(args[3] if len(args) >= 4 else None):
                return True
    return False


def command_has_cheating_signal(shell: str) -> bool:
    if not shell or not isinstance(shell, str):
        return False
    external_hosts = _external_urls_from_text(shell)
    has_lookup_host = _has_cheat_lookup_host(external_hosts)
    for label, pattern in _CHEAT_COMMAND_PATTERNS:
        if not pattern.search(shell):
            continue
        if label == 'git_remote':
            if _has_git_remote_lookup(shell):
                return True
            continue
        if label in {'web_download', 'python_network', 'package_download'}:
            if has_lookup_host:
                return True
    return False
