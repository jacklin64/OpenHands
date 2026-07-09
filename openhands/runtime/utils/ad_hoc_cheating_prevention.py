from __future__ import annotations

import os
import re
import shlex

try:
    import bashlex
except ImportError:  # pragma: no cover - bashlex is an OpenHands dependency.
    bashlex = None


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
    (
        'git_remote',
        re.compile(r'\bgit\s+(clone|fetch|pull|ls-remote|remote\s+add)\b', re.I),
    ),
    ('web_download', re.compile(r'\b(curl|wget|aria2c)\b', re.I)),
    (
        'python_network',
        re.compile(r'\b(urllib\.request|requests\.get|httpx|aiohttp|http\.client)\b', re.I),
    ),
    (
        'package_download',
        re.compile(
            r'\b(pip|pip3|uv|poetry|conda|npm|yarn|pnpm|cargo|go)\b.*'
            r'\b(download|install|get|add|update)\b',
            re.I,
        ),
    ),
)
_SHELL_CMD_SEPARATOR = r'(?:^|(?<!\\)(?:&&|\|\||[;|])\s*)'
_SHELL_GIT_WRAPPER = (
    r'(?:(?:timeout\b(?:\s+--?[^\s]+)*\s+\S+\s+)|'
    r'(?:env\b(?:\s+(?:--?[^\s=]+|[A-Za-z_][A-Za-z0-9_]*=[^\s]+))*\s+)|'
    r'(?:command\b(?:\s+-[^\s]+)*\s+)|'
    r'(?:nice\b(?:\s+-n\s+\S+|\s+-\d+)?\s+)|'
    r'(?:stdbuf\b(?:\s+(?:-[ioe]\S*|--[^\s=]+(?:=\S+)?))*\s+)|'
    r'(?:nohup|unbuffer)\b\s+)*'
)
_SHELL_GIT_CMD_PREFIX = _SHELL_CMD_SEPARATOR + _SHELL_GIT_WRAPPER + r'git\s+'
_SHELL_GIT_COMMAND_RE = re.compile(_SHELL_GIT_CMD_PREFIX + r'([^\n;&|]*)', re.I)
_SHELL_COMMAND_RE = re.compile(_SHELL_CMD_SEPARATOR + r'([^\n;&|]+)', re.I)
_GIT_REMOTE_URL_ARG_RE = re.compile(r'^(?:https?://|ssh://|git@|[^/\s]+:[^/\s].*)', re.I)
_GIT_LOCAL_REMOTE_ARG_RE = re.compile(r'^(?:\.{1,2}(?:/|$)|/|file://)', re.I)
_PACKAGE_VERSION_SPLIT_RE = re.compile(r'(?<![<>=!~])(?:==|~=|>=|<=|>|<|=)')
_PACKAGE_NAME_CHARS_RE = re.compile(r'[^a-z0-9@._+:/-]+')
_PACKAGE_OPTION_VALUE_FLAGS = {
    '-c',
    '--constraint',
    '-f',
    '--find-links',
    '-i',
    '--index-url',
    '--extra-index-url',
    '--trusted-host',
    '-r',
    '--requirement',
    '--python',
    '--platform',
    '--implementation',
    '--abi',
    '--prefix',
    '--target',
    '-d',
    '--dest',
    '--destination-directory',
    '--cache-dir',
    '--src',
    '--root',
    '--upgrade-strategy',
    '--config-settings',
    '-C',
    '--global-option',
    '--install-option',
    '--group',
    '--source',
    '--registry',
    '--tag',
    '--branch',
    '--rev',
    '--path',
    '--git',
    '--features',
    '--bin',
    '--example',
    '--test',
    '--package',
    '--manifest-path',
    '--target-dir',
    '--version',
    '--artifact',
    '-Dartifact',
}
_PACKAGE_OPTION_VALUE_PREFIXES = (
    '--constraint=',
    '--find-links=',
    '--index-url=',
    '--extra-index-url=',
    '--trusted-host=',
    '--requirement=',
    '--python=',
    '--platform=',
    '--implementation=',
    '--abi=',
    '--prefix=',
    '--target=',
    '--dest=',
    '--destination-directory=',
    '--cache-dir=',
    '--src=',
    '--root=',
    '--upgrade-strategy=',
    '--config-settings=',
    '--global-option=',
    '--install-option=',
    '--group=',
    '--source=',
    '--registry=',
    '--tag=',
    '--branch=',
    '--rev=',
    '--path=',
    '--git=',
    '--features=',
    '--bin=',
    '--example=',
    '--test=',
    '--package=',
    '--manifest-path=',
    '--target-dir=',
    '--version=',
    '--artifact=',
    '-Dartifact=',
)
_LOCAL_PACKAGE_SPECS = {'.', './', '../'}


def ad_hoc_cheating_prevention_enabled() -> bool:
    value = os.environ.get('OPENHANDS_AD_HOC_CHEATING_PREVENTION', '')
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


def _blocked_package_names() -> set[str]:
    raw = os.environ.get('OPENHANDS_AD_HOC_BLOCKED_PACKAGE_NAMES', '')
    return {
        normalized
        for value in re.split(r'[\s,;]+', raw)
        if (normalized := _normalize_package_name(value))
    }


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


def _iter_shell_commands(shell: str) -> list[list[str]]:
    commands: list[list[str]] = []
    commands.extend(_iter_bashlex_shell_commands(shell))
    for match in _SHELL_COMMAND_RE.finditer(shell):
        args = _shlex_split_best_effort(match.group(1))
        if args:
            commands.append(args)
    if not commands:
        args = _shlex_split_best_effort(shell)
        if args:
            commands.append(args)
    return commands


def _iter_bashlex_shell_commands(shell: str) -> list[list[str]]:
    if bashlex is None:
        return []
    try:
        nodes = list(bashlex.parse(shell))
    except (
        bashlex.errors.ParsingError,
        NotImplementedError,
        TypeError,
        AttributeError,
    ):
        return []

    commands: list[list[str]] = []

    def visit(node) -> None:
        if getattr(node, 'kind', None) == 'command':
            words = [
                shell[part.pos[0] : part.pos[1]]
                for part in getattr(node, 'parts', [])
                if getattr(part, 'kind', None) == 'word'
            ]
            if words:
                args = _shlex_split_best_effort(' '.join(words))
                if args:
                    commands.append(args)
        for part in getattr(node, 'parts', []):
            visit(part)
        for attr in ('command', 'list'):
            child = getattr(node, attr, None)
            if child is None:
                continue
            if isinstance(child, list):
                for item in child:
                    visit(item)
            else:
                visit(child)

    for node in nodes:
        visit(node)
    return commands


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


def _strip_common_launch_wrappers(args: list[str]) -> list[str]:
    args = list(args)
    while args:
        cmd = os.path.basename(args[0]).lower()
        if cmd in {'do', 'then'}:
            args = args[1:]
            continue
        if cmd == 'timeout':
            i = 1
            while i < len(args) and args[i].startswith('-'):
                option = args[i]
                i += 1
                if option in {'-k', '--kill-after', '-s', '--signal'} and i < len(args):
                    i += 1
            if i < len(args):
                i += 1
            args = args[i:]
            continue
        if cmd == 'env':
            i = 1
            while i < len(args):
                arg = args[i]
                if arg == '--':
                    i += 1
                    break
                if re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', arg):
                    i += 1
                    continue
                if arg.startswith('-'):
                    i += 1
                    continue
                break
            args = args[i:]
            continue
        if cmd == 'command':
            i = 1
            while i < len(args) and args[i].startswith('-'):
                i += 1
            args = args[i:]
            continue
        if cmd == 'nice':
            i = 1
            if i < len(args) and args[i] == '-n':
                i += 2
            elif i < len(args) and re.match(r'^-\d+$', args[i]):
                i += 1
            args = args[i:]
            continue
        if cmd == 'stdbuf':
            i = 1
            while i < len(args) and (
                re.match(r'^-[ioe]', args[i]) or args[i].startswith('--')
            ):
                i += 1
            args = args[i:]
            continue
        if cmd in {'nohup', 'unbuffer'}:
            args = args[1:]
            continue
        break
    return args


def _normalize_package_name(value: str | None) -> str:
    if not value:
        return ''
    value = value.strip().strip('"\'')
    if not value:
        return ''
    value = value.split('#', 1)[0]
    if '://' in value or value.startswith(('git+', 'file:')):
        value = value.rstrip('/').rsplit('/', 1)[-1]
    if value.endswith(('.git', '.tar.gz', '.zip', '.whl', '.tgz')):
        for suffix in ('.tar.gz', '.git', '.zip', '.whl', '.tgz'):
            if value.endswith(suffix):
                value = value[: -len(suffix)]
                break
    if value.startswith('@'):
        version_index = value.find('@', 1)
        if version_index != -1:
            value = value[:version_index]
    elif '@' in value:
        value = value.split('@', 1)[0]
    if '/' in value and ':' in value:
        value = value.split(':', 1)[0]
    elif value.count(':') >= 2:
        value = ':'.join(value.split(':')[:2])
    value = _PACKAGE_VERSION_SPLIT_RE.split(value, 1)[0]
    value = value.split('[', 1)[0]
    value = value.strip()
    if not value or value in _LOCAL_PACKAGE_SPECS:
        return ''
    value = _PACKAGE_NAME_CHARS_RE.sub('', value.lower())
    value = value.strip('/._-')
    return value.replace('_', '-')


def _package_matches_blocked(spec: str, blocked: set[str]) -> bool:
    normalized = _normalize_package_name(spec)
    if not normalized:
        return False
    if normalized in blocked:
        return True
    for name in blocked:
        if '/' not in name:
            continue
        if normalized == name or normalized.startswith(f'{name}/'):
            return True
        if not name.startswith('github.com/') and (
            normalized == f'github.com/{name}'
            or normalized.startswith(f'github.com/{name}/')
        ):
            return True
        if normalized == name.rsplit('/', 1)[-1]:
            return True
    return False


def _iter_explicit_package_args(args: list[str], start: int = 0):
    i = start
    while i < len(args):
        arg = args[i]
        if arg == '--':
            yield from args[i + 1 :]
            return
        if any(arg.startswith(prefix) for prefix in _PACKAGE_OPTION_VALUE_PREFIXES):
            i += 1
            continue
        if arg in _PACKAGE_OPTION_VALUE_FLAGS:
            i += 2
            continue
        if _is_shell_redirection_arg(arg):
            i += 1
            continue
        if arg.startswith('-'):
            i += 1
            continue
        if arg not in _LOCAL_PACKAGE_SPECS and not _GIT_LOCAL_REMOTE_ARG_RE.search(arg):
            yield arg
        i += 1


def _has_blocked_package_request(shell: str) -> bool:
    blocked = _blocked_package_names()
    if not blocked:
        return False
    for args in _iter_shell_commands(shell):
        raw_args = args
        args = _strip_common_launch_wrappers(args)
        if not args:
            continue
        cmd = os.path.basename(args[0]).lower()
        if cmd in {'bash', 'sh'}:
            for flag in ('-c', '-lc'):
                if flag in args:
                    i = args.index(flag)
                    if i + 1 < len(args) and _has_blocked_package_request(args[i + 1]):
                        return True
            args = _strip_common_launch_wrappers(raw_args)
            cmd = os.path.basename(args[0]).lower() if args else ''
        if cmd in {'python', 'python3'} and len(args) >= 4 and args[1:3] == ['-m', 'pip']:
            cmd = 'pip'
            args = ['pip', *args[3:]]
        if cmd in {'pip', 'pip3'} and len(args) >= 2:
            if args[1] in {'install', 'download'}:
                if any(
                    _package_matches_blocked(arg, blocked)
                    for arg in _iter_explicit_package_args(args, 2)
                ):
                    return True
        elif cmd == 'uv' and len(args) >= 3:
            start = 3 if args[1] == 'pip' and args[2] in {'install', 'download'} else None
            if start and any(
                _package_matches_blocked(arg, blocked)
                for arg in _iter_explicit_package_args(args, start)
            ):
                return True
        elif cmd in {'npm', 'yarn', 'pnpm'} and len(args) >= 2:
            action = args[1]
            if action in {'install', 'i', 'add', 'update'}:
                explicit_start = 2
                if action in {'install', 'i'} and not list(
                    _iter_explicit_package_args(args, explicit_start)
                ):
                    continue
                if any(
                    _package_matches_blocked(arg, blocked)
                    for arg in _iter_explicit_package_args(args, explicit_start)
                ):
                    return True
        elif cmd in {'gem', 'bundle', 'bundler'} and len(args) >= 2:
            if args[1] in {'install', 'add', 'update'}:
                if any(
                    _package_matches_blocked(arg, blocked)
                    for arg in _iter_explicit_package_args(args, 2)
                ):
                    return True
        elif cmd == 'composer' and len(args) >= 2:
            if args[1] in {'require', 'update'}:
                if any(
                    _package_matches_blocked(arg, blocked)
                    for arg in _iter_explicit_package_args(args, 2)
                ):
                    return True
        elif cmd == 'cargo' and len(args) >= 2:
            if args[1] in {'add', 'install'}:
                if any(
                    _package_matches_blocked(arg, blocked)
                    for arg in _iter_explicit_package_args(args, 2)
                ):
                    return True
        elif cmd == 'go' and len(args) >= 2:
            if args[1] in {'get', 'install'}:
                if any(
                    _package_matches_blocked(arg, blocked)
                    for arg in _iter_explicit_package_args(args, 2)
                ):
                    return True
        elif cmd in {'mvn', 'mvnw'}:
            for arg in args[1:]:
                if arg.startswith('-Dartifact='):
                    artifact = arg.split('=', 1)[1]
                    if _package_matches_blocked(artifact, blocked) or any(
                        _package_matches_blocked(part, blocked)
                        for part in artifact.split(':')[:2]
                    ):
                        return True
        elif cmd in {'gradle', 'gradlew'} and any(
            _package_matches_blocked(arg, blocked) for arg in _iter_explicit_package_args(args, 1)
        ):
            return True
        elif cmd in {'conda', 'mamba'} and len(args) >= 2:
            if args[1] in {'install', 'update'}:
                if any(
                    _package_matches_blocked(arg, blocked)
                    for arg in _iter_explicit_package_args(args, 2)
                ):
                    return True
    return False


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
    if _has_blocked_package_request(shell):
        return True
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
