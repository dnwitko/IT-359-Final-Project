# EscapeContainer

A tool that checks a running Docker container for misconfigurations that could let
an attacker break out of the container and reach the host.

## Purpose

Most container escapes don't require a clever exploit; they're possible because of
how the container was started: a `--privileged` flag, a mounted Docker socket, an
over-broad capability, a writable kernel path. EscapeContainer checks a running
container for these conditions and reports which ones are present and how serious
each one is.

Run it inside the container you want to check. It works through more than 100
known escape-related checks, grouped into 13 categories, and produces a report.
For each issue it finds, the report shows what it saw, why that issue could allow
an escape, and how to fix it.

It only reads and reports; it never tries to perform an escape and never changes
anything, so it is safe to run in environments where an actual exploit attempt
would not be acceptable.

## What it checks

Run `python3 src/escape_container.py --list-checks` to see every individual check.
At a high level they fall into these categories:

| Category | Count | Covers |
|----------|-------|--------|
| `capabilities` | 43 | Every Linux capability individually, plus the SYS_MODULE / SYS_ADMIN escape combinations |
| `devices` | 12 | Dangerous device files such as `/dev/mem`, `/dev/kmem`, `/dev/kcore`, and host disks |
| `proc_sys` | 9 | Writable kernel settings such as `core_pattern`, `modprobe`, and `uevent_helper` |
| `secret_files` | 8 | SSH keys, cloud credentials, kubeconfig, Docker config, shell history |
| `tooling` | 8 | Tools that help an attacker move around once inside (`nsenter`, `docker`, `kubectl`, `socat`, …) |
| `kernel_cve` | 7 | Kernel versions linked to known escape vulnerabilities (advisory) |
| `config` | 5 | Privileged mode, mounted Docker socket, running as root, writable root filesystem |
| `mac` | 4 | seccomp, AppArmor, SELinux, and `no_new_privs` protections |
| `kubernetes` | 4 | Mounted service-account token and related in-cluster access |
| `namespaces` | 3 | Sharing the host's process or network namespace |
| `mounts` | 2 | Sensitive host folders mounted into the container |
| `cgroups` | 1 | Writable cgroup `release_agent` |
| `secrets_env` | 1 | Secret-looking environment variables |

## Requirements

EscapeContainer runs on **Python 3.9 or newer** and uses only the Python standard
library. There are no required third-party packages.

The one optional extra is **colorama**, which adds color to the terminal output.
Without it, the tool still works fine and prints in plain text.

```bash
pip install -r requirements.txt   # optional: installs colorama for colored output
```

## Setup and running

Get the tool:

```bash
git clone https://github.com/dnwitko/IT-359-Final-Project.git
cd IT-359-Final-Project
```

If you're already inside the container you want to check, you can run it directly from the shell:

```bash
python3 src/escape_container.py
```

To check a container without copying the script into it first, mount the script when you start the container:

```bash
docker run --rm \
  -v "$PWD/src/escape_container.py:/audit.py:ro" \
  python:3.12-slim python3 /audit.py --no-color
```

The tool exits with code `0` if it finds no high- or critical-severity issues, and
`1` if it finds any.

## Usage examples

A full report:

```bash
python3 src/escape_container.py
```

Show only the most serious issues. A large or privileged container can trigger many
minor findings, so `--min-severity` limits the report to findings at or above a
chosen level, for example, only high and critical:

```bash
python3 src/escape_container.py --min-severity high
```

```
SUMMARY: 16 finding(s) at/above HIGH -> 7 CRITICAL, 9 HIGH  (+48 lower-severity hidden)
------------------------------------------------------------------------
1. [CRITICAL] Container appears to run in --privileged mode  (id: privileged_mode, cat: config)
   Evidence   : effective capability set is full; host block devices in /dev: vda, vdb, ...
   Why        : Privileged containers hold all capabilities and see host devices ...
   Remediation: Never use --privileged. Grant specific --cap-add and --device only as needed.
```

Save an HTML report you can open in a browser:

```bash
python3 src/escape_container.py --html report.html
```

Other options:

```bash
python3 src/escape_container.py --category capabilities   # run one category of checks
python3 src/escape_container.py --list-checks             # list every check without running
python3 src/escape_container.py --show-passed             # also show checks that passed
python3 src/escape_container.py --verbose                 # show every check as it runs
python3 src/escape_container.py --json                    # output as JSON
python3 src/escape_container.py -o report.txt             # save a plain-text report
```

## What it does and doesn't do

EscapeContainer checks how a container is configured. It does **not** scan for
vulnerabilities in the software running inside the container, it does **not**
attempt any exploit, and it does **not** change anything on the host or in the
container.

## License

MIT. See [LICENSE](LICENSE).
