
import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from enum import Enum
from pathlib import Path
from typing import Iterator


class DisassemblyFormat(Enum):
    INTEL = "intel"
    ATT = "att"


class ToolError(RuntimeError):
    pass


def executable(name):
    resolved = shutil.which(name)
    if not resolved:
        raise ToolError(f"Required executable not found: {name}")
    return resolved


def target_path(value):
    target = Path(value).expanduser()
    if not target.is_file():
        raise ToolError(f"Not a regular file: {target}")
    return target


def run_command(command, timeout=60):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False
        )
    except subprocess.TimeoutExpired as error:
        raise ToolError(
            f"Command timed out after {timeout} seconds: {command[0]}"
        ) from error
    except OSError as error:
        raise ToolError(str(error)) from error

    if result.returncode:
        message = (
            result.stderr.strip()
            or result.stdout.strip()
            or "Unknown error"
        )
        raise ToolError(
            f"{Path(command[0]).name} exited with "
            f"{result.returncode}: {message}"
        )

    return result.stdout


class ObjdumpDisassembler:
    def __init__(
        self,
        objdump_path="objdump",
        readelf_path="readelf",
        timeout=60
    ):
        self.objdump_path = executable(objdump_path)
        self.readelf_path = executable(readelf_path)
        self.timeout = timeout

    def objdump(self, path, *options):
        return run_command(
            [
                self.objdump_path,
                *options,
                "--",
                str(target_path(path))
            ],
            self.timeout
        )

    def readelf(self, path, *options):
        return run_command(
            [
                self.readelf_path,
                *options,
                "--",
                str(target_path(path))
            ],
            self.timeout
        )

    def disassemble(self, path, extra_args=None):
        return self.objdump(
            path,
            "-d",
            *(extra_args or [])
        )

    def disassemble_section(self, path, section):
        if not section or section.startswith("-"):
            raise ToolError("Invalid section name")

        return self.disassemble(
            path,
            [f"--section={section}"]
        )

    def disassemble_with_source(self, path):
        return self.disassemble(path, ["-S"])

    def disassemble_all_headers(self, path):
        return self.objdump(path, "-D")

    def disassemble_with_format(self, path, format):
        if not isinstance(format, DisassemblyFormat):
            raise ToolError("Invalid disassembly format")

        return self.disassemble(
            path,
            ["-M", format.value]
        )

    def disassemble_stream(
        self,
        path,
        extra_args=None
    ) -> Iterator[str]:
        output = self.disassemble(path, extra_args)
        yield from output.splitlines()

    def get_symbols(self, path):
        return parse_symbols(
            self.objdump(path, "-t")
        )

    def get_dynamic_symbols(self, path):
        return parse_symbols(
            self.objdump(path, "-T")
        )

    def compare_disassembly(self, path1, path2):
        first = self.disassemble(path1).splitlines()
        second = self.disassemble(path2).splitlines()

        return {
            "first": str(path1),
            "second": str(path2),
            "diff": list(
                difflib.unified_diff(
                    first,
                    second,
                    fromfile=str(path1),
                    tofile=str(path2),
                    lineterm=""
                )
            )
        }

    def disassemble_to_file(self, path, output_path):
        output = self.disassemble(path)
        Path(output_path).write_text(
            output,
            encoding="utf-8"
        )

    def disassemble_multiple(self, paths):
        results = {}

        for path in paths:
            try:
                results[str(path)] = self.disassemble(path)
            except ToolError as error:
                results[str(path)] = {
                    "error": str(error)
                }

        return results

    def get_program_headers(self, path):
        return parse_program_headers(
            self.readelf(path, "-W", "-l")
        )

    def analyze_binary_security(self, path):
        return analyze_binary_security(path, self)


def parse_symbols(output):
    symbols = []

    for line in output.splitlines():
        match = re.match(
            r"^\s*([0-9a-fA-F]+)\s+(.+?)\s*$",
            line
        )

        if not match:
            continue

        address, rest = match.groups()
        parts = rest.split()

        if len(parts) < 2:
            continue

        name = parts[-1]

        if name.startswith("*") and name.endswith("*"):
            continue

        symbols.append({
            "name": name,
            "address": "0x" + address.lower(),
            "details": rest
        })

    return symbols


def parse_program_headers(output):
    headers = []
    in_table = False

    for line in output.splitlines():
        if (
            line.strip().startswith("Type")
            and "Offset" in line
            and "VirtAddr" in line
        ):
            in_table = True
            continue

        if not in_table:
            continue

        if line.lstrip().startswith(
            "Section to Segment mapping"
        ):
            break

        parts = line.split()

        if len(parts) < 8 or not parts[1].startswith("0x"):
            continue

        headers.append({
            "type": parts[0],
            "offset": parts[1],
            "virtual_address": parts[2],
            "physical_address": parts[3],
            "file_size": parts[4],
            "memory_size": parts[5],
            "flags": " ".join(parts[6:-1]),
            "alignment": parts[-1]
        })

    return headers


def parse_elf_header(output):
    fields = {}

    for line in output.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()

    return fields


def feature(status, evidence):
    return {
        "status": status,
        "evidence": evidence
    }


def analyze_binary_security(
    path,
    disassembler=None
):
    tool = disassembler or ObjdumpDisassembler()

    header = parse_elf_header(
        tool.readelf(path, "-W", "-h")
    )

    program_text = tool.readelf(
        path,
        "-W",
        "-l"
    )

    program_headers = parse_program_headers(
        program_text
    )

    elf_type = header.get("Type", "")
    entry = header.get("Entry point address", "")

    has_interp = any(
        item["type"] == "INTERP"
        for item in program_headers
    )

    has_relro = any(
        item["type"] == "GNU_RELRO"
        for item in program_headers
    )

    stack = next(
        (
            item
            for item in program_headers
            if item["type"] == "GNU_STACK"
        ),
        None
    )

    try:
        dynamic = tool.readelf(
            path,
            "-W",
            "-d"
        )
    except ToolError as error:
        dynamic = ""
        dynamic_error = str(error)
    else:
        dynamic_error = None

    bind_now = bool(
        re.search(
            r"\(BIND_NOW\)|"
            r"\(FLAGS\).*\bBIND_NOW\b|"
            r"\(FLAGS_1\).*\bNOW\b",
            dynamic
        )
    )

    if stack is None:
        nx = feature(
            "unknown",
            "GNU_STACK program header not found"
        )
    elif "E" in stack["flags"].split():
        nx = feature(
            "disabled",
            "GNU_STACK requests executable stack"
        )
    elif "E" in stack["flags"]:
        nx = feature(
            "disabled",
            "GNU_STACK includes executable permission"
        )
    else:
        nx = feature(
            "enabled",
            "GNU_STACK does not request executable permission"
        )

    if elf_type.startswith("EXEC"):
        pie = feature(
            "disabled",
            "ET_EXEC executable"
        )
    elif elf_type.startswith("DYN") and has_interp:
        pie = feature(
            "enabled",
            "ET_DYN with program interpreter"
        )
    elif elf_type.startswith("DYN"):
        pie = feature(
            "unknown",
            "ET_DYN may be a shared object or static PIE"
        )
    else:
        pie = feature(
            "unknown",
            f"ELF type: {elf_type or 'unavailable'}"
        )

    if dynamic_error:
        relro = feature(
            "unknown",
            f"Dynamic section unavailable: {dynamic_error}"
        )
    elif has_relro and bind_now:
        relro = feature(
            "enabled",
            "GNU_RELRO and immediate binding detected"
        )
    elif has_relro:
        relro = feature(
            "partial",
            "GNU_RELRO present without immediate binding"
        )
    else:
        relro = feature(
            "disabled",
            "GNU_RELRO program header not found"
        )

    symbol_texts = []
    symbol_errors = []

    for flag in ("-t", "-T"):
        try:
            symbol_texts.append(
                tool.objdump(path, flag)
            )
        except ToolError as error:
            symbol_errors.append(str(error))

    if any(
        re.search(
            r"\b__stack_chk_fail(?:@|\b)",
            text
        )
        for text in symbol_texts
    ):
        canary = feature(
            "detected",
            "Reference to __stack_chk_fail found"
        )
    else:
        canary = feature(
            "unknown",
            "No __stack_chk_fail reference found; "
            "protection cannot be ruled out"
        )

    return {
        "file": str(target_path(path)),
        "elf_type": elf_type,
        "entry_point": entry,
        "nx": nx,
        "pie": pie,
        "relro": relro,
        "stack_canary": canary,
        "symbol_inspection_errors": symbol_errors
    }


def disassemble_bytes(
    code_bytes,
    architecture="i386:x86-64",
    objdump_path="objdump",
    timeout=60
):
    if not isinstance(code_bytes, bytes):
        raise ToolError("Raw code must be bytes")

    if not re.fullmatch(
        r"[A-Za-z0-9_:+.-]+",
        architecture
    ):
        raise ToolError("Invalid architecture")

    filename = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".bin",
            delete=False
        ) as temporary:
            filename = temporary.name
            temporary.write(code_bytes)

        return run_command(
            [
                executable(objdump_path),
                "-D",
                "-b",
                "binary",
                "-m",
                architecture,
                "--",
                filename
            ],
            timeout
        )
    finally:
        if filename is not None:
            os.unlink(filename)


def get_program_headers(path):
    return ObjdumpDisassembler().get_program_headers(
        path
    )


def json_output(data):
    print(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False
        )
    )


def build_parser():
    parser = argparse.ArgumentParser(
        description="Linux objdump and ELF inspection toolkit"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="objdump-py 2.0.0"
    )

    parser.add_argument(
        "--objdump",
        default="objdump"
    )

    parser.add_argument(
        "--readelf",
        default="readelf"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=60
    )

    sub = parser.add_subparsers(
        dest="command",
        required=True
    )

    def add_target(name, description):
        item = sub.add_parser(
            name,
            help=description
        )

        item.add_argument("file")
        item.add_argument(
            "--json",
            action="store_true"
        )

        return item

    disasm = add_target(
        "disasm",
        "Disassemble an ELF or object file"
    )

    disasm.add_argument(
        "--syntax",
        choices=["intel", "att"]
    )

    disasm.add_argument("--section")
    disasm.add_argument(
        "--source",
        action="store_true"
    )
    disasm.add_argument(
        "--all",
        action="store_true"
    )
    disasm.add_argument("--output")
    disasm.add_argument(
        "--max-lines",
        type=int,
        default=0
    )

    symbols = add_target(
        "symbols",
        "Inspect static or dynamic symbols"
    )

    symbols.add_argument(
        "--dynamic",
        action="store_true"
    )

    symbols.add_argument(
        "--limit",
        type=int,
        default=0
    )

    add_target(
        "security",
        "Analyze ELF hardening indicators"
    )

    add_target(
        "headers",
        "Inspect ELF program headers"
    )

    compare = sub.add_parser(
        "compare",
        help="Unified diff of disassembly"
    )

    compare.add_argument("first")
    compare.add_argument("second")
    compare.add_argument(
        "--json",
        action="store_true"
    )
    compare.add_argument("--output")

    raw = sub.add_parser(
        "raw",
        help="Disassemble hexadecimal machine code"
    )

    raw.add_argument("hex_bytes")

    raw.add_argument(
        "--architecture",
        default="i386:x86-64"
    )

    raw.add_argument(
        "--json",
        action="store_true"
    )

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    tool = ObjdumpDisassembler(
        args.objdump,
        args.readelf,
        args.timeout
    )

    if args.command == "disasm":
        options = []

        if args.all:
            options.append("-D")

        if args.source:
            options.append("-S")

        if args.syntax:
            options.extend([
                "-M",
                args.syntax
            ])

        if args.section:
            if args.section.startswith("-"):
                raise ToolError("Invalid section name")

            options.append(
                f"--section={args.section}"
            )

        output = tool.objdump(
            args.file,
            *(
                options
                if args.all
                else ["-d", *options]
            )
        )

        if args.max_lines < 0:
            raise ToolError(
                "--max-lines must not be negative"
            )

        if args.max_lines:
            output = (
                "\n".join(
                    output.splitlines()[:args.max_lines]
                )
                + "\n"
            )

        if args.output:
            Path(args.output).write_text(
                output,
                encoding="utf-8"
            )
        elif args.json:
            json_output({
                "file": args.file,
                "disassembly": output
            })
        else:
            print(output, end="")

    elif args.command == "symbols":
        if args.limit < 0:
            raise ToolError(
                "--limit must not be negative"
            )

        symbols = (
            tool.get_dynamic_symbols(args.file)
            if args.dynamic
            else tool.get_symbols(args.file)
        )

        if args.limit:
            symbols = symbols[:args.limit]

        if args.json:
            json_output({
                "file": args.file,
                "dynamic": args.dynamic,
                "symbols": symbols
            })
        else:
            for item in symbols:
                print(
                    f"{item['address']:>18}  "
                    f"{item['name']}"
                )

    elif args.command == "security":
        report = tool.analyze_binary_security(
            args.file
        )

        if args.json:
            json_output(report)
        else:
            print(f"File: {report['file']}")
            print(f"ELF type: {report['elf_type']}")
            print(f"Entry point: {report['entry_point']}")

            for name in (
                "nx",
                "pie",
                "relro",
                "stack_canary"
            ):
                result = report[name]

                print(
                    f"{name.upper():14} "
                    f"{result['status']:10} "
                    f"{result['evidence']}"
                )

    elif args.command == "headers":
        headers = tool.get_program_headers(
            args.file
        )

        if args.json:
            json_output({
                "file": args.file,
                "program_headers": headers
            })
        else:
            for item in headers:
                print(
                    f"{item['type']:15} "
                    f"{item['offset']:12} "
                    f"{item['virtual_address']:20} "
                    f"{item['flags']}"
                )

    elif args.command == "compare":
        report = tool.compare_disassembly(
            args.first,
            args.second
        )

        output = (
            json.dumps(report, indent=2)
            if args.json
            else "\n".join(report["diff"])
        )

        if args.output:
            Path(args.output).write_text(
                output + "\n",
                encoding="utf-8"
            )
        else:
            print(output)

    elif args.command == "raw":
        try:
            raw = bytes.fromhex(args.hex_bytes)
        except ValueError as error:
            raise ToolError(
                "Invalid hexadecimal bytes"
            ) from error

        output = disassemble_bytes(
            raw,
            args.architecture,
            args.objdump,
            args.timeout
        )

        if args.json:
            json_output({
                "architecture": args.architecture,
                "disassembly": output
            })
        else:
            print(output, end="")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ToolError, OSError) as error:
        print(
            f"Error: {error}",
            file=sys.stderr
        )
        sys.exit(1)
