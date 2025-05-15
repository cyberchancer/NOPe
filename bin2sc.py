#!/usr/bin/env python3
# File: bin2sc.py
# Purpose: Convert raw shellcode .bin files into embeddable source-code snippets (C arrays, C strings, Rust).
# Red Team Tradecraft: Automates payload embedding and staging, facilitating in-memory execution and obfuscation (T1027, T1105).
import sys
import os
import argparse


# Function: read_shellcode_file
# Description: Reads raw binary shellcode from disk, handling errors to ensure payload accessibility.
# Red Team Tradecraft: Validates and loads payloads for staging and embedding in various loaders (T1105).
def read_shellcode_file(filepath: str) -> bytes:
    """Read binary shellcode file."""
    try:
        with open(filepath, "rb") as file:
            return file.read()
    except IOError as e:
        print(f"[!] Error reading file '{filepath}': {e}")
        sys.exit(1)


# Function: format_shellcode
# Description: Transforms raw shellcode bytes into the specified source-code format (C array, C string, Rust).
# Red Team Tradecraft: Prepares payloads for diverse delivery methods and embedded execution, aiding evasion (T1027).
def format_shellcode(shellcode: bytes, style: str, name: str, bytes_per_line: int) -> str:
    """Format shellcode bytes in the selected output style."""
    if style == "c-array":
        hex_bytes = [f'0x{byte:02X}' for byte in shellcode]
        lines = []
        for i in range(0, len(hex_bytes), bytes_per_line):
            line = ', '.join(hex_bytes[i:i + bytes_per_line])
            lines.append(f'    {line}')
        return f'unsigned char {name}[] = {{\n' + ',\n'.join(lines) + '\n};'

    elif style == "c-string":
        hex_string = ''.join(f'\\x{byte:02X}' for byte in shellcode)
        return f'char {name}[] = "{hex_string}";'

    elif style == "rust":
        hex_bytes = [f'0x{byte:02X}' for byte in shellcode]
        lines = []
        for i in range(0, len(hex_bytes), bytes_per_line):
            line = ', '.join(hex_bytes[i:i + bytes_per_line])
            lines.append(f'    {line}')
        return f'let {name}: [u8; {len(shellcode)}] = [\n' + ',\n'.join(lines) + '\n];'

    else:
        print(f"[!] Unsupported style: {style}")
        sys.exit(1)


# Function: write_to_file
# Description: Writes formatted shellcode content to the specified file, with error handling for reliability.
# Red Team Tradecraft: Generates payload files for file-based staging or artifact delivery (T1105).
def write_to_file(output_path: str, content: str) -> None:
    """Write formatted shellcode to a file."""
    try:
        with open(output_path, 'w') as f:
            f.write(content)
        print(f"[+] Output written to: {output_path}")
    except IOError as e:
        print(f"[!] Error writing to file '{output_path}': {e}")
        sys.exit(1)


# Function: main
# Description: Parses command-line arguments and orchestrates conversion of shellcode to source-code formats.
# Red Team Tradecraft: Streamlines payload generation workflows for rapid staging and deployment (T1105, T1608).
def main():
    parser = argparse.ArgumentParser(
        description="Convert a raw shellcode .bin file to various source-code formats.",
        epilog="Examples:\n"
               "  python bin2sc.py shellcode.bin\n"
               "  python bin2sc.py shellcode.bin -s c-string -o sc.txt\n"
               "  python bin2sc.py shellcode.bin -s rust --name SHELLCODE\n",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("file", help="Path to shellcode .bin file")
    parser.add_argument("-o", "--output", help="Output file to write formatted shellcode")
    parser.add_argument("-s", "--style", choices=["c-array", "c-string", "rust"], default="c-array",
                        help="Output style (default: c-array)")
    parser.add_argument("--name", default="payload", help="Variable name to use (default: payload)")
    parser.add_argument("--bytes-per-line", type=int, default=16,
                        help="Bytes per line in output (default: 16)")

    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    shellcode = read_shellcode_file(args.file)
    formatted = format_shellcode(shellcode, args.style, args.name, args.bytes_per_line)

    if args.output:
        write_to_file(args.output, formatted)
    else:
        print("Formatted shellcode:")
        print(formatted)


if __name__ == "__main__":
    main()