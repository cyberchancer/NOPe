# NOPe

A flexible Python payload execution toolkit that prepends randomized NOP sleds to shellcode for obfuscation and executes it in memory.

> **Tradecraft Note:** Demonstrates NOP sled obfuscation (MITRE ATT&CK T1027) and in-memory shellcode execution (T1059) to bypass detection.

## Prerequisites

- Python 3.6 or higher (use 32-bit for x86, 64-bit for x64)
- No external dependencies; uses built-in `ctypes`, `mmap`, and `argparse`

## Features

- Dual-architecture support: x86 and x64 shellcode
- Randomized NOP sled variants to evade static analysis (T1027)
- In-memory shellcode execution to minimize disk artifacts (T1059)
- Enumeration and selection of NOP variants for tailored payload crafting

## Tradecraft & MITRE ATT&CK Mapping

| Technique ID | Technique Name                      | Description                                            |
|--------------|-------------------------------------|--------------------------------------------------------|
| T1027        | Obfuscated Files or Information     | Prepends randomized NOP-like instructions to payload    |
| T1059        | Command and Scripting Interpreter   | Executes payload in memory without dropping to disk    |

## Usage

```bash
# Execute default x64 messagebox payload
python3 windows_NOPe.py

# Execute custom shellcode (verbose)
python3 windows_NOPe.py -f my_windows_shellcode.bin --arch x64 --verbose
python3 unix_NOPe.py -f my_unix_shellcode.bin --arch x64 --verbose

# List available NOP variants
python3 NOPe.py --arch x64 --list-nops
```

## Generating Shellcode

```bash
# x64 windows messagebox via MSFVenom
msfvenom -p windows/x64/messagebox TEXT="NOPe64" TITLE="Hello" -f raw > windows-msgbox.x64.bin

# x86 windows messagebox via MSFVenom
msfvenom -p windows/messagebox TEXT="NOPe32" TITLE="Hello" -f raw > windows-msgbox.x86.bin

# x64 linux via MSFVenom 
msfvenom -p linux/x64/exec CMD="echo 'Hello with NOPe64'" -f raw > linux-msgprint.x64.bin

# x86 linux via MSFVenom 
msfvenom -p linux/x86/exec CMD="echo 'Hello with NOPe32'" -f raw > linux-msgprint.x64.bin
```

## bin2sc

A helper script to convert raw shellcode binaries into source-code snippets.

> **Tradecraft Note:** Facilitates payload embedding and staging across diverse delivery mechanisms (T1105, T1027).

## Usage

```bash
# Print as C array
python3 bin2sc.py shellcode.bin

# Write to file
python3 bin2sc.py shellcode.bin -o output.h

# Alternate styles: c-string or rust
python3 bin2sc.py shellcode.bin -s c-string
python3 bin2sc.py shellcode.bin -s rust

# Customize variable name and bytes per line
python3 bin2sc.py shellcode.bin --name mypayload --bytes-per-line 8
```

## Example Output

```c
unsigned char payload[] = {
    0x90, 0x90, 0xCC, 0xCC, 0xEB, 0xFE
};
```

## Changelog

- Reorganized README structure; added Installation section and removed duplicate content.
- Reordered sections for clarity and consistency.
