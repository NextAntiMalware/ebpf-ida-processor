# eBPF IDA Processor

Generic eBPF (ELF machine type 247, EM_BPF) processor module for IDA Pro.

Derived from the open-source `solana-ebpf-ida-processor` project with all
Solana-specific features removed:

- `BPF_PQR` class opcodes (lmul/uhmul/udiv/urem/shmul/sdiv/srem)
- `BPF_HOR` opcode
- `R_BPF_64_RELATIVE` relocation
- `sol_*` syscall recognition in the disassembly output
- `.data.rel.ro` Rust `{ptr, len}` string reference resolution
- `rust_demangler` dependency

## Installation

1. Copy `ebpf-init.py` into IDA's `procs/` directory.
2. Copy the `ebpf/` package folder into `procs/` (same level as `ebpf-init.py`).
3. Restart IDA. Load any eBPF ELF file (e.g. `clang -target bpf` output).
   IDA will select the `eBPF` processor automatically.

Final layout:

    <IDA>/procs/
    |- ebpf.py
    \- ebpf/
       |- __init__.py
       |- config.py
       |- constants.py
       |- helpers.py
       |- processor.py
       |- relocations.py
       \- strings.py

## Dependencies

- IDA Pro 7.x / 8.x / 9.x
- `pyelftools` (bundled with IDA, or `pip install pyelftools`)

## License

The original `processor.py` carries the Beer-Ware license, retained here.
