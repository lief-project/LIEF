from collections import defaultdict

import lief


def iterate() -> None:
    # lief-doc: iterate-start
    for region in lief.runtime.memory_layout():
        print(f"{region.addr:#014x}-{region.end_addr:#014x} {region.name}")
    # lief-doc: iterate-end


def inspect(address: int) -> None:
    # lief-doc: inspect-start
    address: int

    count = 0
    mapped = 0
    footprint: defaultdict[str, int] = defaultdict(int)
    enclosing: lief.runtime.MemoryLayout.Region | None = None

    for region in lief.runtime.memory_layout():
        count += 1
        mapped += region.size

        name = region.name if region.name else "<anonymous>"
        footprint[name] += region.size

        if region.contains(address):
            enclosing = region

    print(f"{count} regions, {mapped // 1024} KB mapped")

    for name, size in footprint.items():
        print(f"{size:#010x} {name}")

    if enclosing is not None:
        print(f"{address:#x}: {enclosing.name}+{address - enclosing.addr:#x}")
    # lief-doc: inspect-end


def stack_and_heap() -> None:
    # lief-doc: stack-heap-start
    for region in lief.runtime.memory_layout():
        # On Linux and Android, the kernel names the regions that back the
        # stack and the heap of the process.
        if region.name in ("[stack]", "[heap]"):
            print(f"{region.name}: {region.addr:#014x}-{region.end_addr:#014x}")
    # lief-doc: stack-heap-end
