"""Emulate copied ARM64 library functions locally, with no network or OS access.

JNI strings and a small set of libc memory functions are represented in isolated
Unicorn memory. Any unsupported external call fails instead of reaching the host.
"""
import io
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X30, UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_TPIDR_EL0,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
)


class Native:
    BASE = 0x10000000
    HEAP = 0x20000000
    STACK = 0x30000000
    STUB = 0x40000000

    def __init__(self, path):
        self.elf = ELFFile(io.BytesIO(Path(path).read_bytes()))
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.symbols = {}
        self.hooks = {}
        self.next_heap = self.HEAP
        self.next_stub = self.STUB + 0x100
        end = max(s["p_vaddr"] + s["p_memsz"] for s in self.elf.iter_segments()
                  if s["p_type"] == "PT_LOAD")
        self.uc.mem_map(self.BASE, (end + 4095) & ~4095)
        for s in self.elf.iter_segments():
            if s["p_type"] == "PT_LOAD":
                self.uc.mem_write(self.BASE + s["p_vaddr"], s.data())
        for address, size in [(self.HEAP, 0x1000000), (self.STACK, 0x100000),
                              (self.STUB, 0x100000)]:
            self.uc.mem_map(address, size)
        dyn = self.elf.get_section_by_name(".dynsym")
        for sym in dyn.iter_symbols():
            if sym["st_value"]:
                self.symbols[sym.name] = self.BASE + sym["st_value"]
        imports = {}
        for section in self.elf.iter_sections():
            if section["sh_type"] != "SHT_RELA":
                continue
            for rel in section.iter_relocations():
                kind = rel["r_info_type"]
                if kind == 1027:  # AArch64 RELATIVE
                    value = self.BASE + rel["r_addend"]
                elif kind in (257, 1025, 1026):
                    sym = dyn.get_symbol(rel["r_info_sym"])
                    if sym["st_value"]:
                        value = self.BASE + sym["st_value"] + rel["r_addend"]
                    else:
                        if sym.name not in imports:
                            imports[sym.name] = self.stub(sym.name)
                        value = imports[sym.name] + rel["r_addend"]
                else:
                    raise RuntimeError(f"Unsupported relocation {kind}")
                self.put64(self.BASE + rel["r_offset"], value)
        self.env = self.allocate(8)
        table = self.allocate(0x1000)
        self.put64(self.env, table)
        for offset, name in [(0x538, "NewStringUTF"), (0x548, "GetStringUTFChars"),
                             (0x550, "ReleaseStringUTFChars")]:
            self.put64(table + offset, self.stub(name))
        tls = self.allocate(0x100)
        self.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, tls)
        self.uc.hook_add(UC_HOOK_CODE, self.hook, begin=self.STUB,
                         end=self.STUB + 0xfffff)

    def put64(self, ptr, value):
        self.uc.mem_write(ptr, struct.pack("<Q", value))

    def allocate(self, size):
        ptr = self.next_heap
        self.next_heap += (max(size, 1) + 15) & ~15
        if self.next_heap >= self.HEAP + 0x1000000:
            raise RuntimeError("Emulated heap exhausted")
        return ptr

    def string(self, text):
        data = text.encode() + b"\0"
        ptr = self.allocate(len(data))
        self.uc.mem_write(ptr, data)
        return ptr

    def cstr(self, ptr):
        out = bytearray()
        while len(out) < 100000:
            byte = self.uc.mem_read(ptr + len(out), 1)
            if byte == b"\0":
                return bytes(out)
            out += byte
        raise RuntimeError("Unterminated emulated string")

    def stub(self, name):
        addr = self.next_stub
        self.next_stub += 4
        self.uc.mem_write(addr, b"\xc0\x03\x5f\xd6")  # ret
        self.hooks[addr] = name
        return addr

    def hook(self, uc, address, size, _):
        name = self.hooks.get(address)
        x0, x1, x2 = [uc.reg_read(r) for r in
                      (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2)]
        if name in ("NewStringUTF", "GetStringUTFChars"):
            result = x1
        elif name in ("ReleaseStringUTFChars", "free", "_ZdlPv"):
            result = 0
        elif name == "strlen":
            result = len(self.cstr(x0))
        elif name in ("malloc", "_Znwm"):
            result = self.allocate(x0)
        elif name in ("memcpy", "memmove", "__memcpy_chk", "__memmove_chk"):
            uc.mem_write(x0, bytes(uc.mem_read(x1, x2)))
            result = x0
        elif name in ("memset", "__memset_chk"):
            uc.mem_write(x0, bytes([x1 & 255]) * x2)
            result = x0
        elif name == "strcmp":
            a, b = self.cstr(x0), self.cstr(x1)
            result = (a > b) - (a < b)
        elif name == "memcmp":
            a, b = bytes(uc.mem_read(x0, x2)), bytes(uc.mem_read(x1, x2))
            result = (a > b) - (a < b)
        else:
            raise RuntimeError(f"Unsupported native import: {name}")
        uc.reg_write(UC_ARM64_REG_X0, result & ((1 << 64) - 1))
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))

    def call(self, symbol, arg2=0, arg3=0):
        return self.raw_call(symbol, [self.env, 0, arg2, arg3])

    def raw_call(self, symbol, args, until=None):
        self.uc.reg_write(UC_ARM64_REG_SP, self.STACK + 0xf0000)
        registers = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                     UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                     UC_ARM64_REG_X6, UC_ARM64_REG_X7]
        for reg, val in zip(registers, args):
            self.uc.reg_write(reg, val)
        self.uc.reg_write(UC_ARM64_REG_X30, self.STUB)
        end = until or self.STUB
        start = self.symbols[symbol] if isinstance(symbol, str) else symbol
        self.uc.emu_start(start, end, timeout=10_000_000,
                          count=10_000_000)
        if self.uc.reg_read(UC_ARM64_REG_PC) != end:
            raise RuntimeError("Native emulation did not return")
        return self.uc.reg_read(UC_ARM64_REG_X0)
