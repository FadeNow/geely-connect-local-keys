"""Minimal offline JNI registration for the fingerprinted 1.3.0 library.

File opens and thread creation return failure inside the emulator. TLS and
mutex state are simulated in memory; no host files, threads or APIs are used.
"""
import base64
import hashlib
import hmac
import struct

from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_PC, UC_ARM64_REG_X30,
)

from _apk130 import find_signing_key
from _native import Native


METHODS = {
    "upDateNativeEnvironment": "(II)V",
    "getNativeSchema": "()Ljava/lang/String;",
    "getNativeHost": "()Ljava/lang/String;",
    "getNativeApplicationId": "()Ljava/lang/String;",
    "getNativeSecret": "()Ljava/lang/String;",
    "getNativeSign": "(Ljava/lang/String;)Ljava/lang/String;",
    "getNativeSignWith": "(IILjava/lang/String;)Ljava/lang/String;",
    "getNativeH5Url": "()Ljava/lang/String;",
}


class RegisteredNative(Native):
    def __init__(self, path):
        super().__init__(path)
        self.registered = {}
        self.thread_values = {}
        self.next_thread_key = 1
        self.class_handle = self.allocate(8)
        self.vm = self.allocate(8)
        table = self.allocate(0x100)
        self.put64(self.vm, table)
        self.put64(table + 0x30, self.stub("GetEnv"))
        env_table = self.get64(self.env)
        for index, name in ((6, "FindClass"), (215, "RegisterNatives"), (23, "DeleteLocalRef")):
            self.put64(env_table + index * 8, self.stub(name))

    def get64(self, address):
        return struct.unpack("<Q", self.uc.mem_read(address, 8))[0]

    def _check_function(self, address):
        if address % 4 or not any(
            segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1
            and self.BASE + segment["p_vaddr"] <= address
            < self.BASE + segment["p_vaddr"] + segment["p_filesz"]
            for segment in self.elf.iter_segments()
        ):
            raise ValueError("Invalid native function address")

    def initialize(self):
        section = self.elf.get_section_by_name(".init_array")
        if section is None or section["sh_size"] != 8:
            raise ValueError("Unexpected native initializer layout")
        pointer = self.get64(self.BASE + section["sh_addr"])
        self._check_function(pointer)
        self.raw_call(pointer, [])
        if self.raw_call("JNI_OnLoad", [self.vm, 0]) != 0x10006:
            raise ValueError("Unexpected JNI version")
        if set(self.registered) != set(METHODS):
            raise ValueError("Incomplete native registration")

    def hook(self, uc, address, size, user):
        name = self.hooks.get(address)
        x0, x1, x2, x3 = [uc.reg_read(reg) for reg in (
            UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3
        )]
        if name == "GetEnv":
            if x0 != self.vm or x2 != 0x10006:
                raise ValueError("Unexpected JNI environment request")
            self.put64(x1, self.env)
            result = 0
        elif name == "FindClass":
            if self.cstr(x1) != b"com/zeekr/env/ServerUtils":
                raise ValueError("Unexpected JNI class")
            result = self.class_handle
        elif name == "RegisterNatives":
            if x1 != self.class_handle or x3 != len(METHODS) or self.registered:
                raise ValueError("Unexpected native method table")
            for index in range(x3):
                pointer = x2 + index * 24
                method = self.cstr(self.get64(pointer)).decode()
                signature = self.cstr(self.get64(pointer + 8)).decode()
                function = self.get64(pointer + 16)
                if method in self.registered or METHODS.get(method) != signature:
                    raise ValueError("Unexpected native method signature")
                self._check_function(function)
                self.registered[method] = function
            result = 0
        elif name in ("DeleteLocalRef", "__cxa_atexit", "__register_atfork",
                      "pthread_mutex_lock", "pthread_mutex_unlock"):
            result = 0
        elif name == "fopen":
            result = 0  # No files exist in the emulator.
        elif name == "pthread_create":
            result = 11  # EAGAIN: no host or emulated thread is started.
        elif name == "pthread_detach":
            result = 22  # EINVAL: no thread was created.
        elif name == "pthread_once":
            if not any(uc.mem_read(x0, 4)):
                self._check_function(x1)
                uc.mem_write(x0, struct.pack("<I", 1))
                uc.reg_write(UC_ARM64_REG_PC, x1)
                return
            result = 0
        elif name == "pthread_key_create":
            if self.next_thread_key > 16:
                raise ValueError("Emulated TLS limit exceeded")
            uc.mem_write(x0, struct.pack("<I", self.next_thread_key))
            self.next_thread_key += 1
            result = 0
        elif name == "pthread_getspecific":
            result = self.thread_values.get(x0, 0)
        elif name == "pthread_setspecific":
            self.thread_values[x0] = x1
            result = 0
        elif name == "pthread_key_delete":
            self.thread_values.pop(x0, None)
            result = 0
        else:
            return super().hook(uc, address, size, user)
        uc.reg_write(UC_ARM64_REG_X0, result)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))

    def signing_key(self):
        message = b"geely-offline-validation"
        signature = self.cstr(self.call(
            self.registered["getNativeSign"], self.string(message.decode())
        ))
        key = find_signing_key(bytes(self.uc.mem_read(self.STACK, 0x100000)), message, signature)
        # Confirm with a second message, not just a coincidental memory string.
        second = b"geely-offline-validation-2"
        signature = self.cstr(self.call(
            self.registered["getNativeSign"], self.string(second.decode())
        ))
        expected = base64.b64encode(hmac.new(key, second, hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError("Local native signing verification failed")
        return key.decode()
