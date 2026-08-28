#!/usr/bin/env node
// Instantiate a kotoba-compiled wasm module and assert ELF ident/header fields.
// The binary fixture is the source of truth; packed words in lief.kotoba must match it.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error("usage: node run_wasm.mjs <file.wasm>");
  process.exit(2);
}

const buf = readFileSync(wasmPath);
if (buf.length < 4 || buf[0] !== 0x00 || buf[1] !== 0x61 || buf[2] !== 0x73 || buf[3] !== 0x6d) {
  console.error("not a wasm module (missing magic)");
  process.exit(1);
}

const module = new WebAssembly.Module(buf);
const imports = WebAssembly.Module.imports(module);
if (imports.length !== 0) {
  console.error("wasm module has imports (not host-independent):", imports);
  process.exit(1);
}

const fixture = readFileSync(join(here, "fixtures", "tiny64le.elf"));
if (fixture.length !== 64) {
  console.error("fixture length", fixture.length, "expected 64");
  process.exit(1);
}

function packWord(bytes, off) {
  let n = 0n;
  for (let i = 0; i < 8; i++) {
    n += BigInt(bytes[off + i]) << BigInt(8 * i);
  }
  return n;
}

const fileW0 = packWord(fixture, 0);
const fileW1 = packWord(fixture, 8);
const fileW2 = packWord(fixture, 16);

const inst = new WebAssembly.Instance(module);
const ex = inst.exports;

function i64(name, ...args) {
  const fn = ex[name];
  if (typeof fn !== "function") {
    console.error("missing export", name);
    process.exit(1);
  }
  const v = fn(...args);
  return typeof v === "bigint" ? v : BigInt(v);
}

if (i64("main") !== 0n) {
  console.error("main returned non-zero (fixture asserts failed)");
  process.exit(1);
}

if (i64("fixture-w0") !== fileW0 || i64("fixture-w1") !== fileW1 || i64("fixture-w2") !== fileW2) {
  console.error("embedded fixture words do not match fixtures/tiny64le.elf");
  console.error(" file", fileW0, fileW1, fileW2);
  console.error(" wasm", i64("fixture-w0"), i64("fixture-w1"), i64("fixture-w2"));
  process.exit(1);
}

if (i64("ident-magic-ok", fileW0) !== 1n) {
  console.error("ident-magic-ok failed on fixture");
  process.exit(1);
}
if (i64("ident-class", fileW0) !== 2n) {
  console.error("ident-class", i64("ident-class", fileW0), "expected 2 (ELF64)");
  process.exit(1);
}
if (i64("ident-data", fileW0) !== 1n) {
  console.error("ident-data", i64("ident-data", fileW0), "expected 1 (LSB)");
  process.exit(1);
}
if (i64("file-type", fileW0, fileW2) !== 3n) {
  console.error("file-type", i64("file-type", fileW0, fileW2), "expected 3 (ET_DYN)");
  process.exit(1);
}
if (i64("machine-type", fileW0, fileW2) !== 62n) {
  console.error("machine-type", i64("machine-type", fileW0, fileW2), "expected 62 (EM_X86_64)");
  process.exit(1);
}

for (let i = 0; i < 16; i++) {
  const got = i64("ident-byte", fileW0, fileW1, BigInt(i));
  const exp = BigInt(fixture[i]);
  if (got !== exp) {
    console.error(`ident-byte ${i}: got ${got}, expected ${exp}`);
    process.exit(1);
  }
}

console.log("ident: magic=7fELF class=ELF64 data=LSB type=ET_DYN machine=EM_X86_64");
console.log("kotoba wasm ELF header fixtures passed");
