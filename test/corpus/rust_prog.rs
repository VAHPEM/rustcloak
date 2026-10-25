// Structs, enums, match, Vec, Option/Result, iterators, closures, and several string literals.
// Deterministic output so obfuscated == baseline can be checked.
use std::collections::HashMap;

#[derive(Clone)]
enum Op { Add(i64), Mul(i64), Xor(i64) }

#[inline(never)]
fn apply(acc: i64, op: &Op) -> i64 {
    match op {
        Op::Add(x) => acc.wrapping_add(*x),
        Op::Mul(x) => acc.wrapping_mul(*x),
        Op::Xor(x) => acc ^ x,
    }
}

#[inline(never)]
fn fnv1a(s: &str) -> u32 {
    s.bytes().fold(2166136261u32, |h, b| (h ^ b as u32).wrapping_mul(16777619))
}

fn main() {
    let labels = ["rust::secret::one", "rust::secret::two", "rust::endpoint::c2"];
    let program = vec![Op::Add(7), Op::Mul(3), Op::Xor(0x5a5a), Op::Add(-11), Op::Mul(2)];

    let mut acc: i64 = 1;
    for op in program.iter().cycle().take(15) {
        acc = apply(acc, op);
    }

    let mut counts: HashMap<u32, usize> = HashMap::new();
    for l in labels.iter() {
        *counts.entry(fnv1a(l) & 0xff).or_insert(0) += 1;
    }
    let distinct = counts.len();
    let hashsum: u32 = labels.iter().map(|l| fnv1a(l)).fold(0, |a, h| a ^ h);
    let pick = labels[(acc.unsigned_abs() as usize) % labels.len()];

    println!("acc={} distinct={} hashsum={:08x} pick={}", acc, distinct, hashsum, pick);
}
