#[inline(never)]
fn decode(ct: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ct.len());
    for (i, &b) in ct.iter().enumerate() { out.push(b ^ key[i % key.len()]); }
    if ct.len() & 1 == 1 { let n = out.len(); out[n-1] ^= 0x20; }
    out
}
fn main() {
    let secret = "rustcloak-secret-7f3c-endpoint";
    let key = [0x5au8, 0x31, 0x7e, 0x14];
    let ct: Vec<u8> = secret.bytes().enumerate().map(|(i,b)| b ^ key[i%4]).collect();
    println!("{}", String::from_utf8_lossy(&decode(&ct, &key)));
}
