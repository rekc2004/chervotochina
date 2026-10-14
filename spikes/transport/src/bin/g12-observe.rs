//! G12: что видит пассивный наблюдатель. Использование:
//! g12-observe --pcap <f> --needles <f> --alpn <s> --version <n>
#![forbid(unsafe_code)]

use spike::observe;
use spike::util::{Args, BoxErr, err};

fn run() -> Result<i32, BoxErr> {
    let mut argv = vec!["observe".to_string()];
    argv.extend(std::env::args().skip(1));
    let a = Args::parse(&argv, &[])?;
    let pcap = std::fs::read(a.req("pcap")?).map_err(|e| err(format!("pcap: {e}")))?;
    let needles = observe::parse_needles(&std::fs::read_to_string(a.req("needles")?)?)?;
    let alpn = a.req("alpn")?.as_bytes().to_vec();
    let version: u32 = a.num("version", 1u32)?;
    let rep = observe::analyze(&pcap, needles, &alpn, version)?;
    for l in &rep.lines {
        println!("{l}");
    }
    println!(
        "OBSERVE datagrams={} quic_initial={} client_decrypted={} server_decrypted={} skips={}",
        rep.datagrams, rep.initials, rep.client_decrypted, rep.server_decrypted, rep.skips
    );
    let mut vs = rep.versions.clone();
    vs.sort_unstable();
    vs.dedup();
    let mut dl = rep.dcid_lens.clone();
    dl.sort_unstable();
    dl.dedup();
    let mut sl = rep.scid_lens.clone();
    sl.sort_unstable();
    sl.dedup();
    println!("QUIC versions={vs:?} client_dcid_lens={dl:?} client_scid_lens={sl:?} alpn_found={}", u8::from(rep.alpn_found));
    for (i, (s, d)) in rep.conns.iter().enumerate() {
        println!("CONN {i} client_scid={} first_dcid={}", spike::util::hex(s), spike::util::hex(d));
    }
    for (n, w) in &rep.hits {
        println!("HIT needle={n} where={w}");
    }
    let (v, why) = rep.verdict();
    println!("RESULT {v} {why}");
    Ok(0)
}

fn main() {
    match run() {
        Ok(c) => std::process::exit(c),
        Err(e) => {
            eprintln!("ERROR {e}");
            std::process::exit(2);
        }
    }
}
