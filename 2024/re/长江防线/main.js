use std::vec;
use std::io::{self, Read, Write};
use hex;
use anyhow::Result;
use std::num::Wrapping;
use openssl::{hash::{hash, MessageDigest, Hasher}, cipher_ctx::CipherCtx, cipher::Cipher};

const SALT: u32 = 0x7ad9c7bd;
const SALT2: u32 = 0x3a0a7fbf;
const ROUND: usize = 1000;

const ENC_FLAG: &[u8] = b"92526a6d0c7152fb057277ed078742203b3cf2840a041334b37d1199bea96da598551a8fb2716a5da1ba4ccbb9fe0eb9a9c2864259fb94794f6171923db155222edfabc8f4dcca91b00f1b390c6a1fd4551117827391d6533241ade56e2caf1e38c2428d2e4576b306bd84e125cc75887e35c7b6b30f2de83f623e2e62e9e86dd28313462d2fa20edf74ed3e0c9fff8c60f8319df75ed8d879883795bb8af8e50fc833f4a0005ab241a73c1047175a5d7f27602a9b03da2a95c1a3edd8dfc7c1d34488bcbde80e2dbf6dc5f33701d528d072708946cb98c8181b0438a6de2e2b946e2cdc0994efd82db7b627888ff2f89127a1b1c6e7f9e0c0cd7012da9058ec2a97fea2fef8be292b99e6c487f1c73c0c389c4626a68904c6c206269f21a88d993e36f055654c45a60865a708d3891e0baae1e022c7dce946c33b2a881c8cf7d7591ffbd3c162dc10c6c0ae2fcd5110b3ea3af5027bcd5770a5feef0b15b5bf2161a7245a6ed8bd0fad6bc7499f8c20733d1d82bed85be868cbd3bcaadf36c6fc0abbd4f2ef744ada607e818c9a1f54";

fn round_key_expand(key: Vec<u8>) -> Vec<u8> {
    assert_eq!(key.len(), 16);
    let mut round_key: Vec<u32> = key.chunks(4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]])).collect();
    let mut expand_key = vec::Vec::new();
    for _ in 0..4 {
        let mut next_round = vec::Vec::new();
        next_round.push(round_key[0] ^ round_key[3] ^ SALT);
        next_round.push(next_round[0] ^ round_key[1]);
        next_round.push(next_round[1] ^ round_key[2]);
        next_round.push(next_round[2] ^ round_key[3]);
        expand_key.extend_from_slice(&next_round);
        round_key = next_round;
    }
    let key = expand_key.into_iter().map(|x| x.to_le_bytes()).fold(vec::Vec::new(), |mut acc, x| {
        acc.extend_from_slice(&x);
        acc
    });

    hash(MessageDigest::sha512(), &key).unwrap().to_vec()
}

fn c4(mut num: u64) -> usize {
    let mut crc_sum: u8 = 0;
    for _ in 0..16 {
        crc_sum *= 2;
        if crc_sum >= 16 {
            crc_sum = (crc_sum % 16) + 1;
        }
        crc_sum ^= (num % 16) as u8;
        num /= 16;
    }
    crc_sum as usize
}

fn bit_hash(data: Vec<u8>) -> Vec<u8> {
    assert_eq!(data.len(), 64);
    let mut hash_sum = Wrapping(0u128);
    for shift in data.chunks(8).map(|x| u64::from_le_bytes([x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]])).map(|x| c4(x) + 1) {
        hash_sum ^= SALT2 as u128;
        hash_sum <<= shift;
    }
    hash_sum.0.to_le_bytes().to_vec()
}

fn bit_upset(data: Vec<u8>) -> Vec<u8> {
    assert_eq!(data.len(), 16);
    data.chunks(2).map(|x| {
        hash(MessageDigest::sha512(), x).unwrap().to_vec()
    }).map(|x| {
        x.chunks(4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]])).fold(0u32, |acc, x| acc ^ x)
    }).map(|x| (x & 0xff) as u8).collect()
}

fn generate_key(mut data: Vec<u8>) -> Vec<u8> {
    let mut salt = vec![0u8; 64];
    for _ in 0..1000000 {
        let mut hasher = Hasher::new(MessageDigest::sha512()).unwrap();
        hasher.update(&data).unwrap();
        hasher.update(&salt).unwrap();
        data = hasher.finish().unwrap().to_vec();
        salt = hash(MessageDigest::sha512(), &salt).unwrap().to_vec();
    }
    data.truncate(16);
    data
}

fn verify_passwd(password: Vec<u8>) -> bool {
    let mut data = hash(MessageDigest::sha512(), &password).unwrap().to_vec();
    for _ in 0..ROUND {
        data = round_key_expand(bit_hash(data));
    }
    data = bit_hash(data);
    data = bit_upset(data);

    &data == &hex::decode("b49e0d474a9a1f7e").unwrap()
}

fn get_passwd() -> Result<Vec<u8>> {
    let mut passwd = vec![0u8; 100];
    io::stdin().read_exact(&mut passwd)?;
    for ch in passwd.iter() {
        if *ch < '0' as u8 || *ch > '9' as u8 {
            return Err(anyhow::anyhow!("Invalid password"));
        }
    }
    Ok(passwd)
}

fn decrypt_flag(passwd: Vec<u8>, enc_flag: Vec<u8>) -> Result<String> {
    let data = hash(MessageDigest::sha512(), &passwd).unwrap().to_vec();
    let ori_key = bit_hash(data);
    let aes_key = generate_key(ori_key);
    let iv = hex::decode("02cc276f84d25c45c393d3b81571b03f").unwrap();

    let mut flag = vec![];
    let mut ctx = CipherCtx::new().unwrap();
    ctx.set_padding(false);
    ctx.decrypt_init(Some(Cipher::aes_128_ofb()), Some(&aes_key), Some(&iv)).unwrap();
    ctx.cipher_update_vec(&enc_flag, &mut flag).unwrap();
    ctx.cipher_final_vec(&mut flag).unwrap();

    let start = flag.windows(5).position(|x| x == b"flag{").ok_or(anyhow::anyhow!("decrypt flag error(bug!!)"))?;
    let end = flag[start..].iter().position(|&x| x == b'}').ok_or(anyhow::anyhow!("decrypt flag error(bug!!)"))?;

    Ok(String::from_utf8_lossy(&flag[start..start + end + 1]).to_string())
}


fn main() -> Result<()> {
    io::stdout().write_all(b"Enter password: ")?;
    io::stdout().flush()?;
    match get_passwd() {
        Ok(passwd) => {
            if !verify_passwd(passwd.clone()) {
                println!("Invalid password");
            }
            let flag = decrypt_flag(passwd, hex::decode(ENC_FLAG).unwrap()).unwrap();
            println!("flag: {}", flag);
        }
        Err(_) => println!("Invalid password"),
    }
    Ok(())
}
