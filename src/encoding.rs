use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::io::Cursor;

use crate::common::*;

pub fn encode_f_as_bs58_str(value: &F) -> String {
    let mut buffer: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut buffer).unwrap();
    bs58::encode(buffer).into_string()
}

pub fn decode_bs58_str_as_f(msg: &String) -> F {
    let buf: Vec<u8> = bs58::decode(msg).into_vec().unwrap();
    F::deserialize_compressed(buf.as_slice()).unwrap()
}

pub fn encode_g1_as_bs58_str(value: &G1) -> String {
    let mut serialized_msg: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut serialized_msg).unwrap();
    bs58::encode(serialized_msg).into_string()
}

pub fn decode_bs58_str_as_g1(msg: &String) -> G1 {
    let decoded = bs58::decode(msg).into_vec().unwrap();
    G1::deserialize_compressed(&mut Cursor::new(decoded)).unwrap()
}

pub fn encode_g2_as_bs58_str(value: &G2) -> String {
    let mut serialized_msg: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut serialized_msg).unwrap();
    bs58::encode(serialized_msg).into_string()
}

pub fn decode_bs58_str_as_g2(msg: &String) -> G2 {
    let decoded = bs58::decode(msg).into_vec().unwrap();
    G2::deserialize_compressed(&mut Cursor::new(decoded)).unwrap()
}

pub fn encode_gt_as_bs58_str(value: &Gt) -> String {
    let mut serialized_msg: Vec<u8> = Vec::new();
    value.serialize_compressed(&mut serialized_msg).unwrap();
    bs58::encode(serialized_msg).into_string()
}

pub fn decode_bs58_str_as_gt(msg: &String) -> Gt {
    let decoded = bs58::decode(msg).into_vec().unwrap();
    Gt::deserialize_compressed(&mut Cursor::new(decoded)).unwrap()
}