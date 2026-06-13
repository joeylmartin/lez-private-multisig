// Hosts the risc0 build infrastructure. The guest binary lives in
// guest/src/bin/private_multisig.rs; this exposes PRIVATE_MULTISIG_ELF and
// PRIVATE_MULTISIG_ID (the program ID is the Risc0 image ID).
include!(concat!(env!("OUT_DIR"), "/methods.rs"));
