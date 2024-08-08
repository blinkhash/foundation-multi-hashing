{
    "targets": [
        {
            "target_name": "multihashing",
            "sources": [
                "multihashing.cc",

                # Main Sources
                "algorithms/main/allium/allium.c",
                "algorithms/main/blake/blake.c",
                "algorithms/main/blake/blake2s.c",
                "algorithms/main/c11/c11.c",
                "algorithms/main/equihash/equihash.cpp",
                "algorithms/main/fugue/fugue.c",
                "algorithms/main/ghostrider/ghostrider.c",
                "algorithms/main/groestl/groestl.c",
                "algorithms/main/keccak/keccak.c",
                "algorithms/main/lyra2re/lyra2re.c",
                "algorithms/main/minotaur/minotaur.c",
                "algorithms/main/nist5/nist5.c",
                "algorithms/main/quark/quark.c",
                "algorithms/main/qubit/qubit.c",
                "algorithms/main/scrypt/scrypt.c",
                "algorithms/main/sha256d/sha256d.c",
                "algorithms/main/sha512256d/sha512256d.c",
                "algorithms/main/skein/skein.c",
                "algorithms/main/verthash/verthash.c",
                "algorithms/main/x11/x11.c",
                "algorithms/main/x13/x13.c",
                "algorithms/main/x15/x15.c",
                "algorithms/main/x16r/x16r.c",
                "algorithms/main/x16rt/x16rt.c",
                "algorithms/main/x17/x17.c",
                "algorithms/main/yespower/yespower.c",

                # ProgPow Sources
                "algorithms/main/evrprogpow/evrprogpow.cpp",
                "algorithms/main/evrprogpow/evrprogpow_progpow.cpp",
                "algorithms/main/firopow/firopow.cpp",
                "algorithms/main/firopow/firopow_progpow.cpp",
                "algorithms/main/kawpow/kawpow.cpp",
                "algorithms/main/kawpow/kawpow_progpow.cpp",
                "algorithms/main/meowpow/meowpow.cpp",
                "algorithms/main/meowpow/meowpow_progpow.cpp",
                "algorithms/main/meraki/meraki.cpp",
                "algorithms/main/meraki/meraki_progpow.cpp",
		
                "algorithms/main/curvehash/curvehash.cpp",

                # Common Sources
                "algorithms/main/common/utils/lyra2.c",
                "algorithms/main/common/utils/sponge.c",
                "algorithms/main/common/utils/sha256c.c",
                "algorithms/main/common/utils/sha256c2.c",
                "algorithms/main/common/utils/utilstrencodings.cpp",
                "algorithms/main/common/sha3/aes_helper.c",
                "algorithms/main/common/sha3/KeccakP-800-reference.c",
                "algorithms/main/common/sha3/sha3.c",
                "algorithms/main/common/sha3/sph_haval.c",
                "algorithms/main/common/sha3/sph_hefty1.c",
                "algorithms/main/common/sha3/sph_fugue.c",
                "algorithms/main/common/sha3/sph_blake.c",
                "algorithms/main/common/sha3/sph_blake2s.c",
                "algorithms/main/common/sha3/sph_bmw.c",
                "algorithms/main/common/sha3/sph_cubehash.c",
                "algorithms/main/common/sha3/sph_echo.c",
                "algorithms/main/common/sha3/sph_gost.c",
                "algorithms/main/common/sha3/sph_groestl.c",
                "algorithms/main/common/sha3/sph_hamsi.c",
                "algorithms/main/common/sha3/sph_jh.c",
                "algorithms/main/common/sha3/sph_keccak.c",
                "algorithms/main/common/sha3/sph_luffa.c",
                "algorithms/main/common/sha3/sph_shavite.c",
                "algorithms/main/common/sha3/sph_simd.c",
                "algorithms/main/common/sha3/sph_skein.c",
                "algorithms/main/common/sha3/sph_whirlpool.c",
                "algorithms/main/common/sha3/sph_shabal.c",
                "algorithms/main/common/sha3/sph_ripemd.c",
                "algorithms/main/common/sha3/sph_sha2.c",
                "algorithms/main/common/sha3/sph_sha2big.c",
                "algorithms/main/common/sha3/sph_tiger.c",
                "algorithms/main/common/cryptonote/cryptonight_dark_lite.c",
                "algorithms/main/common/cryptonote/cryptonight_dark.c",
                "algorithms/main/common/cryptonote/cryptonight_fast.c",
                "algorithms/main/common/cryptonote/cryptonight_lite.c",
                "algorithms/main/common/cryptonote/cryptonight_soft_shell.c",
                "algorithms/main/common/cryptonote/cryptonight_turtle_lite.c",
                "algorithms/main/common/cryptonote/cryptonight_turtle.c",
                "algorithms/main/common/cryptonote/cryptonight.c",
                "algorithms/main/common/crypto/aesb.c",
                "algorithms/main/common/crypto/c_blake256.c",
                "algorithms/main/common/crypto/c_groestl.c",
                "algorithms/main/common/crypto/c_jh.c",
                "algorithms/main/common/crypto/c_keccak.c",
                "algorithms/main/common/crypto/c_skein.c",
                "algorithms/main/common/crypto/hash.c",
                "algorithms/main/common/crypto/oaes_lib.c",
                "algorithms/main/common/crypto/wild_keccak.cpp",
                "algorithms/main/common/ethash/ethash/primes.c",
                "algorithms/main/common/ethash/keccak/keccak.c",
                "algorithms/main/common/ethash/keccak/keccakf800.c",
                "algorithms/main/common/ethash/keccak/keccakf1600.c",
                "algorithms/main/secp256k1/src/secp256k1.c",
                "algorithms/main/secp256k1/src/precomputed_ecmult.c",
                "algorithms/main/secp256k1/src/precomputed_ecmult_gen.c",
            ],
            "include_dirs": [
                ".",
                "<!(node -e \"require('nan')\")",
            ],
            "cflags_cc": [
                "-std=c++0x",
                "-fPIC",
                "-fexceptions"
            ],
            "defines": [
                "HAVE_DECL_STRNLEN=1",
                "HAVE_BYTESWAP_H=1"
            ],
            "link_settings": {
                "libraries": [
                    "-Wl,-rpath,./build/Release/",
                    "-lboost_system",
                    "-lsodium"
                ]
            },
            'conditions': [
                ['OS=="mac"', {
                    'xcode_settings': {
                        'GCC_ENABLE_CPP_EXCEPTIONS': 'YES'
                    }
                }]
            ]
        }
    ]
}
