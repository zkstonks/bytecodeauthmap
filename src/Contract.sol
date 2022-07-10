// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// Contract has been tested only with Solidity v0.8.15 and optimizer_runs=500.
// With a different compiler configuration, the bytecode may change, causing
// the bytecode offset of ADDRESSES to change, breaking the contract.
// Run test_get_offset() with 3 verbosity to get the offset
contract Contract {
    // ADDRESSES is the concatenation of 128 sorted-increasing mined addresses.
    // The first 2 bytes of address i is 241 + 32 * i, the address's offset in the bytecode
    // Run test_get_offset() with 3 verbosity to get the offset
    bytes public constant ADDRESSES = hex"00000000000000000000000000f168f0a7a69e02d8379cec46b71b0f8e7aa9fe0000000000000000000000000111ed73b85755938b678860872c55e150454cc700000000000000000000000001310172b9e19abe024d476e8008a924d348438e00000000000000000000000001518a8f54adb7523c8edfb04e700e6742f6d51a00000000000000000000000001714de2709fbbbaebd0f42cfc2176be1b8630e400000000000000000000000001916409c86fb1ee6ac6b9717a1ee382d5112b2500000000000000000000000001b1c4146fac00c0a579a227d46b140c98c24b9200000000000000000000000001d18e9c65bd513693bd88a443c6242c366e3dc900000000000000000000000001f18b73cc356241b1379a5709a5b8307f92e1170000000000000000000000000211fcef20d8d9b4a39fd6e4da78dec0a43a598500000000000000000000000002317681355377f112955aea3fd9670c353fc9810000000000000000000000000251f55dddd0fb9e0cab2b0175858e2a581b82050000000000000000000000000271a85d0c74b69a39a9d5a8d59a0d7926eb64af000000000000000000000000029146c471828df7d54311cb2dee8e8930f2b36700000000000000000000000002b1f7f8872bd28fa4bf04de7001537fb1f4305800000000000000000000000002d1da320fb46fd4277ce484efe85568738272d100000000000000000000000002f14d5bd7332dcfca39fb312dd14d67570d4f8b00000000000000000000000003118e420e894dd190dbd0b40bad481a094f116300000000000000000000000003312058ae8759034ced88c53b16fdc8ce3ac3db00000000000000000000000003518698cba0805ba88a2157370ac0c8198a6aad0000000000000000000000000371e4208c3cd24d9d7ea60e4cbf0fc44580d2ee0000000000000000000000000391f51de9353aa9f07de461929c7a5340d879f400000000000000000000000003b17f39cb8e088bdd5bd2436cd7ff9057172cbe00000000000000000000000003d1cc5f092e198894e8fee03faad2c0a6a300c100000000000000000000000003f196ad378ae7341a4feefaaf53e50722ae1d77000000000000000000000000041160e150921017231da8f185b0307463d402810000000000000000000000000431ce921260f6509cd761009c5b706b8eac12d10000000000000000000000000451ef291ee0b37cbf2cad4b95b4caee0e6561900000000000000000000000000471cd91922a5c5bc0afe6bc772fe174442c4847000000000000000000000000049133fd9509320b1b6f686db4d708d9897ca1f300000000000000000000000004b180b394a66a7974aeb06c3625c0ac11ad74f200000000000000000000000004d1a97df1a2b5c09f7257cb579a1268ed35ce4b00000000000000000000000004f113f56b934ddf068ed8ce3ed7fd2639786f2f00000000000000000000000005110020c3a3ac343b4d6bafc4457cb3f8a912d00000000000000000000000000531ebd5949673b6f46902bec0acc798dca6dcc50000000000000000000000000551cac715d559fe14d7edba24e50ca79c4814c00000000000000000000000000571c49f1d4d19eee2b4801dac6aa00cd95027b900000000000000000000000005914a854af9ef68b802711f7ebac7dcd80187b000000000000000000000000005b1f3dac64c43f578c07b08a9ae3b315cebf21000000000000000000000000005d116d13015634cadcf925701090351d8d1696000000000000000000000000005f1b4c3efef3f840045e085315293aa2f1084a300000000000000000000000006111e780972d0bf6be7092d7183e2b75602be5e0000000000000000000000000631938e0a9be2639156a6bd50012e67c9c8b6ec0000000000000000000000000651e227b934bbd4237b94d4c092e2c59992f3d70000000000000000000000000671a7d1fd513054f9dc6f9f21f692a18d85478d00000000000000000000000006912bf68f1bf1e8e8e67ae8b3afff88010372c200000000000000000000000006b1ad902cf3c5549fc44c20680378bbdb2c743e00000000000000000000000006d157688af9188d36ff5abf0f2b8c848e41cd7500000000000000000000000006f1db9908b256155072c2f3c1fac7dded4afd36000000000000000000000000071184e402bebe7e8cb3c90318b77beaac38de73000000000000000000000000073154bf6fdd36b5097531212aa462fb139bf4520000000000000000000000000751552aefdcf2c7a783f4b455c8ccf5aa34701d0000000000000000000000000771b8abbda3b9b2b13f983472925d14ad610ee10000000000000000000000000791411ceb5037b437853dbd60babe97e6b832d900000000000000000000000007b1081f0cfaf6b70a2eca3a518e42cc4a434fcd00000000000000000000000007d186753a8ef3d284ee10c57bfd89ba1341226200000000000000000000000007f1c2f88296739c035a9ac1bc67f63f6a60c94c0000000000000000000000000811b4d4dcc02b85e89a7bb042b31f0830773425000000000000000000000000083130b9553dc95f235c49be6ff1511f550f050e00000000000000000000000008517a2f6a4f316d595bbb5a75f089d02156889700000000000000000000000008715562b4cf6aa8c811f9e91917725dc97e4be600000000000000000000000008919c3051e7952637f0617964f5fe67afbe04f200000000000000000000000008b1c257363cbdf0d4cff48f86eb0b770d37a1ef00000000000000000000000008d11ff806bcc5bab2dc53a06b94fd2654e616e900000000000000000000000008f1964561ed41e32eb0ae0b48c10bf676902c5500000000000000000000000009116a3f8847352d650ce7c7dc7250ce1a26cd8e0000000000000000000000000931a426037505d7114a798ec16c121ab2a6d1a70000000000000000000000000951022d5ba1aaa6dacb93cfafde12f8c47827a90000000000000000000000000971cf94c9a16e16e7311f33d34772149d8bc34100000000000000000000000009916c14dd3bad92158497e27256f679e4849f9d00000000000000000000000009b1dfeb7eb85b76c446a4cdd8d21902609db7a500000000000000000000000009d1deeb7a32fa1aa08a772d583d3cec9e4d6c6c00000000000000000000000009f125ae695b6971edd68d5600df32c0fcb98dac0000000000000000000000000a119b0f49e867ea4c85485fe434dd7ad3fa989a0000000000000000000000000a31834a85c7228acf6599be29b307328b2c11000000000000000000000000000a518cd93196c620d28618ebf120a0eb274fff710000000000000000000000000a717426d141255a153594ed1f44557b262722140000000000000000000000000a91ca27f2daab97a2cfcf1c6d488c0bd3ccce290000000000000000000000000ab1c144302235bbcd1621ed0429a0855a34f0800000000000000000000000000ad10db91678b0df08e0c1e964815c9f6b95054f0000000000000000000000000af1197ccaeeba8e33f923ce67be7e1ee0a1f10c0000000000000000000000000b113ae75509b87706d4b3afb40ca66172b603000000000000000000000000000b31338389ac8501d0c6c929f214da4e2ce0ad760000000000000000000000000b51789db9f3198b4832bf21495823307bdb34850000000000000000000000000b7109c58afa9ce521a9ecb9d1584d45929c2f330000000000000000000000000b91b84a8733391bfa6cd7856c29840a2ec74cbc0000000000000000000000000bb11a66c0b0d08149de3856c5ad7228511586fc0000000000000000000000000bd1de8d59a06d9eef064571d473470a0711ac0b0000000000000000000000000bf15a0da2a49a028adc042a3cab1022ae466dd20000000000000000000000000c11035bf7edacb2fb307946cb03318c4ccd60aa0000000000000000000000000c319b5f8257cab4f5e598d16cdd61932448407e0000000000000000000000000c51643a45afb59114cc9d9951e1a068adb66e770000000000000000000000000c714d6393fde1a15d4c515bf1f4a2f9d52a31570000000000000000000000000c91475df26d98c14da057b4b20510760298254d0000000000000000000000000cb1f22d2180c9dc942530ec50b7e5547440692f0000000000000000000000000cd18f43af4a0302f0a8ba1a6bd4375ed1284d860000000000000000000000000cf1766f57f78478d3eef57647e7757ca121e6380000000000000000000000000d111fa5c040fa67ebca764b9306933420cca25b0000000000000000000000000d31b0bf86277d702cd26e07c9417c8244e9856f0000000000000000000000000d51d60a05b6760c31521b6a6e228f8dbb0428a50000000000000000000000000d71ce01cfdbf57daa63c257c36a79f0c389861e0000000000000000000000000d91df5df9cf3e844272b95f053fd339594c1d310000000000000000000000000db1c42682db0496f95581d259778decf9b0815f0000000000000000000000000dd136728e41d22acaab0888e7f461d272c983900000000000000000000000000df192a0251a39cd93cc9b4d5ce1f63018d1ba890000000000000000000000000e11076763fd2d521e129f8ce7b63f51bb48d4100000000000000000000000000e316eb9a00dcb3905bb80a8ced888551df55d000000000000000000000000000e51aef8d91aaabaea38432ecab400bee9a292b30000000000000000000000000e719607461d7a9051726c2a0f5f681cf2a439d30000000000000000000000000e91a20d9c6e2a84f35211995bc5f151c2ee5aed0000000000000000000000000eb1a369a3f337906c5405f57e5ca014e74a1ded0000000000000000000000000ed19c605780a3268b1cad3aef526bb0e6da13950000000000000000000000000ef15bc434035b036520801507b66cc0c5ebcb5a0000000000000000000000000f11f12126b86b1beaf523190f846d96592638b90000000000000000000000000f31b0de788f55741b587e3a65951a521be61f1b0000000000000000000000000f5173c6dcf2f8b60019455980f2c9f587f843a40000000000000000000000000f7182b54c22743c7bdb6a8fa5c90c6c95c4e93b0000000000000000000000000f9105fd3df24de31c25a072256949dd7acc245e0000000000000000000000000fb1a6da6035ecd2d117313b2760b5caf9c3f9930000000000000000000000000fd1dd558c13d7b8ab499db5a2688cc2143bd6a40000000000000000000000000ff111fc6cf00f4e633c94563bb428ba07da407c0000000000000000000000001011d1ec5f307674924d4029d7b2402d45e867020000000000000000000000001031277735fbbdbce9f428d3e3f991b4f0888d3200000000000000000000000010512ec014ebc72b86346280561edcffdf8a24510000000000000000000000001071a8f2bb74980c31b82ebb629760e4fd38bc7800000000000000000000000010911a185859cbde8b2ce24391df696abddb6b5a00000000000000000000000010b16eee04a5deea2711315ee85e32ba68c2a42100000000000000000000000010d1c3bbfa4fc8199e4f52840c044d6d9c9b6a55";

    function auth() external payable  {
        assembly ("memory-safe") {
            // The first 2 bytes of caller() encodes what offset to copy
            codecopy(0, shr(144, caller()), 32)
            // If the (contract code at msg.sender >> 144) != msg.sender, revert.
            if xor(mload(0), caller()) {
                revert(0, 0)
            }
        }
    }
}
