// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Contract.sol";
import {console2} from "forge-std/console2.sol";

contract ContractTest is Test {
    Contract internal c;
    function setUp() public {
        c = new Contract();
    }

    function testAuth() public {
        address[128] memory addresses = [0x00F168F0A7A69e02D8379cEc46b71B0f8e7aA9FE, 0x0111ED73B85755938b678860872c55E150454Cc7, 0x01310172B9E19abE024d476E8008A924d348438e, 0x01518A8f54aDB7523c8edFB04E700E6742f6D51a, 0x01714DE2709fBBBaeBD0F42cFC2176BE1B8630E4, 0x01916409c86fb1ee6AC6b9717a1eE382D5112B25, 0x01b1C4146FAC00C0a579a227d46b140C98c24b92, 0x01d18e9C65bd513693Bd88A443c6242c366e3DC9, 0x01f18b73cC356241b1379a5709A5B8307F92e117, 0x0211FCEF20d8D9B4a39fD6E4DA78DEc0A43A5985, 0x02317681355377f112955aea3FD9670c353Fc981, 0x0251f55DDdd0fb9E0CAB2b0175858e2a581B8205, 0x0271A85d0c74B69A39a9d5a8d59a0d7926eb64AF, 0x029146c471828df7D54311cb2DEe8e8930f2b367, 0x02b1f7f8872bD28Fa4Bf04dE7001537fB1F43058, 0x02D1DA320Fb46Fd4277Ce484EFE85568738272d1, 0x02F14d5Bd7332dcFCa39fb312DD14D67570d4f8b, 0x03118e420E894DD190Dbd0B40bad481A094f1163, 0x03312058aE8759034cED88C53b16Fdc8Ce3aC3DB, 0x03518698cBA0805ba88a2157370AC0C8198A6AAd, 0x0371E4208C3CD24d9D7Ea60e4CbF0FC44580D2Ee, 0x0391F51DE9353AA9F07de461929c7a5340d879F4, 0x03B17f39cB8E088bdD5bD2436cd7ff9057172Cbe, 0x03d1Cc5F092E198894E8FeE03fAad2C0a6A300C1, 0x03F196ad378aE7341A4FeeFaAf53e50722Ae1d77, 0x041160e150921017231DA8f185b0307463d40281, 0x0431cE921260F6509CD761009c5b706b8EAC12D1, 0x0451ef291eE0b37cbf2CAD4b95B4CAEe0e656190, 0x0471CD91922A5C5bC0aFE6Bc772FE174442C4847, 0x049133fD9509320b1B6f686Db4D708D9897ca1F3, 0x04b180B394a66A7974AEb06C3625C0aC11ad74F2, 0x04D1A97dF1A2b5C09F7257CB579A1268eD35ce4b, 0x04F113f56B934dDF068ed8Ce3ed7fD2639786F2F, 0x05110020C3A3ac343b4d6baFc4457CB3f8A912D0, 0x0531eBd5949673b6f46902beC0AcC798dca6DCc5, 0x0551CAC715d559FE14d7eDbA24E50ca79c4814C0, 0x0571c49f1D4D19Eee2B4801Dac6aA00Cd95027b9, 0x05914a854af9ef68b802711F7EBAc7dCd80187B0, 0x05B1F3DAc64c43F578c07B08A9Ae3b315CebF210, 0x05D116d13015634cADcf925701090351D8d16960, 0x05f1b4c3eFef3F840045E085315293Aa2F1084A3, 0x06111e780972D0bf6be7092d7183E2B75602Be5E, 0x0631938E0A9bE2639156a6Bd50012E67C9c8B6Ec, 0x0651e227b934BBD4237B94d4c092E2C59992f3d7, 0x0671a7D1FD513054f9DC6F9f21F692a18D85478D, 0x06912BF68f1BF1e8e8E67ae8B3aFff88010372c2, 0x06B1AD902cF3c5549fc44c20680378bbDb2C743E, 0x06D157688af9188D36FF5ABf0f2b8c848e41Cd75, 0x06f1Db9908b256155072c2F3C1fAc7dDeD4aFd36, 0x071184E402BEBE7e8cB3c90318b77BEAAC38de73, 0x073154bF6fDd36B5097531212aa462FB139bF452, 0x0751552AefdCf2c7A783F4B455c8CCF5Aa34701D, 0x0771B8AbbdA3B9B2b13F983472925d14aD610EE1, 0x0791411Ceb5037b437853DbD60BaBe97E6B832D9, 0x07B1081F0cFAF6b70a2eCA3a518E42cC4A434fcd, 0x07D186753A8eF3d284ee10C57bFD89Ba13412262, 0x07F1C2F88296739C035a9Ac1Bc67f63f6A60c94C, 0x0811B4d4DCc02b85e89a7BB042B31f0830773425, 0x083130b9553dC95F235C49be6ff1511F550f050e, 0x08517A2f6A4F316D595Bbb5a75F089D021568897, 0x08715562b4cF6aa8C811f9e91917725DC97e4bE6, 0x08919C3051E7952637f0617964f5fe67AFBE04f2, 0x08B1c257363cBdf0d4cff48F86eb0b770D37a1eF, 0x08D11ff806bcC5BAB2DC53A06b94FD2654e616E9, 0x08F1964561ed41e32EB0aE0b48c10bF676902C55, 0x09116a3F8847352D650CE7C7dC7250Ce1A26cd8e, 0x0931A426037505d7114a798Ec16c121aB2A6D1A7, 0x0951022d5ba1aAa6dAcb93cFafdE12F8C47827a9, 0x0971cf94C9A16E16E7311f33D34772149d8bC341, 0x09916c14Dd3bAd92158497E27256F679e4849f9d, 0x09B1dfEb7Eb85b76c446A4Cdd8d21902609db7A5, 0x09d1DeEb7a32fA1Aa08a772D583D3CEc9E4D6C6c, 0x09f125ae695b6971eDd68d5600df32C0FcB98daC, 0x0a119b0f49E867eA4C85485fE434DD7aD3fA989a, 0x0A31834a85C7228acF6599Be29B307328b2C1100, 0x0a518cd93196c620D28618eBF120a0EB274fFf71, 0x0a717426D141255a153594ed1F44557B26272214, 0x0a91CA27F2dAaB97a2cFcF1C6d488c0Bd3ccCE29, 0x0ab1c144302235bBcd1621eD0429a0855a34F080, 0x0AD10dB91678b0DF08e0C1e964815C9F6b95054F, 0x0AF1197CCaEEba8e33F923CE67be7E1Ee0a1f10c, 0x0b113Ae75509B87706D4B3aFB40CA66172B60300, 0x0b31338389ac8501D0c6C929F214DA4E2CE0ad76, 0x0B51789dB9f3198b4832bf21495823307BDB3485, 0x0b7109c58AfA9cE521A9EcB9d1584D45929c2f33, 0x0b91b84a8733391bfA6cd7856c29840A2EC74cbc, 0x0bB11A66C0B0D08149DE3856c5AD7228511586Fc, 0x0bd1DE8D59A06D9EEf064571D473470a0711AC0B, 0x0bF15A0Da2A49a028adc042A3cAB1022aE466dd2, 0x0C11035Bf7edACb2FB307946cb03318c4ccD60AA, 0x0C319B5f8257caB4f5E598d16cDD61932448407e, 0x0c51643a45afb59114Cc9D9951e1a068ADB66E77, 0x0C714d6393fDE1A15d4C515bf1f4a2f9D52A3157, 0x0c91475DF26d98C14da057b4b20510760298254D, 0x0cB1F22D2180C9DC942530eC50B7e5547440692F, 0x0CD18f43af4a0302f0A8ba1A6bd4375ed1284d86, 0x0Cf1766f57F78478D3EeF57647e7757Ca121e638, 0x0D111Fa5C040fa67eBCa764B9306933420Cca25B, 0x0D31b0Bf86277D702cD26e07C9417C8244e9856f, 0x0D51d60A05B6760C31521B6A6e228f8Dbb0428A5, 0x0D71ce01cFdbf57daA63C257c36a79f0c389861e, 0x0d91Df5DF9Cf3E844272b95f053FD339594c1D31, 0x0db1C42682Db0496F95581D259778deCF9B0815F, 0x0dD136728E41D22ACaAB0888e7f461d272C98390, 0x0DF192A0251a39CD93Cc9b4d5cE1f63018d1Ba89, 0x0E11076763fd2D521E129f8CE7B63f51bb48d410, 0x0e316eB9a00DCB3905bb80a8ceD888551DF55D00, 0x0e51aEF8d91aaabaea38432ecaB400bEe9a292B3, 0x0e719607461D7A9051726C2A0F5F681Cf2a439D3, 0x0e91A20D9c6e2A84F35211995bc5f151C2eE5aed, 0x0eB1A369A3F337906c5405f57E5ca014E74a1dED, 0x0eD19c605780a3268B1CaD3Aef526Bb0e6da1395, 0x0eF15bc434035B036520801507b66Cc0C5EbCb5A, 0x0f11F12126b86b1BeAF523190F846D96592638b9, 0x0F31b0de788F55741B587E3a65951A521Be61f1b, 0x0f5173C6dCF2F8B60019455980F2C9f587f843A4, 0x0f7182b54c22743c7Bdb6a8fA5c90c6C95c4e93B, 0x0f9105FD3DF24DE31C25A072256949dd7ACc245E, 0x0fB1a6DA6035ecd2D117313b2760b5Caf9C3F993, 0x0FD1DD558C13d7B8ab499db5a2688cC2143bD6A4, 0x0ff111Fc6cf00f4E633c94563bB428BA07DA407c, 0x1011d1eC5F307674924d4029d7B2402d45e86702, 0x1031277735FBBDbCe9f428d3E3f991B4f0888D32, 0x10512ec014Ebc72B86346280561eDCFfDF8A2451, 0x1071A8F2BB74980C31B82eBb629760E4fd38Bc78, 0x10911A185859cbDE8B2cE24391DF696abdDb6b5A, 0x10b16EEe04A5dEea2711315EE85e32Ba68c2a421, 0x10d1C3bbfa4fc8199E4f52840C044D6d9c9B6a55];
        for (uint i = 0; i < addresses.length; i++) {
            vm.prank(addresses[i]);
            c.auth();
        }
    }

    // test_get_offset and getCodeAt taken from libevm's CPO:
    // https://github.com/libevm/cpo/blob/master/src/test/CPO.t.sol
    function test_get_offset() public {
        c = new Contract();

        address impl = 0x00F168F0A7A69e02D8379cEc46b71B0f8e7aA9FE;
        address a = address(c);

        bytes memory bytecode = getCodeAt(a);
        address extractedAddress;
        uint256 offset = 0;

        for (uint256 i = 0; i < bytecode.length; i++) {
            assembly {
                extractedAddress := mload(add(add(bytecode, 20), i))
            }

            if (extractedAddress == impl) {
                offset = i-12;
                break;
            }
        }

        emit log_string("immutable address offset");
        emit log_uint(offset);

        // Uncomment to get creation code
        // emit log_string("proxy creation code");
        // emit log_bytes(type(Proxy).creationCode);

        // emit log_string("proxy runtime code");
        // emit log_bytes(bytecode);

        assertGt(offset, 0);
    }

    function getCodeAt(address _addr)
    internal
    view
    returns (bytes memory o_code)
    {
        assembly {
        // retrieve the size of the code, this needs assembly
        let size := extcodesize(_addr)
        // allocate output byte array - this could also be done without assembly
        // by using o_code = new bytes(size)
        o_code := mload(0x40)
        // new "memory end" including padding
        mstore(
            0x40,
            add(o_code, and(add(add(size, 0x20), 0x1f), not(0x1f)))
        )
        // store length in memory
        mstore(o_code, size)
        // actually retrieve the code, this needs assembly
        extcodecopy(_addr, add(o_code, 0x20), 0, size)
        }
    }
}