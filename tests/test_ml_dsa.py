import unittest
import os
import json
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87


class TestMLDSA(unittest.TestCase):
    """
    Test ML DSA for internal consistency by generating signatures
    and verifying them!
    """

    def generic_test_ml_dsa(self, ML_DSA, count=5):
        for _ in range(count):
            msg = b"Signed by ML_DSA" + os.urandom(16)
            ctx = os.urandom(128)

            # Perform signature process
            pk, sk = ML_DSA.keygen()
            sig = ML_DSA.sign(sk, msg, ctx=ctx)
            check_verify = ML_DSA.verify(pk, msg, sig, ctx=ctx)

            check_short_verify = ML_DSA.verify(pk, msg, sig[:-1], ctx=ctx)
            check_long_verify = ML_DSA.verify(pk, msg, sig + b"\x00", ctx=ctx)
            check_empty_verify = ML_DSA.verify(pk, msg, b"", ctx=ctx)

            # Sign with external_mu instead
            external_mu = ML_DSA.prehash_external_mu(pk, msg, ctx=ctx)
            sig_external_mu = ML_DSA.sign_external_mu(sk, external_mu)
            check_external_mu = ML_DSA.verify(pk, msg, sig_external_mu, ctx=ctx)

            # Generate some fail cases
            pk_bad, _ = ML_DSA.keygen()
            check_wrong_pk = ML_DSA.verify(pk_bad, msg, sig, ctx=ctx)
            check_wrong_msg = ML_DSA.verify(pk, b"", sig, ctx=ctx)
            check_no_ctx = ML_DSA.verify(pk, msg, sig)

            # Generate the public key directly from the secret key
            recovered_pk = ML_DSA.pk_from_sk(sk)

            # Check that recovering the pk works
            self.assertEqual(pk, recovered_pk)

            # Check that signature works
            self.assertTrue(check_verify)

            # Check that too short signature is rejected
            self.assertFalse(check_short_verify)

            # Check that too short signature is rejected
            self.assertFalse(check_long_verify)

            # Check that empty signature is rejected
            self.assertFalse(check_empty_verify)

            # Check that external_mu also works
            self.assertTrue(check_external_mu)

            # Check changing the key breaks verify
            self.assertFalse(check_wrong_pk)

            # Check changing the message breaks verify
            self.assertFalse(check_wrong_msg)

            # Check removing the context breaks verify
            self.assertFalse(check_no_ctx)

    def test_ml_dsa_44(self):
        self.generic_test_ml_dsa(ML_DSA_44)

    def test_ml_dsa_65(self):
        self.generic_test_ml_dsa(ML_DSA_65)

    def test_ml_dsa_87(self):
        self.generic_test_ml_dsa(ML_DSA_87)


class TestMLDSADeterministic(unittest.TestCase):
    """
    Test ML DSA for internal consistency by generating signatures
    and verifying them!
    """

    def generic_test_ml_dsa(self, ML_DSA, count=5):
        for _ in range(count):
            msg = b"Signed by ML_DSA" + os.urandom(16)
            ctx = os.urandom(128)

            # Perform signature process
            pk, sk = ML_DSA.keygen()
            sig = ML_DSA.sign(sk, msg, ctx=ctx, deterministic=True)
            check_verify = ML_DSA.verify(pk, msg, sig, ctx=ctx)

            # Sign with external_mu instead
            external_mu = ML_DSA.prehash_external_mu(pk, msg, ctx=ctx)
            sig_external_mu = ML_DSA.sign_external_mu(
                sk, external_mu, deterministic=True
            )
            check_external_mu = ML_DSA.verify(pk, msg, sig_external_mu, ctx=ctx)

            # Generate some fail cases
            pk_bad, _ = ML_DSA.keygen()
            check_wrong_pk = ML_DSA.verify(pk_bad, msg, sig, ctx=ctx)
            check_wrong_msg = ML_DSA.verify(pk, b"", sig, ctx=ctx)
            check_no_ctx = ML_DSA.verify(pk, msg, sig)

            # Check that signature works
            self.assertTrue(check_verify)

            # Check that external_mu also works
            self.assertTrue(check_external_mu)

            # Check changing the key breaks verify
            self.assertFalse(check_wrong_pk)

            # Check changing the message breaks verify
            self.assertFalse(check_wrong_msg)

            # Check removing the context breaks verify
            self.assertFalse(check_no_ctx)

    def test_ml_dsa_44(self):
        self.generic_test_ml_dsa(ML_DSA_44)

    def test_ml_dsa_65(self):
        self.generic_test_ml_dsa(ML_DSA_65)

    def test_ml_dsa_87(self):
        self.generic_test_ml_dsa(ML_DSA_87)

    def test_derive_with_wrong_seed_length(self):
        with self.assertRaises(ValueError) as e:
            ML_DSA_44.key_derive(bytes(range(31)))

        self.assertIn("seed must be 32 bytes long", str(e.exception))

    # test vectors copied from
    # https://datatracker.ietf.org/doc/html/draft-ietf-lamps-dilithium-certificates-07
    def test_derive_from_seed_ML_DSA_44(self):
        pk, _ = ML_DSA_44.key_derive(bytes(range(32)))

        exp_pk = bytes.fromhex(
            """
                d7b2b47254aae0db45e7930d4a98d2c97d8f1397d1789dafa17024b316e9bec9
                4fc9946d42f19b79a7413bbaa33e7149cb42ed5115693ac041facb988adeb5fe
                0e1d8631184995b592c397d2294e2e14f90aa414ba3826899ac43f4cccacbc26
                e9a832b95118d5cb433cbef9660b00138e0817f61e762ca274c36ad554eb22aa
                c1162e4ab01acba1e38c4efd8f80b65b333d0f72e55dfe71ce9c1ebb9889e7c5
                6106c0fd73803a2aecfeafded7aa3cb2ceda54d12bd8cd36a78cf975943b47ab
                d25e880ac452e5742ed1e8d1a82afa86e590c758c15ae4d2840d92bca1a5090f
                40496597fca7d8b9513f1a1bda6e950aaa98de467507d4a4f5a4f0599216582c
                3572f62eda8905ab3581670c4a02777a33e0ca7295fd8f4ff6d1a0a3a7683d65
                f5f5f7fc60da023e826c5f92144c02f7d1ba1075987553ea9367fcd76d990b7f
                a99cd45afdb8836d43e459f5187df058479709a01ea6835935fa70460990cd3d
                c1ba401ba94bab1dde41ac67ab3319dcaca06048d4c4eef27ee13a9c17d0538f
                430f2d642dc2415660de78877d8d8abc72523978c042e4285f4319846c441262
                42976844c10e556ba215b5a719e59d0c6b2a96d39859071fdcc2cde7524a7bed
                ae54e85b318e854e8fe2b2f3edfac9719128270aafd1e5044c3a4fdafd9ff31f
                90784b8e8e4596144a0daf586511d3d9962b9ea95af197b4e5fc60f2b1ed15de
                3a5bef5f89bdc79d91051d9b2816e74fa54531efdc1cbe74d448857f476bcd58
                f21c0b653b3b76a4e076a6559a302718555cc63f74859aabab925f023861ca8c
                d0f7badb2871f67d55326d7451135ad45f4a1ba69118fbb2c8a30eec9392ef3f
                977066c9add5c710cc647b1514d217d958c7017c3e90fd20c04e674b90486e93
                70a31a001d32f473979e4906749e7e477fa0b74508f8a5f2378312b83c25bd38
                8ca0b0fff7478baf42b71667edaac97c46b129643e586e5b055a0c211946d4f3
                6e675bed5860fa042a315d9826164d6a9237c35a5fbf495490a5bd4df248b95c
                4aae7784b605673166ac4245b5b4b082a09e9323e62f2078c5b76783446defd7
                36ad3a3702d49b089844900a61833397bc4419b30d7a97a0b387c1911474c4d4
                1b53e32a977acb6f0ea75db65bb39e59e701e76957def6f2d44559c31a77122b
                5204e3b5c219f1688b14ed0bc0b801b3e6e82dcd43e9c0e9f41744cd9815bd1b
                c8820d8bb123f04facd1b1b685dd5a2b1b8dbbf3ed933670f095a180b4f192d0
                8b10b8fabbdfcc2b24518e32eea0a5e0c904ca844780083f3b0cd2d0b8b6af67
                bc355b9494025dc7b0a78fa80e3a2dbfeb51328851d6078198e9493651ae787e
                c0251f922ba30e9f51df62a6d72784cf3dd205393176dfa324a512bd94970a36
                dd34a514a86791f0eb36f0145b09ab64651b4a0313b299611a2a1c4889162759
                8768a3114060ba4443486df51522a1ce88b30985c216f8e6ed178dd567b304a0
                d4cafba882a28342f17a9aa26ae58db630083d2c358fdf566c3f5d62a428567b
                c9ea8ce95caa0f35474b0bfa8f339a250ab4dfcf2083be8eefbc1055e18fe153
                70eecb260566d83ff06b211aaec43ca29b54ccd00f8815a2465ef0b46515cc7e
                41f3124f09efff739309ab58b29a1459a00bce5038e938c9678f72eb0e4ee5fd
                aae66d9f8573fc97fc42b4959f4bf8b61d78433e86b0335d6e9191c4d8bf487b
                3905c108cfd6ac24b0ceb7dcb7cf51f84d0ed687b95eaeb1c533c06f0d97023d
                92a70825837b59ba6cb7d4e56b0a87c203862ae8f315ba5925e8edefa679369a
                2202766151f16a965f9f81ece76cc070b55869e4db9784cf05c830b3242c8312
            """
        )

        self.assertEqual(len(pk), len(exp_pk))
        self.assertEqual(pk, exp_pk)

    # test vectors copied from
    # https://datatracker.ietf.org/doc/html/draft-ietf-lamps-dilithium-certificates-07
    def test_derive_from_seed_ML_DSA_65(self):
        pk, _ = ML_DSA_65.key_derive(bytes(range(32)))

        exp_pk = bytes.fromhex(
            """
            48683d91978e31eb3dddb8b0473482d2b88a5f625949fd8f58a561e696bd4c27
            d05b38dbb2edf01e664efd81be1ea893688ce68aa2d51c5958f8bbc6eb4e89ee
            67d2c0320954d57212cac7229ff1d6eaf03928bd51511f8d88d847736c7de273
            0d5978e5410713160978867711bf5539a0bfc4c350c2be572baf0ee2e2fb16cc
            fea08028d99ac49aebb75937ddce111cdab62fff3cea8ba2233d1e56fbc5c5a1
            e726de63fadd2af016b119177fa3d971a2d9277173fce55b67745af0b7c21d59
            7dbeb93e6a32f341c49a5a8be9e825088d1f2aa45155d6c8ae15367e4eb003b8
            fdf7851071949739f9fff09023eaf45104d2a84a45906eed4671a44dc28d2798
            7bb55df69e9e8561f61a80a72699503865fed9b7ee72a8e17a19c408144f4b29
            afef7031c3a6d8571610b42c9f421245a88f197e16812b031159b65b9687e5b3
            e934c5225ae98a79ba73d2b399d73510effad19e53b8450f0ba8fce1012fd98d
            260a74aaaa13fae249a006b1c34f5ba0b882f26378222fb36f2283c243f0ffeb
            5f1bb414a0a70d55e3d40a56b6cbc88ae1f03b7b2882d98deea28e145c9dedfd
            8eaf1cef2ed94a8b050f8964f46d1ea0d0c2a43e0dda6182adbf4f6ed175b674
            2257859bf22f3a417ecf1f9d89317b5e539d587af16b9e1313e04514ffa64ba8
            b3ff2b8321f8811cb3fb022c8f644e70a4b80a2fbfee604abb7379091ea8e6c5
            c74dfc0283666b40c0793870028204a136bf5da9568eb798d349038bdb0c11e0
            3445e7847cb5069c75cf28ac601c7799d958210ddbcb226e51afef9f1de47b07
            3873d6d3f97456bede085082e74a298b2cd48f4b3093155f366c8fa601c6af85
            8dfa32c08491b2a29887f90335949a5d6edaa679882a3a95d6bf6d970a221f4b
            9d3d8cbf384af81aac95e2b3294e04789ac83727a5dc04559f96af41d8a05351
            6feeeebc52746eb6ab2819e09108710d835f011fa63065872ad334d5cdffb2b2
            310507e92fc993ae317da97f4f309cdaf0f67ed99d90215576083849f953b246
            d7fedb3fdb67679850a5ad404e64147fb7cf4f6aeddd05afb4b834968d1fe880
            14960dce5d942236526e12a478d69e5fbe6970310b308c06845018cfc7b2ab43
            0a13a6b1ac7bb02cccbb3d911ac2f11068613fbe029bfdce02cf5cd38950ed72
            c83944edfbc75615af87f864c051f3c55456c5412863a40c06d1dab562bdff05
            71b8d3c3917bbd300880bba5e998239b95fa91b7d6416d4f398b3adbcd30983e
            d3592b4d9ef7d4236fd00f50d98aa53a235ac4172720f77d96172672980cfe8f
            f7a5a702783edc2ba31b2259015a112fc7f468a9c2f9464039002d30ef678b4c
            b798bc116216bf7a9a7c18ba03b7b58fd07515d3115049d3614be7a07e744300
            750df1d2c58753389059eafc3d785ccdd31c07648bedc03a5c3b8ad46d064d59
            c13d57374729fc4e295362e2a5191204530428bc1522afa28ff5fe1655e304ca
            5bc8c27ad0e0c6a39dd4df28956c14b38cc93682cefe402bbd5e82d29c464e44
            eb5d37b48fc568dfe0cc6e8e16baea05e5135590f19294e73e8367b0216dbb81
            5030b9de55913f08039c42351c59e5515dd5af8e089a15e625e8f6dee639386c
            46497d7a263288774de581a7de9629b41b4424141f978fb8331208efdec3c6e0
            de39bc57063f3dcd6c470373c08891ea29cbc7cc6d6483b8889083ace86aa7b5
            1b1c2cfe6e2ad18d97ce36fbc56ea42fae97e6a7ac114864478c366df1ebb1e7
            b11a9098504fd5975bdf1f49dc70002b63c1739a9d263fbad4073f6a9f6c2b8a
            f4b4c332a103a0cffa5deeb2d062ca3c215fd360026be7c5164f4a4424ef7494
            8804d66f46487732c8202c795478647b4ea71d627c086024cca354a41f0877b3
            8f19b3774ad2095c8da53b069e21c76ae2d2007e16719ed40080d334f7da52e9
            f5a5990439caf083a95b833f02ad10a08c1a6d0f260c007285bd4a2f47703a5a
            ef465287d253b18ac22514316210ff566814b10f87a293d6f199d3c3959990d0
            c1268b4f50d5f9fcefbbf237bd0c28b80182d6659741f14f10bfbb21bba12ab6
            20aa2396f56c0686b4ea9017990224216b2fe8ad76c4a9148eef9a86a3635a6a
            a77bc1dcfb6fba59a77dfda9b7530dc0ca8648c8d973738e01bab8f08b4905e8
            4aa4641bd602410cd97520265f2f231f2b35e15eb2fa04d2bd94d5a77abaf1e0
            e161010a990087f5b46ea988b2bc0512fda0fa923dadd6c45c5301d094836732
            65b5ab2e10f4ba520f6bbad564a5c3d5e27bdb080f7d20e13296a3181954c39c
            649c943ebe17df5c1f7aae0a8fe126c477585a5d4d648a0d008b6af5e8cd31be
            69a9296d4f3fd25ed86f221e4b93f65f5929967533624b9235750c30707550b5
            8536d109a7131c5a5bbe4a5715567c12534aec7660761eebb9fae2891c774589
            b80e566ad557ddef7367196b7227ea9870ef09ddfec79d6b9319a6879b5205d7
            6bf7aba5acf33afb59d17fc54e68383d6be5a08e9b66da53dcde008bb294b858
            2bd132cdcc49959fdbc21e52721880c8ad0352c79f03a43bbd84c4cdfdc6c529
            005e1e7cd9a349a7168a35569ba5dea818968d5a91466bd6e64e20bf62417198
            afc4e81c28dd77ed4028232398b52fbde86bc84f475b9016710ce2aabc11a06b
            4dbac901ec16cf365ca3f2d53813948a693a0f93e79c46ca5d5a6dca3d28ca50
            ad18bd13fca55059dd9b185f79f9c47196a4e81b2104bc460a051e02f2e8444f
        """
        )

        self.assertEqual(len(pk), len(exp_pk))
        self.assertEqual(pk, exp_pk)

    # test vectors copied from
    # https://datatracker.ietf.org/doc/html/draft-ietf-lamps-dilithium-certificates-07
    def test_derive_from_seed_ML_DSA_87(self):
        pk, _ = ML_DSA_87.key_derive(bytes(range(32)))

        exp_pk = bytes.fromhex(
            """
            9792bcec2f2430686a82fccf3c2f5ff665e771d7ab41b90258cfa7e90ec97124
            a73b323b9ba21ab64d767c433f5a521effe18f86e46a188952c4467e048b729e
            7fc4d115e7e48da1896d5fe119b10dcddef62cb307954074b42336e52836de61
            da941f8d37ea68ac8106fabe19070679af6008537120f70793b8ea9cc0e6e7b7
            b4c9a5c7421c60f24451ba1e933db1a2ee16c79559f21b3d1b8305850aa42afb
            b13f1f4d5b9f4835f9d87dfceb162d0ef4a7fdc4cba1743cd1c87bb4967da16c
            c8764b6569df8ee5bdcbffe9a4e05748e6fdf225af9e4eeb7773b62e8f85f9b5
            6b548945551844fbd89806a4ac369bed2d256100f688a6ad5e0a709826dc4449
            e91e23c5506e642361ef5a313712f79bc4b3186861ca85a4bab17e7f943d1b8a
            333aa3ae7ce16b440d6018f9e04daf5725c7f1a93fad1a5a27b67895bd249aa9
            1685de20af32c8b7e268c7f96877d0c85001135a4f0a8f1b8264fa6ebe5a349d
            8aecad1a16299ccf2fd9c7b85bace2ced3aa1276ba61ee78ed7e5ca5b67cdd45
            8a9354030e6abbbabf56a0a2316fec9dba83b51d42fd3167f1e0f90855d5c665
            09b210265dc1e54ec44b43ba7cf9aef118b44d80912ce75166a6651e116cebe4
            9229a7062c09931f71abd2293f76f7efc3215ba97800037e58e470bdbbb43c1b
            0439eaf79c54d93b44aac9efe9fbe151874cfb2a64cbee28cc4c0fe7775e5d87
            0f1c02e5b2e3c5004c995f24c9b779cb753a277d0e71fd425eb6bc2ca56ce129
            db51f70740f31e63976b50c7312e9797d78c5b1ac24a5fa347cc916e0a83f5c3
            b675cd30b81e3fa10b93444e07397571cce98b28da51db9056bc728c5b0b1181
            e2fbd387b4c79ab1a5fefece37167af772ddad14eb4c3982da5a59d0e9eb173e
            c6315091170027a3ab5ef6aa129cb8585727b9358a28501d713a72f3f1db3171
            4286f9b6408013af06045d75592fc0b7dd47c73ed9c75b11e9d7c69f7cadfc32
            80a9062c5273c43be1c34f87448864cea7b5c97d6d32f59bd5f25384653bb5c4
            faa45bea8b89402843e645b6b9269e2bd988ddacb033328ffb060450f7df0800
            53e6969b251e875ecec32cfc592840d69ab69a75e06b379c535d95266b082f4f
            09c93162b33b0d9f7307a4eaaa52104437fed66f8ee3eabbd45d67b25a8133f4
            96468b52baffdbfad93eef1a9818b5e42ec722788a3d8d3529fc777d2ba57080
            1dfae01ec88302837c1fb9e0355727645ee1046c3f915f6ae82dad4fb6b0356a
            46518ffc834155c3b4fe6dafa6cc8a5ccf53c73a0849d8d44f7dcf72754e70e1
            b7dfb447bb4ef49d1a718f6171bbce200950e0ce926106b151a3e871d5ce4973
            1bd6650a9b0ca972da1c5f136d44820ea6383c08f3b384cf2338e789c513f618
            cc5694a6f0cee104511e1ed7c5f23a1ebfd8a0db8424553240156dbf622831b0
            c643d1c551b6f3f7a98d29b85c2de05a65fa615eee16495bd90737672115b53e
            91c5d90028cf3f1a93953a153de53b44084e9ccff6b736693926daefebb2d77a
            a5ad689b92f31686669df16d1715cc58f7a2cfb72dd1a51e92f825993a74022b
            e7e9eb6054654457094d14928f20215e7b222ac56b51adbec8d8bdb6983979a7
            e3a21b44b5d1518ca97d0b5195f51ed6a24350c89747e1edea51b448e3e91470
            54ce927873c90db394d86888e07dff177593d6f79e152302204aeb03be2386af
            3e24078bd028b1689f5e147c9f452c8ceb02ec59cc9db63a03576ceeafe98239
            023897da0236630a53c0de7f435a19869792fab36e7b9e635760f09069e6432e
            700035ac2a02879fff0a1e1bec522047193d94eb5df1efd53eea1144ca789408
            52f5ec9727904b366ede4f5e2d331fad5fc282ea2c47e923142771c3dd75a873
            57487def99e5f18e9d9ed623c175d02888c51f82c07a80d54716b3c3c2bdbe2e
            9f0a9bbaaebeb4d52936876406f5c00e8e4bbd0a5ec05797e6207c5ab6c88f1a
            688421bd05a114f4d7de2ac241fa0e8bedff47f762ddcbeaa91004f8d31e8509
            5c81054994ad3826e344ba96040810fc0b2ad1de48cfade002c62e5a49a0731a
            b38344bc1636df16bf607d56855e56d684003c718e4bad9e5a099979fcddeeb1
            c4a7776cd37a3417cb0e184e29ef9bc0e87475ba663be09e00ab562eb7c0f716
            5f969a9b42414198ccf1bff2a2c8d689a414ece7662927665689e94db961ebae
            c5615cbc1a7895c6851ac961432ff1118d4607d32ef9dc732d51333be4b4d0e3
            0ddea784eca8be47e741be9c19631dc470a52ef4dc13a4f3633fd434d787c170
            977b417df598e1d0dde506bb71d6f0bc17ec70e3b03cdc1965cb36993f633b04
            72e50d0923ac6c66fdf1d3e6459cc121f0f5f94d09e9dbcf5d690e23233838a0
            bacb7c638d1b2650a4308cd171b6855126d1da672a6ed85a8d78c286fb56f4ab
            3d21497528045c63262c8a42af2f9802c53b7bb8be28e78fe0b5ce45fbb7a1af
            1a3b28a8d94b7890e3c882e39bc98e9f0ad76025bf0dd2f00298e7141a226b3d
            7cee414f604d1e0ba54d11d5fe58bccea6ad77ad2e8c1caacf32459014b7b910
            01b1efa8ad172a523fb8e365b577121bf9fd88a2c60c21e821d7b6acb47a5a99
            5e40caced5c223b8fe6de5e18e9d2e5893aefebb7aae7ff1a146260e2f110e93
            9528213a0025a38ec79aabc861b25ebc509a4674c132aaacb7e0146f14efd11c
            fcaf4caa4f775a716ce325e0a435a4d349d720bcf137450afc45046fc1a1f83a
            9d329777a7084e4aadae7122ce97005930528eb3c7f7f1129b372887a371155a
            3ba201a25cbf1dcb64e7cdee092c3141fb5550fe3d0dd82e870e578b2b465008
            18113b8f6569773c677385b69a42b77dcba7acffd95fd4452e23aaa1d37e1da2
            151ea658d40a3596b27ac9f8129dc6cf0643772624b59f4f461230df471ca260
            87c3942d5c6687df6082835935a3f87cb762b0c3b1d0dda4a6533965bef1b7b8
            292e254c014d090fed857c44c1839c694c0a64e3fad90a11f534722b6ee1574f
            2e149d55d744de4887024e08511431c062750e16c74ab9f3242f2db3ffb12a8d
            6107faa229d6f6373b07f36d3932b3bdb04c19dd64eadd7f93c3c564c358a1c8
            1dcf1c9c31e5b06568f97544c17dc15698c5cb38983a9afc42783faa773a52c9
            d8260690be9e3156aa5bc1509dea3f69587695cd6ff172ba83e6a6d8a7d6bbeb
            bbcda3672731983f89bc5831dc37c3f3c5c56facc697f3cb20bd5dbadbd702e5
            4844ac2f626901fe159db93dfd4773d8fe73562b846c1fc856d1802762840ebc
            72d7988bde75cbca70d319d32ce0cc0253bb2ad455723ee0c7f4736ce6e6665c
            5aca32a481c53839bc259167b013d0423395eeb9aaaee3206149a7d550d67fc5
            fdfe4a8a5c35d2510b664379ab8f72855a2af47abce2a632048eaf89e5cb4a88
            debc53a595103acce4f1cff18acff07afe1eb5716aa1e40b63134c3a3ae9579f
            a87f515be093c2d29db6d6b65c93661e00636b592704d093cc6716c2342eb185
            3d48c85c63ac8a2854462c7b77e7e3bd1eac5bca28ffaa00b5d349f8a547ad87
            5b96a8c2b2910c9301309a3f9138a5693111f55b3c009ca947c39dfc82d98eb1
            caa4a9cbe885f786fa86e55be062222f8ba90a974073326b31212aece0a34a60
            """
        )

        self.assertEqual(len(pk), len(exp_pk))
        self.assertEqual(pk, exp_pk)


class TestML_DSA_KAT(unittest.TestCase):
    """
    Test ML-DSA against test vectors collected from
    https://github.com/usnistgov/ACVP-Server/releases/tag/v1.1.0.35
    """

    def generic_keygen_kat(self, ML_DSA, index):
        with open("assets/ML-DSA-keyGen-FIPS204/internalProjection.json") as f:
            data = json.load(f)
        kat_data = data["testGroups"][index]["tests"]

        for test in kat_data:
            seed = bytes.fromhex(test["seed"])
            pk_kat = bytes.fromhex(test["pk"])
            sk_kat = bytes.fromhex(test["sk"])

            pk, sk = ML_DSA._keygen_internal(seed)
            self.assertEqual(pk, pk_kat)
            self.assertEqual(sk, sk_kat)

    def generic_sign_kat(self, ML_DSA, index, deterministic=False):
        with open("assets/ML-DSA-sigGen-FIPS204/internalProjection.json") as f:
            data = json.load(f)
        if deterministic:
            kat_data = data["testGroups"][2 * index]["tests"]
        else:
            kat_data = data["testGroups"][2 * index + 1]["tests"]

        for test in kat_data:
            sk_kat = bytes.fromhex(test["sk"])
            msg_kat = bytes.fromhex(test["message"])
            sig_kat = bytes.fromhex(test["signature"])

            if deterministic:
                rng_kat = bytes([0]) * 32
            else:
                rng_kat = bytes.fromhex(test["rng"])

            sig = ML_DSA._sign_internal(sk_kat, msg_kat, rng_kat)
            self.assertEqual(sig, sig_kat)

    def generic_verify_kat(self, ML_DSA, index):
        with open("assets/ML-DSA-sigVer-FIPS204/internalProjection.json") as f:
            data = json.load(f)
        pk_kat = bytes.fromhex(data["testGroups"][index]["pk"])
        kat_data = data["testGroups"][index]["tests"]

        for test in kat_data:
            check_kat = test["testPassed"]
            msg_kat = bytes.fromhex(test["message"])
            sig_kat = bytes.fromhex(test["signature"])

            check = ML_DSA._verify_internal(pk_kat, msg_kat, sig_kat)
            self.assertEqual(check, check_kat)

    def test_ML_DSA_44_keygen(self):
        self.generic_keygen_kat(ML_DSA_44, 0)

    def test_ML_DSA_65_keygen(self):
        self.generic_keygen_kat(ML_DSA_65, 1)

    def test_ML_DSA_87_keygen(self):
        self.generic_keygen_kat(ML_DSA_87, 2)

    def test_ML_DSA_44_sign(self):
        self.generic_sign_kat(ML_DSA_44, 0, deterministic=True)

    def test_ML_DSA_65_sign(self):
        self.generic_sign_kat(ML_DSA_65, 1, deterministic=True)

    def test_ML_DSA_87_sign(self):
        self.generic_sign_kat(ML_DSA_87, 2, deterministic=True)

    def test_ML_DSA_44_verify(self):
        self.generic_verify_kat(ML_DSA_44, 0)

    def test_ML_DSA_65_verify(self):
        self.generic_verify_kat(ML_DSA_65, 1)

    def test_ML_DSA_87_verify(self):
        self.generic_verify_kat(ML_DSA_87, 2)
