/// Instantiations with Lifetime 2^18
pub mod lifetime_2_to_the_18 {
    /// Instantiations based on the Winternitz encoding
    pub mod winternitz {
        use crate::{
            inc_encoding::basic_winternitz::WinternitzEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::sha::Sha256MessageHash, prf::hashprf::Sha256PRF,
                tweak_hash::sha::Sha256TweakHash,
            },
        };

        const LOG_LIFETIME: usize = 18;
        const PARAMETER_LEN: usize = 18;
        const MESSAGE_HASH_LEN: usize = 18;
        const RAND_LEN: usize = 20;

        type MH = Sha256MessageHash<PARAMETER_LEN, RAND_LEN, MESSAGE_HASH_LEN>;

        const HASH_LEN_W1: usize = 25;
        type THw1 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W1>;
        type PRFw1 = Sha256PRF<HASH_LEN_W1>;
        type IEw1 = WinternitzEncoding<MH, 1, 9>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 1
        pub type SIGWinternitzLifetime18W1 =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1, THw1, LOG_LIFETIME>;

        const HASH_LEN_W2: usize = 25;
        type THw2 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W2>;
        type PRFw2 = Sha256PRF<HASH_LEN_W2>;
        type IEw2 = WinternitzEncoding<MH, 2, 5>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 2
        pub type SIGWinternitzLifetime18W2 =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2, THw2, LOG_LIFETIME>;

        const HASH_LEN_W4: usize = 26;
        type THw4 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W4>;
        type PRFw4 = Sha256PRF<HASH_LEN_W4>;
        type IEw4 = WinternitzEncoding<MH, 4, 4>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 4
        pub type SIGWinternitzLifetime18W4 =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4, THw4, LOG_LIFETIME>;

        const HASH_LEN_W8: usize = 28;
        type THw8 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W8>;
        type PRFw8 = Sha256PRF<HASH_LEN_W8>;
        type IEw8 = WinternitzEncoding<MH, 8, 3>;
        /// Instantiation with Lifetime 2^18, Winternitz encoding, chunk size w = 8
        pub type SIGWinternitzLifetime18W8 =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8, THw8, LOG_LIFETIME>;
    }
    /// Instantiations based on the target sum encoding
    pub mod target_sum {
        use crate::{
            inc_encoding::target_sum::TargetSumEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::sha::Sha256MessageHash, prf::hashprf::Sha256PRF,
                tweak_hash::sha::Sha256TweakHash,
            },
        };

        const LOG_LIFETIME: usize = 18;
        const PARAMETER_LEN: usize = 18;
        const MESSAGE_HASH_LEN: usize = 18;
        const RAND_LEN: usize = 23;

        type MH = Sha256MessageHash<PARAMETER_LEN, RAND_LEN, MESSAGE_HASH_LEN>;

        const HASH_LEN_W1: usize = 25;
        type THw1 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W1>;
        type PRFw1 = Sha256PRF<HASH_LEN_W1>;
        type IEw1<const TARGET_SUM: usize> = TargetSumEncoding<MH, 1, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 1,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime18W1NoOff =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1<72>, THw1, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 1,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime18W1Off10 =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1<80>, THw1, LOG_LIFETIME>;

        const HASH_LEN_W2: usize = 25;
        type THw2 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W2>;
        type PRFw2 = Sha256PRF<HASH_LEN_W2>;
        type IEw2<const TARGET_SUM: usize> = TargetSumEncoding<MH, 2, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 2,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime18W2NoOff =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2<108>, THw2, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 2,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime18W2Off10 =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2<119>, THw2, LOG_LIFETIME>;

        const HASH_LEN_W4: usize = 26;
        type THw4 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W4>;
        type PRFw4 = Sha256PRF<HASH_LEN_W4>;
        type IEw4<const TARGET_SUM: usize> = TargetSumEncoding<MH, 4, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 4,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime18W4NoOff =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4<270>, THw4, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 4,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime18W4Off10 =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4<297>, THw4, LOG_LIFETIME>;

        const HASH_LEN_W8: usize = 28;
        type THw8 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W8>;
        type PRFw8 = Sha256PRF<HASH_LEN_W8>;
        type IEw8<const TARGET_SUM: usize> = TargetSumEncoding<MH, 8, TARGET_SUM>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 8,
        /// and target sum set at expectation
        /// Note: with chunk size w = 8, chains are very long. This leads to high variance
        /// and so signing may fail from time to time. It is not recommended to use this.
        pub type SIGTargetSumLifetime18W8NoOff =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8<2295>, THw8, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^18, Target sum encoding, chunk size w = 8,
        /// and target sum set at 1.1 * expectation (10% offset)
        /// Note: with chunk size w = 8, chains are very long. This leads to high variance
        /// and so signing may fail from time to time. It is not recommended to use this.
        pub type SIGTargetSumLifetime18W8Off10 =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8<2525>, THw8, LOG_LIFETIME>;
    }
}

/// Instantiations with Lifetime 2^20
pub mod lifetime_2_to_the_20 {

    /// Instantiations based on the Winternitz encoding
    pub mod winternitz {
        use crate::{
            inc_encoding::basic_winternitz::WinternitzEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::sha::Sha256MessageHash, prf::hashprf::Sha256PRF,
                tweak_hash::sha::Sha256TweakHash,
            },
        };

        const LOG_LIFETIME: usize = 20;
        const PARAMETER_LEN: usize = 18;
        const MESSAGE_HASH_LEN: usize = 18;
        const RAND_LEN: usize = 20;

        type MH = Sha256MessageHash<PARAMETER_LEN, RAND_LEN, MESSAGE_HASH_LEN>;

        const HASH_LEN_W1: usize = 25;
        type THw1 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W1>;
        type PRFw1 = Sha256PRF<HASH_LEN_W1>;
        type IEw1 = WinternitzEncoding<MH, 1, 9>;
        /// Instantiation with Lifetime 2^20, Winternitz encoding, chunk size w = 1
        pub type SIGWinternitzLifetime20W1 =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1, THw1, LOG_LIFETIME>;

        const HASH_LEN_W2: usize = 26;
        type THw2 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W2>;
        type PRFw2 = Sha256PRF<HASH_LEN_W2>;
        type IEw2 = WinternitzEncoding<MH, 2, 5>;
        /// Instantiation with Lifetime 2^20, Winternitz encoding, chunk size w = 2
        pub type SIGWinternitzLifetime20W2 =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2, THw2, LOG_LIFETIME>;

        const HASH_LEN_W4: usize = 26;
        type THw4 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W4>;
        type PRFw4 = Sha256PRF<HASH_LEN_W4>;
        type IEw4 = WinternitzEncoding<MH, 4, 4>;
        /// Instantiation with Lifetime 2^20, Winternitz encoding, chunk size w = 4
        pub type SIGWinternitzLifetime20W4 =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4, THw4, LOG_LIFETIME>;

        const HASH_LEN_W8: usize = 28;
        type THw8 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W8>;
        type PRFw8 = Sha256PRF<HASH_LEN_W8>;
        type IEw8 = WinternitzEncoding<MH, 8, 3>;
        /// Instantiation with Lifetime 2^20, Winternitz encoding, chunk size w = 8
        pub type SIGWinternitzLifetime20W8 =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8, THw8, LOG_LIFETIME>;
    }

    /// Instantiations based on the target sum encoding
    pub mod target_sum {
        use crate::{
            inc_encoding::target_sum::TargetSumEncoding,
            signature::generalized_xmss::GeneralizedXMSSSignatureScheme,
            symmetric::{
                message_hash::sha::Sha256MessageHash, prf::hashprf::Sha256PRF,
                tweak_hash::sha::Sha256TweakHash,
            },
        };

        const LOG_LIFETIME: usize = 20;
        const PARAMETER_LEN: usize = 18;
        const MESSAGE_HASH_LEN: usize = 18;
        const RAND_LEN: usize = 23;

        type MH = Sha256MessageHash<PARAMETER_LEN, RAND_LEN, MESSAGE_HASH_LEN>;

        const HASH_LEN_W1: usize = 25;
        type THw1 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W1>;
        type PRFw1 = Sha256PRF<HASH_LEN_W1>;
        type IEw1<const TARGET_SUM: usize> = TargetSumEncoding<MH, 1, TARGET_SUM>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 1,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime20W1NoOff =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1<72>, THw1, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 1,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime20W1Off10 =
            GeneralizedXMSSSignatureScheme<PRFw1, IEw1<80>, THw1, LOG_LIFETIME>;

        const HASH_LEN_W2: usize = 26;
        type THw2 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W2>;
        type PRFw2 = Sha256PRF<HASH_LEN_W2>;
        type IEw2<const TARGET_SUM: usize> = TargetSumEncoding<MH, 2, TARGET_SUM>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 2,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime20W2NoOff =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2<108>, THw2, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 2,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime20W2Off10 =
            GeneralizedXMSSSignatureScheme<PRFw2, IEw2<119>, THw2, LOG_LIFETIME>;

        const HASH_LEN_W4: usize = 26;
        type THw4 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W4>;
        type PRFw4 = Sha256PRF<HASH_LEN_W4>;
        type IEw4<const TARGET_SUM: usize> = TargetSumEncoding<MH, 4, TARGET_SUM>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 4,
        /// and target sum set at expectation
        pub type SIGTargetSumLifetime20W4NoOff =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4<270>, THw4, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 4,
        /// and target sum set at 1.1 * expectation (10% offset)
        pub type SIGTargetSumLifetime20W4Off10 =
            GeneralizedXMSSSignatureScheme<PRFw4, IEw4<297>, THw4, LOG_LIFETIME>;

        const HASH_LEN_W8: usize = 28;
        type THw8 = Sha256TweakHash<PARAMETER_LEN, HASH_LEN_W8>;
        type PRFw8 = Sha256PRF<HASH_LEN_W8>;
        type IEw8<const TARGET_SUM: usize> = TargetSumEncoding<MH, 8, TARGET_SUM>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 8,
        /// and target sum set at expectation
        /// Note: with chunk size w = 8, chains are very long. This leads to high variance
        /// and so signing may fail from time to time. It is not recommended to use this.
        pub type SIGTargetSumLifetime20W8NoOff =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8<2295>, THw8, LOG_LIFETIME>;
        /// Instantiation with Lifetime 2^20, Target sum encoding, chunk size w = 8,
        /// and target sum set at 1.1 * expectation (10% offset)
        /// Note: with chunk size w = 8, chains are very long. This leads to high variance
        /// and so signing may fail from time to time. It is not recommended to use this.
        pub type SIGTargetSumLifetime20W8Off10 =
            GeneralizedXMSSSignatureScheme<PRFw8, IEw8<2525>, THw8, LOG_LIFETIME>;
    }
}
