use nalgebra::SMatrix;

pub trait RijndaelMode
{
    /// key length
    const NK_WORDS: usize;
    /// block size
    const NB_WORDS: usize;
    /// round key size (which equals `max(Nk, Nb) + 7`)
    const NR_KEY: usize;
    /// round count (which equals `max(Nk, Nb) + 5`)
    const NR: usize;

    // type State = SMatrix<u8, 4, { Self::NB_WORDS }> where [(); Self::NB_WORDS]:;
}

macro_rules! impl_length_mode {
    ($s:ident, $nk:literal, $nb:literal) => {
        pub struct $s;

        impl crate::aes::RijndaelMode for $s {
            const NK_WORDS: usize = $nk;
            const NB_WORDS: usize = $nb;
            // the following are trick to address unstable associated default types
            // https://github.com/rust-lang/rust/issues/29661
            const NR_KEY: usize = crate::max($nk, $nb) + 7;
            const NR: usize = crate::max($nk, $nb) + 5;
        }
    };
}

impl_length_mode!(AES128, 4, 4);
impl_length_mode!(AES192, 6, 4);
impl_length_mode!(AES256, 8, 4);
