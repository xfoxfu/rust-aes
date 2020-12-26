pub trait LengthMode {
    /// key length
    type NkWords: typenum::Unsigned;
    /// block size
    type NbWords: typenum::Unsigned;
    /// round key size (which equals `max(Nk, Nb) + 7`)
    type NrKey: typenum::Unsigned;
    /// round count (which equals `max(Nk, Nb) + 5`)
    type Nr: typenum::Unsigned;
}

macro_rules! impl_length_mode {
    ($s:ident, $nk:ty, $nb:ty) => {
        pub struct $s;

        impl LengthMode for $s {
            type NkWords = $nk;
            type NbWords = $nb;
            type NrKey = typenum::Sum<typenum::Maximum<$nk, $nb>, typenum::U7>;
            type Nr = typenum::Sum<typenum::Maximum<$nk, $nb>, typenum::U5>;
        }
    };
}

impl_length_mode!(AES128, typenum::U4, typenum::U4);
impl_length_mode!(AES192, typenum::U6, typenum::U4);
impl_length_mode!(AES256, typenum::U8, typenum::U4);
