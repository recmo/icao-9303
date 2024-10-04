use {
    crate::ensure_err,
    cms::signed_data::SignedData,
    der::{
        asn1::ObjectIdentifier as Oid, AnyRef, Decode, DecodeValue, EncodeValue, Error, ErrorKind,
        Length, Sequence, SliceReader, Tag, Tagged,
    },
};

pub const ID_SIGNED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct DocumentSecurityObject {
    pub contents: IdentifiedData<SignedData>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct IdentifiedData<T: for<'a> Sequence<'a>> {
    // Should be `ID_SIGNED_DATA`
    pub oid: Oid,

    #[asn1(context_specific = "0")]
    pub contents: T,
}

/// Helper function to read a DER-encoded value with an application specific tag.
pub fn read_with_tag<T>(data: &[u8], tag: Tag) -> Result<T, Error>
where
    T: for<'a> DecodeValue<'a>,
{
    let any = AnyRef::from_der(data)?;
    ensure_err!(
        any.tag() == tag,
        Error::new(
            ErrorKind::TagUnexpected {
                expected: Some(tag),
                actual: any.tag()
            },
            Length::new(0)
        )
    );
    let header = any.header()?;
    let mut reader = SliceReader::new(any.value())?;
    let value = T::decode_value(&mut reader, header)?;
    Ok(value)
}
