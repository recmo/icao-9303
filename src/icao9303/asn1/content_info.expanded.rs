mod content_info {
    //! A compile time typed version of `ContentInfo`
    //!
    //! See [`cms::content_info::ContentInfo`] for a dynamic version.
    use der::{
        asn1::{ContextSpecific, ContextSpecificRef, ObjectIdentifier},
        Decode, DecodeValue, Encode, EncodeValue, Error, ErrorKind, Header, Length,
        Reader, Result, Sequence, Tag, TagMode, TagNumber, Writer,
    };
    pub trait ContentType: Encode + for<'a> Decode<'a> {
        const CONTENT_TYPE: ObjectIdentifier;
    }
    /// The `ContentInfo` type is defined in [RFC 5652 Section 3].
    ///
    /// ```text
    ///   ContentInfo ::= SEQUENCE {
    ///       contentType        CONTENT-TYPE.
    ///                       &id({ContentSet}),
    ///       content            [0] EXPLICIT CONTENT-TYPE.
    ///                       &Type({ContentSet}{@contentType})}
    /// ```
    ///
    /// [RFC 5652 Section 3]: https://www.rfc-editor.org/rfc/rfc5652#section-3
    pub struct ContentInfo<T: ContentType>(T);
    #[automatically_derived]
    impl<T: ::core::clone::Clone + ContentType> ::core::clone::Clone for ContentInfo<T> {
        #[inline]
        fn clone(&self) -> ContentInfo<T> {
            ContentInfo(::core::clone::Clone::clone(&self.0))
        }
    }
    #[automatically_derived]
    impl<T: ::core::fmt::Debug + ContentType> ::core::fmt::Debug for ContentInfo<T> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(f, "ContentInfo", &&self.0)
        }
    }
    #[automatically_derived]
    impl<T: ::core::cmp::Eq + ContentType> ::core::cmp::Eq for ContentInfo<T> {
        #[inline]
        #[doc(hidden)]
        #[coverage(off)]
        fn assert_receiver_is_total_eq(&self) -> () {
            let _: ::core::cmp::AssertParamIsEq<T>;
        }
    }
    #[automatically_derived]
    impl<T: ContentType> ::core::marker::StructuralPartialEq for ContentInfo<T> {}
    #[automatically_derived]
    impl<T: ::core::cmp::PartialEq + ContentType> ::core::cmp::PartialEq
    for ContentInfo<T> {
        #[inline]
        fn eq(&self, other: &ContentInfo<T>) -> bool {
            self.0 == other.0
        }
    }
    impl<'a, T: ContentType> Sequence<'a> for ContentInfo<T> {}
    impl<'a, T: ContentType> DecodeValue<'a> for ContentInfo<T> {
        fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
            reader
                .read_nested(
                    header.length,
                    |reader| {
                        let content_type = reader.decode()?;
                        if content_type != T::CONTENT_TYPE {
                            return Err(
                                Error::new(
                                    ErrorKind::OidUnknown {
                                        oid: content_type,
                                    },
                                    reader.position(),
                                ),
                            );
                        }
                        let content = match ContextSpecific::decode(reader)? {
                            field if field.tag_number == TagNumber::N0 => Some(field),
                            _ => None,
                        }
                            .ok_or_else(|| {
                                Tag::ContextSpecific {
                                    number: TagNumber::N0,
                                    constructed: false,
                                }
                                    .value_error()
                            })?
                            .value;
                        Ok(Self(content))
                    },
                )
        }
    }
    impl<'a, T: ContentType> EncodeValue for ContentInfo<T> {
        fn value_len(&self) -> Result<Length> {
            let content_type_len = T::CONTENT_TYPE.encoded_len()?;
            let content_len = ContextSpecificRef {
                tag_number: TagNumber::N0,
                tag_mode: TagMode::Explicit,
                value: &self.0,
            }
                .encoded_len()?;
            Ok(content_type_len + content_len)
        }
        fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
            T::CONTENT_TYPE.encode(writer)?;
            ContextSpecificRef {
                tag_number: TagNumber::N0,
                tag_mode: TagMode::Explicit,
                value: &self.0,
            }
                .encode(writer)?;
            Ok(())
        }
    }
}
