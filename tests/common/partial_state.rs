// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5
//
// Unless explicitly acquired and licensed from Licensor under another license,
// the contents of this file are subject to the Reciprocal Public License
// ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
// may not copy or use this file in either source code or executable form,
// except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS"
// basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
// HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
// ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
// rights and limitations under the RPL.

#![allow(dead_code)]
use ::serde::de::value::Error;
use ::serde::{Serialize, Serializer, ser::Impossible};
pub struct Bytes;
macro_rules! scalar {($($name:ident($t:ty)),* $(,)?)=>{$(fn $name(self,_:$t)->Result<Vec<u8>,Error> {Err(::serde::ser::Error::custom("only bytes accepted"))})*};}
impl Serializer for Bytes {
    type Ok = Vec<u8>;
    type Error = Error;
    type SerializeSeq = Impossible<Vec<u8>, Error>;
    type SerializeTuple = Impossible<Vec<u8>, Error>;
    type SerializeTupleStruct = Impossible<Vec<u8>, Error>;
    type SerializeTupleVariant = Impossible<Vec<u8>, Error>;
    type SerializeMap = Impossible<Vec<u8>, Error>;
    type SerializeStruct = Impossible<Vec<u8>, Error>;
    type SerializeStructVariant = Impossible<Vec<u8>, Error>;
    scalar!(
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_f32(f32),
        serialize_f64(f64),
        serialize_char(char),
        serialize_str(&str)
    );
    fn serialize_bytes(self, v: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(v.to_vec())
    }
    fn serialize_none(self) -> Result<Vec<u8>, Error> {
        Err(::serde::ser::Error::custom("only bytes accepted"))
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<Vec<u8>, Error> {
        self.serialize_none()
    }
    fn serialize_unit(self) -> Result<Vec<u8>, Error> {
        self.serialize_none()
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<Vec<u8>, Error> {
        self.serialize_none()
    }
    fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<Vec<u8>, Error> {
        self.serialize_none()
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _: &'static str, _: &T) -> Result<Vec<u8>, Error> {
        self.serialize_none()
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<Vec<u8>, Error> {
        self.serialize_none()
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Err(::serde::ser::Error::custom("only bytes accepted"))
    }
    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Error> {
        self.serialize_seq(None)
    }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeTupleStruct, Error> {
        self.serialize_seq(None)
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        self.serialize_seq(None)
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Error> {
        self.serialize_seq(None)
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self::SerializeStruct, Error> {
        self.serialize_seq(None)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        self.serialize_seq(None)
    }
}

pub fn roundtrip<T: Serialize + for<'de> ::serde::Deserialize<'de>>(state: &T) -> T {
    let bytes = state.serialize(Bytes).unwrap();
    T::deserialize(::serde::de::value::BytesDeserializer::<Error>::new(&bytes)).unwrap()
}
