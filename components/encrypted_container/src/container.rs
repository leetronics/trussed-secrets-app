// Copyright (C) 2023 Nitrokey GmbH
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use cbor_smol::{cbor_deserialize, cbor_serialize_to};
use heapless_bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::Serialize;
use trussed_core::{
    mechanisms::Chacha8Poly1305,
    try_syscall,
    types::{KeyId, Message},
};

/// Universal AEAD encrypted data container, using CBOR and Chacha8Poly1305
///
/// Encryption is realized by serializing the object using CBOR, then encrypting it using Chacha8Poly1305,
/// storing related crypto data, namely nonce and tag, and finally serializing the latter,
/// again using CBOR.
///
/// For the plaintext of size 48 bytes, the resulting container size is 87 bytes,
/// including the 28 bytes of cryptographic data overhead, and leaving 11 bytes
/// as the CBOR serialization overhead.
///
/// Decryption operation is done the same way as its counterpart, but backwards.
/// The serialized Encrypted Data Container in bytes is first deserialized, making a EDC instance,
/// and afterwards the decryption operation in Trussed is called, resulting in a original serialized
/// object, which is then deserialized to a proper instance.
///
/// CBOR was chosen as the serialization format due to its simplicity and extensibility.
/// If that is a requirement, more space efficient and faster would be postcard. Be advised however,
/// that it's format changes between major revisions (as expected with semver versioning).
///
/// This type has implemented bidirectional serialization to trussed Message object.
///
/// Showing the processing paths graphically:
///
/// T -> \[u8\]: object -> CBOR serialization -> EncryptedDataContainer encryption  -> CBOR serialization -> serialized EncryptedDataContainer
///
/// \[u8\] -> T: serialized EncryptedDataContainer -> CBOR deserialization -> EncryptedDataContainer decryption -> CBOR deserialization -> object
///
/// Note: to decrease the CBOR overhead it might be useful to rename the serialized object fields for
/// the serialization purposes. Use the `#[serde(rename = "A")]` attribute.
///
/// The minimum buffer size for the serialization operation of a single encrypted+serialized credential
/// should be about 256 bytes (the current maximum packet length) + CBOR overhead (field names and map encoding) + encryption overhead (12 bytes nonce + 16 bytes tag).
/// The extra bytes could be used in the future, when operating on the password-extended credentials.
///
/// Usage example:
/// ```
/// # use encrypted_container::EncryptedDataContainer;
/// # use trussed::Client;
/// # use serde::Serialize;
/// # use trussed::client::Chacha8Poly1305;
/// # use trussed::types::{KeyId, Message};
/// # use secrets_app::encrypted_container::EncryptedDataContainer;
/// fn encrypt_unit<O: Serialize, T: Client + Chacha8Poly1305>(trussed: &mut T, obj: &O, ek: KeyId) -> Message {
///    let data = EncryptedDataContainer::from_obj(trussed, obj, None, ek).unwrap();
///    let data_serialized: Message = data.try_into().unwrap();
///    data_serialized
/// }
/// ```
/// Future work and extensions:
/// - Generalize over serialization method
/// - Generalize buffer size (currently buffer is based on the Message type)
/// - Investigate postcard structure extensibility, as a means for smaller overhead for serialization
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct EncryptedDataContainer {
    /// The encryption key type identifier.
    /// 0x01 = Hardware-based encryption (default)
    /// 0x02 = PIN-based encryption
    /// This field was added in v0.14.1 to fix PIN protection key isolation.
    /// For backward compatibility, it's optional and defaults to Hardware.
    #[serde(rename = "K", skip_serializing_if = "Option::is_none")]
    key_type: Option<u8>,
    /// The ciphertext. 1024 bytes maximum. Reusing trussed::types::Message.
    #[serde(rename = "D")]
    data: Message,
    #[serde(rename = "T")]
    tag: ContainerTag,
    #[serde(rename = "N")]
    nonce: ContainerNonce,
}

use crate::error::Error;
use crate::error::Result;

type ContainerTag = Bytes<16>;
type ContainerNonce = Bytes<12>;

/// Key type identifiers for encryption
pub const KEY_TYPE_HARDWARE: u8 = 0x01;
pub const KEY_TYPE_PIN_BASED: u8 = 0x02;

pub fn cbor_serialize_message<T: ?Sized + serde::Serialize>(value: &T) -> Result<Message> {
    let mut writer = Message::new();
    cbor_serialize_to(value, &mut writer).map_err(|_| Error::ObjectSerializationError)?;
    Ok(writer)
}

impl TryFrom<&[u8]> for EncryptedDataContainer {
    type Error = Error;

    /// Create an instance from this serialized Encrypted Data Container
    fn try_from(value: &[u8]) -> Result<Self> {
        cbor_deserialize(value).map_err(|_| Error::DeserializationToContainerError)
    }
}

impl TryFrom<EncryptedDataContainer> for Message {
    type Error = Error;

    /// Try to serialize EncryptedDataContainer to Bytes
    fn try_from(value: EncryptedDataContainer) -> Result<Self> {
        cbor_serialize_message(&value)
    }
}

impl EncryptedDataContainer {
    /// Get the key type from the container
    /// Returns KEY_TYPE_HARDWARE if not set (backward compatibility)
    pub fn key_type(&self) -> u8 {
        self.key_type.unwrap_or(KEY_TYPE_HARDWARE)
    }

    /// Check if this container uses PIN-based encryption
    pub fn is_pin_encrypted(&self) -> bool {
        self.key_type() == KEY_TYPE_PIN_BASED
    }

    /// Decrypt given Bytes and return original object instance
    /// Note: This will fail if the wrong key is provided.
    /// For key-type aware decryption, use decrypt_with_key_check().
    pub fn decrypt_from_bytes<T, O>(
        trussed: &mut T,
        ser_encrypted: &Message,
        encryption_key: KeyId,
    ) -> Result<O>
    where
        T: Chacha8Poly1305,
        O: DeserializeOwned,
    {
        let deserialized_container: EncryptedDataContainer =
            cbor_deserialize(ser_encrypted).map_err(|_| Error::DeserializationToContainerError)?;

        deserialized_container.decrypt(trussed, None, encryption_key)
    }

    /// Peek at the key type without fully deserializing
    /// This is useful for determining which key to use before attempting decryption
    pub fn peek_key_type(ser_encrypted: &Message) -> Option<u8> {
        // Try to deserialize just enough to get the key_type field
        // For CBOR, we need to parse the map structure
        // A simple heuristic: look for the "K" field in the CBOR map
        if ser_encrypted.len() < 3 {
            return None;
        }

        // Try full deserialization and extract key_type
        // This is not the most efficient but is simple and reliable
        if let Ok(container) = Self::try_from(ser_encrypted.as_slice()) {
            container.key_type
        } else {
            None
        }
    }

    /// Create Encrypted Data Container from the given object
    ///
    /// # Arguments
    /// * `key_type` - 0x01 for Hardware, 0x02 for PIN-based
    pub fn from_obj_with_key_type<T, O>(
        trussed: &mut T,
        obj: &O,
        associated_data: Option<&[u8]>,
        encryption_key: KeyId,
        key_type: u8,
    ) -> Result<EncryptedDataContainer>
    where
        T: Chacha8Poly1305,
        O: Serialize,
    {
        let message = cbor_serialize_message(obj)?;
        debug_now!("Plaintext size: {}", message.len());
        Self::encrypt_message_with_key_type(
            trussed,
            &message,
            associated_data,
            encryption_key,
            key_type,
        )
    }

    /// Create Encrypted Data Container from the given object (backward compatible, uses Hardware key type)
    pub fn from_obj<T, O>(
        trussed: &mut T,
        obj: &O,
        associated_data: Option<&[u8]>,
        encryption_key: KeyId,
    ) -> Result<EncryptedDataContainer>
    where
        T: Chacha8Poly1305,
        O: Serialize,
    {
        Self::from_obj_with_key_type(
            trussed,
            obj,
            associated_data,
            encryption_key,
            KEY_TYPE_HARDWARE,
        )
    }

    /// Encrypt given Bytes object, and return an Encrypted Data Container
    ///
    /// # Arguments
    /// * `key_type` - 0x01 for Hardware, 0x02 for PIN-based
    pub fn encrypt_message_with_key_type<T>(
        trussed: &mut T,
        message: &[u8],
        associated_data: Option<&[u8]>,
        encryption_key: KeyId,
        key_type: u8,
    ) -> Result<EncryptedDataContainer>
    where
        T: Chacha8Poly1305,
    {
        #[cfg(dangerous_disable_encryption)]
        {
            // Skipping error handling, as this feature is only for the debugging purposes
            return Ok(EncryptedDataContainer {
                key_type: Some(key_type),
                data: Message::from_slice(&message).unwrap(),
                nonce: Default::default(),
                tag: Default::default(),
            });
        }

        // nonce is provided internally via internal per-key counter, hence not passed here
        let encryption_results = try_syscall!(trussed.encrypt_chacha8poly1305(
            encryption_key,
            message,
            associated_data.unwrap_or_default(),
            None
        ))
        .map_err(|_| Error::FailedEncryption)?;

        let encrypted_serialized_credential = EncryptedDataContainer {
            key_type: Some(key_type),
            data: encryption_results.ciphertext,
            nonce: (&*encryption_results.nonce).try_into().unwrap(), // should always be 12 bytes
            tag: (&*encryption_results.tag).try_into().unwrap(),     // should always be 16 bytes
        };
        Ok(encrypted_serialized_credential)
    }

    /// Encrypt given Bytes object (backward compatible, uses Hardware key type)
    pub fn encrypt_message<T>(
        trussed: &mut T,
        message: &[u8],
        associated_data: Option<&[u8]>,
        encryption_key: KeyId,
    ) -> Result<EncryptedDataContainer>
    where
        T: Chacha8Poly1305,
    {
        Self::encrypt_message_with_key_type(
            trussed,
            message,
            associated_data,
            encryption_key,
            KEY_TYPE_HARDWARE,
        )
    }

    /// Decrypt the content of this Encrypted Data Instance, and deserialize to the original object
    pub fn decrypt<T, O>(
        &self,
        trussed: &mut T,
        associated_data: Option<&[u8]>,
        encryption_key: KeyId,
    ) -> Result<O>
    where
        T: Chacha8Poly1305,
        O: DeserializeOwned,
    {
        let message = self
            .decrypt_to_serialized(trussed, associated_data, encryption_key)
            .map_err(|_| Error::DeserializationToContainerError)?;
        cbor_deserialize(&message).map_err(|_| Error::DeserializationToObjectError)
    }

    /// Decrypt the content of this Encrypted Data Instance, and return the original serialized object
    pub fn decrypt_to_serialized<T>(
        &self,
        trussed: &mut T,
        associated_data: Option<&[u8]>,
        encryption_key: KeyId,
    ) -> Result<Message>
    where
        T: Chacha8Poly1305,
    {
        if self.data.is_empty() {
            return Err(Error::EmptyContainerData);
        }

        #[cfg(dangerous_disable_encryption)]
        {
            // Skipping error handling, as this feature is only for the debugging purposes
            return Ok(Message::from_slice(&self.data).unwrap());
        }

        let serialized = try_syscall!(trussed.decrypt_chacha8poly1305(
            encryption_key,
            &self.data,
            associated_data.unwrap_or_default(),
            &self.nonce,
            &self.tag
        ))
        .map_err(|_| Error::FailedDecryption)?
        .plaintext
        .ok_or(Error::EmptyDecryptedData)?;

        Ok(serialized)
    }
}
