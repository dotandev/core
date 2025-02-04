extern crate alloc;
use alloc::borrow::Cow;
use alloc::vec::Vec as StdVec;
use std::fmt::Display;

use bs58;
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use soroban_sdk::xdr::{FromXdr, ToXdr};
use soroban_sdk::{contracterror, contracttype, Bytes, BytesN, Env, String, Vec};

use super::StellarProxyMutateRequest;
use crate::repr::{Repr, ReprBytes, ReprError, ReprTransmute};
use crate::types::{
    Application, ApplicationMetadata, ApplicationSource, Capability, ConfigError, IntoResult,
    SignerId,
};
use crate::{ContextRequest, ContextRequestKind, RequestKind};

#[derive(Clone, Debug, Copy)]
#[contracterror]
pub enum StellarProxyError {
    AlreadyInitialized = 1,
    Unauthorized = 2,
    ProposalNotFound = 3,
    ProposalAlreadyApproved = 4,
    TooManyActiveProposals = 5,
    InvalidAction = 6,
    ExecutionFailed = 7,
    InsufficientBalance = 8,
    TransferFailed = 9,
}

// Trait for environment-aware conversion
pub trait FromWithEnv<T> {
    fn from_with_env(value: T, env: &Env) -> Self;
}

// Core types for Application
#[derive(Clone, Debug)]
#[contracttype]
pub struct StellarApplication {
    pub id: BytesN<32>,
    pub blob: BytesN<32>,
    pub size: u64,
    pub source: String,
    pub metadata: Bytes,
}

impl<'a> FromWithEnv<Application<'a>> for StellarApplication {
    fn from_with_env(value: Application<'a>, env: &Env) -> Self {
        StellarApplication {
            id: BytesN::from_array(env, &value.id.rt().expect("infallible conversion")),
            blob: BytesN::from_array(env, &value.blob.rt().expect("infallible conversion")),
            size: value.size,
            source: String::from_str(env, &value.source.0),
            metadata: Bytes::from_slice(env, &value.metadata.0),
        }
    }
}

impl<'a> From<StellarApplication> for Application<'a> {
    fn from(value: StellarApplication) -> Self {
        let mut bytes = vec![0u8; value.source.len() as usize];
        value.source.copy_into_slice(&mut bytes);
        let std_string = std::string::String::from_utf8(bytes).expect("valid utf8");

        Application::new(
            value.id.rt().expect("infallible conversion"),
            value.blob.rt().expect("infallible conversion"),
            value.size,
            ApplicationSource(Cow::Owned(std_string)),
            ApplicationMetadata(Repr::new(Cow::Owned(value.metadata.to_alloc_vec()))),
        )
    }
}

// Request structures
#[derive(Clone, Debug)]
#[contracttype]
pub struct StellarContextRequest {
    pub context_id: BytesN<32>,
    pub kind: StellarContextRequestKind,
}

impl<'a> FromWithEnv<ContextRequest<'a>> for StellarContextRequest {
    fn from_with_env(value: ContextRequest<'a>, env: &Env) -> Self {
        let context_id =
            BytesN::from_array(env, &value.context_id.rt().expect("infallible conversion"));
        let kind = StellarContextRequestKind::from_with_env(value.kind, env);
        Self { context_id, kind }
    }
}

#[derive(Clone, Debug, Copy)]
#[contracttype]
pub enum StellarCapability {
    ManageApplication,
    ManageMembers,
    Proxy,
}

impl From<Capability> for StellarCapability {
    fn from(value: Capability) -> Self {
        match value {
            Capability::ManageApplication => StellarCapability::ManageApplication,
            Capability::ManageMembers => StellarCapability::ManageMembers,
            Capability::Proxy => StellarCapability::Proxy,
        }
    }
}

impl From<StellarCapability> for Capability {
    fn from(value: StellarCapability) -> Self {
        match value {
            StellarCapability::ManageApplication => Capability::ManageApplication,
            StellarCapability::ManageMembers => Capability::ManageMembers,
            StellarCapability::Proxy => Capability::Proxy,
        }
    }
}

// Request types without named fields in enum variants
#[derive(Clone, Debug)]
#[contracttype]
pub enum StellarContextRequestKind {
    Add(BytesN<32>, StellarApplication),
    UpdateApplication(StellarApplication),
    AddMembers(Vec<BytesN<32>>),
    RemoveMembers(Vec<BytesN<32>>),
    Grant(Vec<(BytesN<32>, StellarCapability)>),
    Revoke(Vec<(BytesN<32>, StellarCapability)>),
    UpdateProxyContract,
}

impl FromWithEnv<ContextRequestKind<'_>> for StellarContextRequestKind {
    fn from_with_env(value: ContextRequestKind<'_>, env: &Env) -> Self {
        match value {
            ContextRequestKind::Add {
                author_id,
                application,
            } => {
                let author_id =
                    BytesN::from_array(env, &author_id.rt().expect("infallible conversion"));
                let stellar_app = StellarApplication::from_with_env(application, env);
                StellarContextRequestKind::Add(author_id, stellar_app)
            }
            ContextRequestKind::UpdateApplication { application } => {
                StellarContextRequestKind::UpdateApplication(StellarApplication::from_with_env(
                    application,
                    env,
                ))
            }
            ContextRequestKind::AddMembers { members } => {
                let mut vec = Vec::new(&env);
                for member in members.into_owned() {
                    vec.push_back(BytesN::from_array(&env, &member.as_bytes()));
                }
                StellarContextRequestKind::AddMembers(vec)
            }
            ContextRequestKind::RemoveMembers { members } => {
                let mut vec = Vec::new(&env);
                for member in members.into_owned() {
                    vec.push_back(BytesN::from_array(&env, &member.as_bytes()));
                }
                StellarContextRequestKind::RemoveMembers(vec)
            }
            ContextRequestKind::Grant { capabilities } => {
                let mut vec = Vec::new(&env);
                for (id, cap) in capabilities.into_owned() {
                    vec.push_back((
                        BytesN::from_array(
                            &env,
                            &id.rt::<BytesN<32>>()
                                .expect("infallible conversion")
                                .as_bytes(),
                        ),
                        cap.into(),
                    ));
                }
                StellarContextRequestKind::Grant(vec)
            }
            ContextRequestKind::Revoke { capabilities } => {
                let mut vec = Vec::new(&env);
                for (id, cap) in capabilities.into_owned() {
                    vec.push_back((
                        BytesN::from_array(
                            &env,
                            &id.rt::<BytesN<32>>()
                                .expect("infallible conversion")
                                .as_bytes(),
                        ),
                        cap.into(),
                    ));
                }
                StellarContextRequestKind::Revoke(vec)
            }
            ContextRequestKind::UpdateProxyContract => {
                StellarContextRequestKind::UpdateProxyContract
            }
        }
    }
}

#[derive(Clone, Debug)]
#[contracttype]
pub enum StellarRequestKind {
    Context(StellarContextRequest),
}

impl<'a> FromWithEnv<RequestKind<'a>> for StellarRequestKind {
    fn from_with_env(value: RequestKind<'a>, env: &Env) -> Self {
        match value {
            RequestKind::Context(context) => {
                let stellar_context = StellarContextRequest::from_with_env(context, env);
                StellarRequestKind::Context(stellar_context)
            }
        }
    }
}

#[derive(Clone, Debug)]
#[contracttype]
pub struct StellarRequest {
    pub kind: StellarRequestKind,
    pub signer_id: BytesN<32>,
    pub nonce: u64,
}

impl StellarRequest {
    pub fn new(signer_id: BytesN<32>, kind: StellarRequestKind, nonce: u64) -> Self {
        Self {
            signer_id,
            kind,
            nonce,
        }
    }
}

#[derive(Clone, Debug)]
#[contracttype]
pub enum StellarSignedRequestPayload {
    Context(StellarRequest),
    Proxy(StellarProxyMutateRequest),
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct StellarSignedRequest {
    pub payload: Bytes,
    pub signature: BytesN<64>,
}

impl StellarSignedRequest {
    pub fn new<T, F>(env: &Env, payload: T, sign: F) -> Result<Self, StellarError>
    where
        T: Serialize,
        F: FnOnce(&[u8]) -> Result<ed25519_dalek::Signature, ed25519_dalek::SignatureError>,
    {
        // let payload = payload.to_xdr(env);
        let payload = serde_json::to_vec(&payload).unwrap();

        let signature = sign(&payload).map_err(|_| StellarError::InvalidSignature)?;
        let payload = Bytes::from_slice(env, &payload);
        Ok(Self {
            payload,
            signature: BytesN::from_array(env, &signature.to_bytes()),
        })
    }

    pub fn verify<'a, T, R, F>(&self, f: F) -> Result<SignerId, StellarError>
    where
        T: Deserialize<'a>,
        R: IntoResult<SignerId>,
        F: FnOnce(&T) -> R,
        <R as IntoResult<SignerId>>::Error: Display,
    {
        todo!()
        // let payload = self.payload.to_alloc_vec();
        // let parsed = serde_json::from_slice(&payload).unwrap();

        // let bytes = f(&parsed)
        //     .into_result()
        //     .map_err(ConfigError::DerivationError).unwrap();

        // let key = bytes
        //     .rt::<VerifyingKey>()
        //     .map_err(ConfigError::VerificationKeyParseError).unwrap();

        // key.verify(bytes, &self.signature)
        //     .map_or(Err(ConfigError::InvalidSignature), |()| Ok(parsed))
        // let bytes = self.payload.to_xdr(env);

        // let payload = StellarSignedRequestPayload::from_xdr(env, &self.payload).unwrap();

        // println!("payload: {:#?}", payload);
        // // Get signer_id based on payload type
        // let signer_id = match &payload {
        //     StellarSignedRequestPayload::Context(req) => &req.signer_id,
        //     StellarSignedRequestPayload::Proxy(req) => match req {
        //         StellarProxyMutateRequest::Propose(proposal) => &proposal.author_id,
        //         StellarProxyMutateRequest::Approve(approval) => &approval.signer_id,
        //     },
        // };

        // env.crypto()
        //     .ed25519_verify(signer_id, &self.payload, &self.signature);

        // Ok(payload)
    }
}

impl ReprBytes for BytesN<32> {
    type EncodeBytes<'a>
        = [u8; 32]
    where
        Self: 'a;
    type DecodeBytes = [u8; 32];
    type Error = bs58::decode::Error;

    fn as_bytes(&self) -> Self::EncodeBytes<'_> {
        self.to_array()
    }

    fn from_bytes<F>(f: F) -> Result<Self, ReprError<Self::Error>>
    where
        F: FnOnce(&mut Self::DecodeBytes) -> Result<usize, bs58::decode::Error>,
    {
        let mut bytes = [0u8; 32];
        match f(&mut bytes) {
            Ok(_) => {
                let env = Env::default();
                Ok(BytesN::from_array(&env, &bytes))
            }
            Err(e) => Err(ReprError::InvalidBase58(e)),
        }
    }
}

// Contract error enum (keep this for contract errors)
#[contracterror]
#[derive(Copy, Clone, Debug)]
pub enum StellarError {
    InvalidSignature = 1,
    Unauthorized = 2,
    ContextExists = 3,
    ContextNotFound = 4,
    InvalidNonce = 5,
    ProxyCodeNotSet = 6,
    NotAMember = 7,
    InvalidState = 8,
    ProxyUpgradeFailed = 9,
    InvalidRequest = 10,
}
