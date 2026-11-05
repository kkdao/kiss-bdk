//! A [`Transport`] over one Marmot group: MLS encrypted group messaging
//! carried by nostr relays (the protocol behind White Noise), driven
//! through MDK, the Marmot Development Kit.
//!
//! Everything lives in `<wallet dir>/marmot/`:
//!
//! - `identity.key`: the nostr secret key (hex), mode 0600.
//! - `mls.json`: the MLS group state and the MDK group records, mode 0600.
//! - `state.json`: the relay list, the group, the peer, the receive cursor
//!   and the send counter.
//!
//! MDK's own SQLite store cannot be linked next to bdk_wallet (they need
//! different rusqlite versions), so the MLS state sits in the in-memory
//! stores from openmls and MDK and is written to `mls.json` after every
//! step that changes it.
//!
//! The [`Transport`] trait is synchronous while MDK's relay side is async,
//! so the type owns a tokio runtime and blocks on it.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use mdk_core::prelude::*;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use crate::transport::Transport;

/// Relays used when none are given. They are the defaults of White Noise,
/// so they are known to carry the Marmot event kinds (30443, 443, 444 in a
/// 1059 gift wrap, 445 and 10051).
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
];

/// Kind of the current (addressable) key package event, MIP-00.
const KIND_KEY_PACKAGE: u16 = 30443;
/// Inner event kind of an application message (a chat message in White
/// Noise terms).
const KIND_APP_MESSAGE: u16 = 9;
/// Tag carrying the per-sender message counter, so two messages sent in
/// the same second still come out in order.
const SEQ_TAG: &str = "kiss-seq";
/// How long one relay query may take.
const FETCH_TIMEOUT: Duration = Duration::from_secs(8);
/// Pause between two polls while waiting for a message.
const POLL_PAUSE: Duration = Duration::from_millis(700);

/// Write `bytes` to `path` through a temporary file, readable only by the
/// owner, so a crash never leaves half a file.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&tmp)
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

mod store {
    //! A storage provider for MDK whose contents can be saved to a file.
    //!
    //! The MLS half delegates to openmls' memory store, whose key/value map
    //! is public; the MDK half delegates to MDK's memory store and is saved
    //! by reading its records back through the storage traits.

    use std::collections::{BTreeSet, HashMap};
    use std::ops::Deref;
    use std::sync::Arc;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use mdk_memory_storage::MdkMemoryStorage;
    use mdk_storage_traits::groups::GroupStorage;
    use mdk_storage_traits::groups::error::GroupError;
    use mdk_storage_traits::groups::types::*;
    use mdk_storage_traits::messages::MessageStorage;
    use mdk_storage_traits::messages::error::MessageError;
    use mdk_storage_traits::messages::types::*;
    use mdk_storage_traits::welcomes::WelcomeStorage;
    use mdk_storage_traits::welcomes::error::WelcomeError;
    use mdk_storage_traits::welcomes::types::*;
    use mdk_storage_traits::{Backend, GroupId, MdkStorageError, MdkStorageProvider};
    use nostr_sdk::prelude::{EventId, PublicKey, RelayUrl};
    use openmls_memory_storage::{MemoryStorage, MemoryStorageError};
    use openmls_traits::storage::{CURRENT_VERSION, StorageProvider, traits};
    use serde::{Deserialize, Serialize};

    pub struct Inner {
        mls: MemoryStorage,
        mdk: MdkMemoryStorage,
    }

    /// Cheap to clone: MDK owns one handle and the transport keeps another
    /// to save the state.
    #[derive(Clone)]
    pub struct Store(Arc<Inner>);

    impl Deref for Store {
        type Target = Inner;
        fn deref(&self) -> &Inner {
            &self.0
        }
    }

    #[derive(Serialize, Deserialize, Default)]
    struct Saved {
        mls: Vec<(String, String)>,
        groups: Vec<Group>,
        relays: Vec<GroupRelay>,
        secrets: Vec<GroupExporterSecret>,
        legacy_secrets: Vec<GroupExporterSecret>,
        mip04_secrets: Vec<GroupExporterSecret>,
    }

    impl Store {
        pub fn new() -> Self {
            Store(Arc::new(Inner {
                mls: MemoryStorage::default(),
                mdk: MdkMemoryStorage::default(),
            }))
        }

        /// Everything needed to carry on after a restart, as JSON.
        pub fn save(&self) -> anyhow::Result<Vec<u8>> {
            let mut saved = Saved::default();
            {
                let values = self
                    .mls
                    .values
                    .read()
                    .map_err(|_| anyhow::anyhow!("lock"))?;
                let mut pairs: Vec<_> = values
                    .iter()
                    .map(|(k, v)| (B64.encode(k), B64.encode(v)))
                    .collect();
                pairs.sort();
                saved.mls = pairs;
            }
            for group in self.mdk.all_groups()? {
                let id = group.mls_group_id.clone();
                saved.relays.extend(self.mdk.group_relays(&id)?);
                for epoch in 0..=group.epoch {
                    if let Some(s) = self.mdk.get_group_exporter_secret(&id, epoch)? {
                        saved.secrets.push(s);
                    }
                    if let Some(s) = self.mdk.get_group_legacy_exporter_secret(&id, epoch)? {
                        saved.legacy_secrets.push(s);
                    }
                    if let Some(s) = self.mdk.get_group_mip04_exporter_secret(&id, epoch)? {
                        saved.mip04_secrets.push(s);
                    }
                }
                saved.groups.push(group);
            }
            Ok(serde_json::to_vec(&saved)?)
        }

        /// Rebuild a store from what [`Store::save`] wrote.
        pub fn load(bytes: &[u8]) -> anyhow::Result<Self> {
            let saved: Saved = serde_json::from_slice(bytes)?;
            let store = Store::new();
            {
                let mut values = store
                    .mls
                    .values
                    .write()
                    .map_err(|_| anyhow::anyhow!("lock"))?;
                let mut map = HashMap::new();
                for (k, v) in saved.mls {
                    map.insert(B64.decode(k)?, B64.decode(v)?);
                }
                *values = map;
            }
            for group in saved.groups {
                store.mdk.save_group(group)?;
            }
            let mut relays: HashMap<GroupId, BTreeSet<RelayUrl>> = HashMap::new();
            for relay in saved.relays {
                relays
                    .entry(relay.mls_group_id)
                    .or_default()
                    .insert(relay.relay_url);
            }
            for (id, set) in relays {
                store.mdk.replace_group_relays(&id, set)?;
            }
            for s in saved.secrets {
                store.mdk.save_group_exporter_secret(s)?;
            }
            for s in saved.legacy_secrets {
                store.mdk.save_group_legacy_exporter_secret(s)?;
            }
            for s in saved.mip04_secrets {
                store.mdk.save_group_mip04_exporter_secret(s)?;
            }
            Ok(store)
        }
    }

    impl StorageProvider<CURRENT_VERSION> for Store {
        type Error = MemoryStorageError;

        fn write_mls_join_config<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            config: &MlsGroupJoinConfig,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_mls_join_config::<GroupId, MlsGroupJoinConfig>(
                &self.mls, group_id, config,
            )
        }

        fn append_own_leaf_node<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            LeafNode: traits::LeafNode<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            leaf_node: &LeafNode,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::append_own_leaf_node::<GroupId, LeafNode>(
                &self.mls, group_id, leaf_node,
            )
        }

        fn queue_proposal<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
            QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            proposal_ref: &ProposalRef,
            proposal: &QueuedProposal,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::queue_proposal::<GroupId, ProposalRef, QueuedProposal>(
                &self.mls,
                group_id,
                proposal_ref,
                proposal,
            )
        }

        fn write_tree<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            TreeSync: traits::TreeSync<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            tree: &TreeSync,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_tree::<GroupId, TreeSync>(
                &self.mls, group_id, tree,
            )
        }

        fn write_interim_transcript_hash<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            interim_transcript_hash: &InterimTranscriptHash,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_interim_transcript_hash::<
                GroupId,
                InterimTranscriptHash,
            >(&self.mls, group_id, interim_transcript_hash)
        }

        fn write_context<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            GroupContext: traits::GroupContext<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_context: &GroupContext,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_context::<GroupId, GroupContext>(
                &self.mls,
                group_id,
                group_context,
            )
        }

        fn write_confirmation_tag<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            confirmation_tag: &ConfirmationTag,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_confirmation_tag::<GroupId, ConfirmationTag>(
                &self.mls,
                group_id,
                confirmation_tag,
            )
        }

        fn write_group_state<
            GroupState: traits::GroupState<CURRENT_VERSION>,
            GroupId: traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_state: &GroupState,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_group_state::<GroupState, GroupId>(
                &self.mls,
                group_id,
                group_state,
            )
        }

        fn write_message_secrets<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            message_secrets: &MessageSecrets,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_message_secrets::<GroupId, MessageSecrets>(
                &self.mls,
                group_id,
                message_secrets,
            )
        }

        fn write_resumption_psk_store<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            resumption_psk_store: &ResumptionPskStore,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_resumption_psk_store::<
                GroupId,
                ResumptionPskStore,
            >(&self.mls, group_id, resumption_psk_store)
        }

        fn write_own_leaf_index<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            own_leaf_index: &LeafNodeIndex,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_own_leaf_index::<GroupId, LeafNodeIndex>(
                &self.mls,
                group_id,
                own_leaf_index,
            )
        }

        fn write_group_epoch_secrets<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_epoch_secrets: &GroupEpochSecrets,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_group_epoch_secrets::<
                GroupId,
                GroupEpochSecrets,
            >(&self.mls, group_id, group_epoch_secrets)
        }

        fn write_signature_key_pair<
            SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
            SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
        >(
            &self,
            public_key: &SignaturePublicKey,
            signature_key_pair: &SignatureKeyPair,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_signature_key_pair::<
                SignaturePublicKey,
                SignatureKeyPair,
            >(&self.mls, public_key, signature_key_pair)
        }

        fn write_encryption_key_pair<
            EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
            HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        >(
            &self,
            public_key: &EncryptionKey,
            key_pair: &HpkeKeyPair,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_encryption_key_pair::<
                EncryptionKey,
                HpkeKeyPair,
            >(&self.mls, public_key, key_pair)
        }

        fn write_encryption_epoch_key_pairs<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            EpochKey: traits::EpochKey<CURRENT_VERSION>,
            HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            epoch: &EpochKey,
            leaf_index: u32,
            key_pairs: &[HpkeKeyPair],
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_encryption_epoch_key_pairs::<
                GroupId,
                EpochKey,
                HpkeKeyPair,
            >(&self.mls, group_id, epoch, leaf_index, key_pairs)
        }

        fn write_key_package<
            HashReference: traits::HashReference<CURRENT_VERSION>,
            KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
        >(
            &self,
            hash_ref: &HashReference,
            key_package: &KeyPackage,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_key_package::<HashReference, KeyPackage>(
                &self.mls,
                hash_ref,
                key_package,
            )
        }

        fn write_psk<
            PskId: traits::PskId<CURRENT_VERSION>,
            PskBundle: traits::PskBundle<CURRENT_VERSION>,
        >(
            &self,
            psk_id: &PskId,
            psk: &PskBundle,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::write_psk::<PskId, PskBundle>(
                &self.mls, psk_id, psk,
            )
        }

        fn mls_group_join_config<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::mls_group_join_config::<GroupId, MlsGroupJoinConfig>(
                &self.mls, group_id,
            )
        }

        fn own_leaf_nodes<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            LeafNode: traits::LeafNode<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<LeafNode>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::own_leaf_nodes::<GroupId, LeafNode>(
                &self.mls, group_id,
            )
        }

        fn queued_proposal_refs<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<ProposalRef>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::queued_proposal_refs::<GroupId, ProposalRef>(
                &self.mls, group_id,
            )
        }

        fn queued_proposals<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
            QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::queued_proposals::<
                GroupId,
                ProposalRef,
                QueuedProposal,
            >(&self.mls, group_id)
        }

        fn tree<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            TreeSync: traits::TreeSync<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<TreeSync>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::tree::<GroupId, TreeSync>(&self.mls, group_id)
        }

        fn group_context<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            GroupContext: traits::GroupContext<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<GroupContext>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::group_context::<GroupId, GroupContext>(
                &self.mls, group_id,
            )
        }

        fn interim_transcript_hash<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::interim_transcript_hash::<
                GroupId,
                InterimTranscriptHash,
            >(&self.mls, group_id)
        }

        fn confirmation_tag<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<ConfirmationTag>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::confirmation_tag::<GroupId, ConfirmationTag>(
                &self.mls, group_id,
            )
        }

        fn group_state<
            GroupState: traits::GroupState<CURRENT_VERSION>,
            GroupId: traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<GroupState>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::group_state::<GroupState, GroupId>(
                &self.mls, group_id,
            )
        }

        fn message_secrets<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<MessageSecrets>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::message_secrets::<GroupId, MessageSecrets>(
                &self.mls, group_id,
            )
        }

        fn resumption_psk_store<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<ResumptionPskStore>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::resumption_psk_store::<GroupId, ResumptionPskStore>(
                &self.mls, group_id,
            )
        }

        fn own_leaf_index<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<LeafNodeIndex>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::own_leaf_index::<GroupId, LeafNodeIndex>(
                &self.mls, group_id,
            )
        }

        fn group_epoch_secrets<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::group_epoch_secrets::<GroupId, GroupEpochSecrets>(
                &self.mls, group_id,
            )
        }

        fn signature_key_pair<
            SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
            SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
        >(
            &self,
            public_key: &SignaturePublicKey,
        ) -> Result<Option<SignatureKeyPair>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::signature_key_pair::<
                SignaturePublicKey,
                SignatureKeyPair,
            >(&self.mls, public_key)
        }

        fn encryption_key_pair<
            HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
            EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        >(
            &self,
            public_key: &EncryptionKey,
        ) -> Result<Option<HpkeKeyPair>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::encryption_key_pair::<HpkeKeyPair, EncryptionKey>(
                &self.mls, public_key,
            )
        }

        fn encryption_epoch_key_pairs<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            EpochKey: traits::EpochKey<CURRENT_VERSION>,
            HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            epoch: &EpochKey,
            leaf_index: u32,
        ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::encryption_epoch_key_pairs::<
                GroupId,
                EpochKey,
                HpkeKeyPair,
            >(&self.mls, group_id, epoch, leaf_index)
        }

        fn key_package<
            KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
            KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
        >(
            &self,
            hash_ref: &KeyPackageRef,
        ) -> Result<Option<KeyPackage>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::key_package::<KeyPackageRef, KeyPackage>(
                &self.mls, hash_ref,
            )
        }

        fn psk<
            PskBundle: traits::PskBundle<CURRENT_VERSION>,
            PskId: traits::PskId<CURRENT_VERSION>,
        >(
            &self,
            psk_id: &PskId,
        ) -> Result<Option<PskBundle>, Self::Error> {
            StorageProvider::<CURRENT_VERSION>::psk::<PskBundle, PskId>(&self.mls, psk_id)
        }

        fn remove_proposal<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            proposal_ref: &ProposalRef,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::remove_proposal::<GroupId, ProposalRef>(
                &self.mls,
                group_id,
                proposal_ref,
            )
        }

        fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_own_leaf_nodes::<GroupId>(
                &self.mls, group_id,
            )
        }

        fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_group_config::<GroupId>(&self.mls, group_id)
        }

        fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_tree::<GroupId>(&self.mls, group_id)
        }

        fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_confirmation_tag::<GroupId>(
                &self.mls, group_id,
            )
        }

        fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_group_state::<GroupId>(&self.mls, group_id)
        }

        fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_context::<GroupId>(&self.mls, group_id)
        }

        fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_interim_transcript_hash::<GroupId>(
                &self.mls, group_id,
            )
        }

        fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_message_secrets::<GroupId>(
                &self.mls, group_id,
            )
        }

        fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_all_resumption_psk_secrets::<GroupId>(
                &self.mls, group_id,
            )
        }

        fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_own_leaf_index::<GroupId>(
                &self.mls, group_id,
            )
        }

        fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_group_epoch_secrets::<GroupId>(
                &self.mls, group_id,
            )
        }

        fn clear_proposal_queue<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::clear_proposal_queue::<GroupId, ProposalRef>(
                &self.mls, group_id,
            )
        }

        fn delete_signature_key_pair<
            SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        >(
            &self,
            public_key: &SignaturePublicKey,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_signature_key_pair::<SignaturePublicKey>(
                &self.mls, public_key,
            )
        }

        fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
            &self,
            public_key: &EncryptionKey,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_encryption_key_pair::<EncryptionKey>(
                &self.mls, public_key,
            )
        }

        fn delete_encryption_epoch_key_pairs<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            EpochKey: traits::EpochKey<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            epoch: &EpochKey,
            leaf_index: u32,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_encryption_epoch_key_pairs::<GroupId, EpochKey>(
                &self.mls, group_id, epoch, leaf_index,
            )
        }

        fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
            &self,
            hash_ref: &KeyPackageRef,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_key_package::<KeyPackageRef>(
                &self.mls, hash_ref,
            )
        }

        fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
            &self,
            psk_id: &PskKey,
        ) -> Result<(), Self::Error> {
            StorageProvider::<CURRENT_VERSION>::delete_psk::<PskKey>(&self.mls, psk_id)
        }
    }

    impl GroupStorage for Store {
        fn all_groups(&self) -> Result<Vec<Group>, GroupError> {
            GroupStorage::all_groups(&self.mdk)
        }

        fn find_group_by_mls_group_id(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<Group>, GroupError> {
            GroupStorage::find_group_by_mls_group_id(&self.mdk, group_id)
        }

        fn find_group_by_nostr_group_id(
            &self,
            nostr_group_id: &[u8; 32],
        ) -> Result<Option<Group>, GroupError> {
            GroupStorage::find_group_by_nostr_group_id(&self.mdk, nostr_group_id)
        }

        fn save_group(&self, group: Group) -> Result<(), GroupError> {
            GroupStorage::save_group(&self.mdk, group)
        }

        fn messages(
            &self,
            group_id: &GroupId,
            pagination: Option<mdk_storage_traits::groups::Pagination>,
        ) -> Result<Vec<Message>, GroupError> {
            GroupStorage::messages(&self.mdk, group_id, pagination)
        }

        fn last_message(
            &self,
            group_id: &GroupId,
            sort_order: mdk_storage_traits::groups::MessageSortOrder,
        ) -> Result<Option<Message>, GroupError> {
            GroupStorage::last_message(&self.mdk, group_id, sort_order)
        }

        fn admins(&self, group_id: &GroupId) -> Result<BTreeSet<PublicKey>, GroupError> {
            GroupStorage::admins(&self.mdk, group_id)
        }

        fn group_relays(&self, group_id: &GroupId) -> Result<BTreeSet<GroupRelay>, GroupError> {
            GroupStorage::group_relays(&self.mdk, group_id)
        }

        fn replace_group_relays(
            &self,
            group_id: &GroupId,
            relays: BTreeSet<RelayUrl>,
        ) -> Result<(), GroupError> {
            GroupStorage::replace_group_relays(&self.mdk, group_id, relays)
        }

        fn get_group_exporter_secret(
            &self,
            group_id: &GroupId,
            epoch: u64,
        ) -> Result<Option<GroupExporterSecret>, GroupError> {
            GroupStorage::get_group_exporter_secret(&self.mdk, group_id, epoch)
        }

        fn save_group_exporter_secret(
            &self,
            group_exporter_secret: GroupExporterSecret,
        ) -> Result<(), GroupError> {
            GroupStorage::save_group_exporter_secret(&self.mdk, group_exporter_secret)
        }

        fn get_group_legacy_exporter_secret(
            &self,
            group_id: &GroupId,
            epoch: u64,
        ) -> Result<Option<GroupExporterSecret>, GroupError> {
            GroupStorage::get_group_legacy_exporter_secret(&self.mdk, group_id, epoch)
        }

        fn save_group_legacy_exporter_secret(
            &self,
            group_exporter_secret: GroupExporterSecret,
        ) -> Result<(), GroupError> {
            GroupStorage::save_group_legacy_exporter_secret(&self.mdk, group_exporter_secret)
        }

        fn get_group_mip04_exporter_secret(
            &self,
            group_id: &GroupId,
            epoch: u64,
        ) -> Result<Option<GroupExporterSecret>, GroupError> {
            GroupStorage::get_group_mip04_exporter_secret(&self.mdk, group_id, epoch)
        }

        fn save_group_mip04_exporter_secret(
            &self,
            group_exporter_secret: GroupExporterSecret,
        ) -> Result<(), GroupError> {
            GroupStorage::save_group_mip04_exporter_secret(&self.mdk, group_exporter_secret)
        }

        fn prune_group_exporter_secrets_before_epoch(
            &self,
            group_id: &GroupId,
            min_epoch_to_keep: u64,
        ) -> Result<(), GroupError> {
            GroupStorage::prune_group_exporter_secrets_before_epoch(
                &self.mdk,
                group_id,
                min_epoch_to_keep,
            )
        }
    }
    impl MessageStorage for Store {
        fn save_message(&self, message: Message) -> Result<(), MessageError> {
            MessageStorage::save_message(&self.mdk, message)
        }

        fn find_message_by_event_id(
            &self,
            mls_group_id: &GroupId,
            event_id: &EventId,
        ) -> Result<Option<Message>, MessageError> {
            MessageStorage::find_message_by_event_id(&self.mdk, mls_group_id, event_id)
        }

        fn save_processed_message(
            &self,
            processed_message: ProcessedMessage,
        ) -> Result<(), MessageError> {
            MessageStorage::save_processed_message(&self.mdk, processed_message)
        }

        fn find_processed_message_by_event_id(
            &self,
            event_id: &EventId,
        ) -> Result<Option<ProcessedMessage>, MessageError> {
            MessageStorage::find_processed_message_by_event_id(&self.mdk, event_id)
        }

        fn invalidate_messages_after_epoch(
            &self,
            group_id: &GroupId,
            epoch: u64,
        ) -> Result<Vec<EventId>, MessageError> {
            MessageStorage::invalidate_messages_after_epoch(&self.mdk, group_id, epoch)
        }

        fn invalidate_processed_messages_after_epoch(
            &self,
            group_id: &GroupId,
            epoch: u64,
        ) -> Result<Vec<EventId>, MessageError> {
            MessageStorage::invalidate_processed_messages_after_epoch(&self.mdk, group_id, epoch)
        }

        fn find_failed_messages_for_retry(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<EventId>, MessageError> {
            MessageStorage::find_failed_messages_for_retry(&self.mdk, group_id)
        }

        fn find_invalidated_messages(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<Message>, MessageError> {
            MessageStorage::find_invalidated_messages(&self.mdk, group_id)
        }

        fn find_invalidated_processed_messages(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<ProcessedMessage>, MessageError> {
            MessageStorage::find_invalidated_processed_messages(&self.mdk, group_id)
        }

        fn mark_processed_message_retryable(&self, event_id: &EventId) -> Result<(), MessageError> {
            MessageStorage::mark_processed_message_retryable(&self.mdk, event_id)
        }

        fn find_message_epoch_by_tag_content(
            &self,
            group_id: &GroupId,
            content_substring: &str,
        ) -> Result<Option<u64>, MessageError> {
            MessageStorage::find_message_epoch_by_tag_content(
                &self.mdk,
                group_id,
                content_substring,
            )
        }

        fn delete_messages_for_group(&self, group_id: &GroupId) -> Result<usize, MessageError> {
            MessageStorage::delete_messages_for_group(&self.mdk, group_id)
        }
    }
    impl WelcomeStorage for Store {
        fn save_welcome(&self, welcome: Welcome) -> Result<(), WelcomeError> {
            WelcomeStorage::save_welcome(&self.mdk, welcome)
        }

        fn find_welcome_by_event_id(
            &self,
            event_id: &EventId,
        ) -> Result<Option<Welcome>, WelcomeError> {
            WelcomeStorage::find_welcome_by_event_id(&self.mdk, event_id)
        }

        fn pending_welcomes(
            &self,
            pagination: Option<mdk_storage_traits::welcomes::Pagination>,
        ) -> Result<Vec<Welcome>, WelcomeError> {
            WelcomeStorage::pending_welcomes(&self.mdk, pagination)
        }

        fn save_processed_welcome(
            &self,
            processed_welcome: ProcessedWelcome,
        ) -> Result<(), WelcomeError> {
            WelcomeStorage::save_processed_welcome(&self.mdk, processed_welcome)
        }

        fn find_processed_welcome_by_event_id(
            &self,
            event_id: &EventId,
        ) -> Result<Option<ProcessedWelcome>, WelcomeError> {
            WelcomeStorage::find_processed_welcome_by_event_id(&self.mdk, event_id)
        }
    }
    impl MdkStorageProvider for Store {
        fn backend(&self) -> Backend {
            MdkStorageProvider::backend(&self.mdk)
        }

        fn create_group_snapshot(
            &self,
            group_id: &GroupId,
            name: &str,
        ) -> Result<(), MdkStorageError> {
            MdkStorageProvider::create_group_snapshot(&self.mdk, group_id, name)
        }

        fn rollback_group_to_snapshot(
            &self,
            group_id: &GroupId,
            name: &str,
        ) -> Result<(), MdkStorageError> {
            MdkStorageProvider::rollback_group_to_snapshot(&self.mdk, group_id, name)
        }

        fn release_group_snapshot(
            &self,
            group_id: &GroupId,
            name: &str,
        ) -> Result<(), MdkStorageError> {
            MdkStorageProvider::release_group_snapshot(&self.mdk, group_id, name)
        }

        fn list_group_snapshots(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<(String, u64)>, MdkStorageError> {
            MdkStorageProvider::list_group_snapshots(&self.mdk, group_id)
        }

        fn prune_expired_snapshots(&self, min_timestamp: u64) -> Result<usize, MdkStorageError> {
            MdkStorageProvider::prune_expired_snapshots(&self.mdk, min_timestamp)
        }

        fn delete_group(&self, group_id: &GroupId) -> Result<(), MdkStorageError> {
            MdkStorageProvider::delete_group(&self.mdk, group_id)
        }
    }
}

/// What is kept in `state.json`.
#[derive(Serialize, Deserialize, Default, Clone)]
struct State {
    relays: Vec<String>,
    /// MLS group id, hex.
    group: Option<String>,
    /// Nostr group id (the `h` tag of kind 445 events), hex.
    nostr_group: Option<String>,
    /// The other member, npub.
    peer: Option<String>,
    /// Oldest kind 445 timestamp worth asking the relays for.
    since: u64,
    /// Kind 445 events already handled: sent by us or processed. This is
    /// the receive cursor.
    seen: BTreeSet<String>,
    /// Counter put in the next message we send.
    next_seq: u64,
}

/// A summary for the `status` command.
pub struct Status {
    pub npub: String,
    pub relays: Vec<String>,
    pub group: Option<String>,
    pub peer: Option<String>,
    pub handled: usize,
}

/// One Marmot group with one other member, used as a [`Transport`].
pub struct Marmot {
    dir: PathBuf,
    keys: Keys,
    store: store::Store,
    mdk: MDK<store::Store>,
    state: State,
    client: Option<Client>,
    connected: bool,
    rt: tokio::runtime::Runtime,
}

impl Marmot {
    /// Open (or create) the Marmot state of a wallet folder. A non-empty
    /// `relays` replaces the saved relay list; with none saved and none
    /// given, [`DEFAULT_RELAYS`] are used. Does not touch the network.
    pub fn open(wallet_dir: &Path, relays: &[String]) -> Result<Self> {
        let dir = wallet_dir.join("marmot");
        fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }

        let key_path = dir.join("identity.key");
        let keys = if key_path.exists() {
            let hex = fs::read_to_string(&key_path)?;
            Keys::parse(hex.trim()).context("identity.key is not a nostr secret key")?
        } else {
            let keys = Keys::generate();
            write_private(&key_path, keys.secret_key().to_secret_hex().as_bytes())?;
            keys
        };

        let state_path = dir.join("state.json");
        let mut state: State = if state_path.exists() {
            serde_json::from_slice(&fs::read(&state_path)?).context("state.json is damaged")?
        } else {
            State::default()
        };
        if !relays.is_empty() {
            state.relays = relays.to_vec();
        }
        if state.relays.is_empty() {
            state.relays = DEFAULT_RELAYS.iter().map(|r| r.to_string()).collect();
        }
        for relay in &state.relays {
            RelayUrl::parse(relay).with_context(|| format!("not a relay address: {relay}"))?;
        }

        let mls_path = dir.join("mls.json");
        let store = if mls_path.exists() {
            store::Store::load(&fs::read(&mls_path)?).context("mls.json is damaged")?
        } else {
            store::Store::new()
        };
        let mdk = MDK::new(store.clone());
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;

        let me = Marmot {
            dir,
            keys,
            store,
            mdk,
            state,
            client: None,
            connected: false,
            rt,
        };
        me.save_state()?;
        Ok(me)
    }

    /// This wallet's nostr public key, npub form.
    pub fn npub(&self) -> String {
        self.keys
            .public_key()
            .to_bech32()
            .expect("a public key always encodes")
    }

    pub fn status(&self) -> Status {
        Status {
            npub: self.npub(),
            relays: self.state.relays.clone(),
            group: self.state.group.clone(),
            peer: self.state.peer.clone(),
            handled: self.state.seen.len(),
        }
    }

    fn save_state(&self) -> Result<()> {
        write_private(
            &self.dir.join("state.json"),
            &serde_json::to_vec_pretty(&self.state)?,
        )
    }

    fn save_mls(&self) -> Result<()> {
        write_private(&self.dir.join("mls.json"), &self.store.save()?)
    }

    fn relay_urls(&self) -> Vec<RelayUrl> {
        self.state
            .relays
            .iter()
            .filter_map(|r| RelayUrl::parse(r).ok())
            .collect()
    }

    /// The relay client, connected on first use.
    fn client(&mut self) -> Result<Client> {
        if self.client.is_none() {
            let client = Client::new(self.keys.clone());
            let relays = self.state.relays.clone();
            self.rt.block_on(async {
                for relay in &relays {
                    client.add_relay(relay.as_str()).await?;
                }
                Ok::<_, anyhow::Error>(())
            })?;
            self.client = Some(client);
        }
        let client = self.client.clone().expect("set above");
        if !self.connected {
            self.rt.block_on(async {
                client.connect().await;
                client.wait_for_connection(Duration::from_secs(6)).await;
            });
            self.connected = true;
        }
        Ok(client)
    }

    fn publish(&mut self, event: &Event) -> Result<()> {
        let client = self.client()?;
        let out = self.rt.block_on(client.send_event(event))?;
        if out.success.is_empty() {
            let why: Vec<String> = out
                .failed
                .iter()
                .map(|(r, e)| format!("{r}: {e}"))
                .collect();
            bail!(
                "no relay took event kind {}: {}",
                event.kind,
                why.join("; ")
            );
        }
        Ok(())
    }

    fn fetch(&mut self, filter: Filter) -> Result<Vec<Event>> {
        let client = self.client()?;
        let events = self
            .rt
            .block_on(client.fetch_events(filter, FETCH_TIMEOUT))?;
        Ok(events.into_iter().collect())
    }

    /// Publish a fresh key package (kind 30443, and the legacy kind 443
    /// for older clients) and the key package relay list (kind 10051), so
    /// another wallet can invite this one.
    pub fn publish_key_package(&mut self) -> Result<()> {
        let relays = self.relay_urls();
        let data = self
            .mdk
            .create_key_package_for_event(&self.keys.public_key(), relays.clone())?;
        // The key package's private half must be on disk before anyone can
        // use the public half.
        self.save_mls()?;
        let keys = self.keys.clone();
        let (current, legacy, relay_list) = self.rt.block_on(async {
            let current = EventBuilder::new(Kind::Custom(KIND_KEY_PACKAGE), data.content.clone())
                .tags(data.tags_30443.clone())
                .sign(&keys)
                .await?;
            let legacy = EventBuilder::new(Kind::MlsKeyPackage, data.content.clone())
                .tags(data.tags_443.clone())
                .sign(&keys)
                .await?;
            let relay_list = EventBuilder::new(Kind::MlsKeyPackageRelays, "")
                .tags(
                    relays
                        .iter()
                        .map(|r| Tag::custom(TagKind::Relay, [r.to_string()])),
                )
                .sign(&keys)
                .await?;
            Ok::<_, anyhow::Error>((current, legacy, relay_list))
        })?;
        self.publish(&current)?;
        // Relays that no longer take the legacy kind are not an error.
        let _ = self.publish(&legacy);
        self.publish(&relay_list)?;
        Ok(())
    }

    /// Create the group with one other wallet, found by npub: fetch its
    /// newest key package, create the group, and send the welcome as a
    /// NIP-59 gift wrap.
    pub fn invite(&mut self, peer_npub: &str) -> Result<()> {
        if self.state.group.is_some() {
            bail!("this wallet is already in a group; remove the marmot folder to start over");
        }
        let peer = PublicKey::parse(peer_npub).context("not an npub")?;
        let filter = Filter::new()
            .author(peer)
            .kinds([Kind::Custom(KIND_KEY_PACKAGE), Kind::MlsKeyPackage])
            .limit(20);
        let mut packages = self.fetch(filter)?;
        // Newest first, the current kind before the legacy one.
        packages.sort_by_key(|e| {
            (
                std::cmp::Reverse(e.created_at),
                e.kind != Kind::Custom(KIND_KEY_PACKAGE),
            )
        });
        let package = packages
            .into_iter()
            .find(|e| self.mdk.parse_key_package(e).is_ok())
            .ok_or_else(|| anyhow!("no usable key package from {peer_npub} on the relays; run init on that wallet first"))?;

        let me = self.keys.public_key();
        let config = NostrGroupConfigData::new(
            "kiss-bdk shared send".to_string(),
            "Two wallets paying one silent payment together".to_string(),
            None,
            None,
            None,
            self.relay_urls(),
            vec![me],
        );
        let created = self.mdk.create_group(&me, vec![package], config)?;
        self.save_mls()?;
        self.state.group = Some(hex_encode(created.group.mls_group_id.as_slice()));
        self.state.nostr_group = Some(hex_encode(&created.group.nostr_group_id));
        self.state.peer = Some(peer.to_bech32()?);
        self.state.since = Timestamp::now().as_secs().saturating_sub(600);
        self.save_state()?;

        let client = self.client()?;
        for rumor in created.welcome_rumors {
            let out = self
                .rt
                .block_on(client.gift_wrap(&peer, rumor, Vec::<Tag>::new()))?;
            if out.success.is_empty() {
                bail!("no relay took the welcome gift wrap");
            }
        }
        Ok(())
    }

    /// Accept the newest pending welcome, waiting up to `wait` for one.
    /// Returns the inviter's npub, or None when nothing arrived.
    pub fn accept(&mut self, wait: Duration) -> Result<Option<String>> {
        if self.state.group.is_some() {
            bail!("this wallet is already in a group");
        }
        let start = Instant::now();
        let me = self.keys.public_key();
        loop {
            // Gift wraps carry a randomised timestamp, so no `since` here.
            let wraps = self.fetch(Filter::new().kind(Kind::GiftWrap).pubkey(me))?;
            let client = self.client()?;
            for wrap in wraps {
                if self.state.seen.contains(&wrap.id.to_hex()) {
                    continue;
                }
                let Ok(gift) = self.rt.block_on(client.unwrap_gift_wrap(&wrap)) else {
                    continue;
                };
                if gift.rumor.kind == Kind::MlsWelcome {
                    // A welcome for a key package this wallet no longer has
                    // fails here; that is not this wallet's group.
                    let _ = self.mdk.process_welcome(&wrap.id, &gift.rumor);
                }
            }
            let mut pending = self.mdk.get_pending_welcomes(None)?;
            pending.sort_by_key(|w| w.event.created_at);
            if let Some(welcome) = pending.pop() {
                self.mdk.accept_welcome(&welcome)?;
                self.save_mls()?;
                self.state.seen.insert(welcome.wrapper_event_id.to_hex());
                self.state.group = Some(hex_encode(welcome.mls_group_id.as_slice()));
                self.state.nostr_group = Some(hex_encode(&welcome.nostr_group_id));
                self.state.peer = Some(welcome.welcomer.to_bech32()?);
                self.state.since = welcome.event.created_at.as_secs().saturating_sub(600);
                self.save_state()?;
                return Ok(self.state.peer.clone());
            }
            if start.elapsed() >= wait {
                return Ok(None);
            }
            std::thread::sleep(POLL_PAUSE);
        }
    }

    fn group_id(&self) -> Result<GroupId> {
        let hex = self.state.group.as_ref().ok_or_else(|| {
            anyhow!("no Marmot group yet: run invite on one wallet and accept on the other")
        })?;
        Ok(GroupId::from_slice(&hex_decode(hex)?))
    }

    /// Fetch and decrypt group messages not handled before. Returns
    /// (sent at, counter, text) for messages from the other member.
    fn poll(&mut self) -> Result<Vec<(u64, u64, String)>> {
        let nostr_group = self.state.nostr_group.clone().expect("checked by group_id");
        let filter = Filter::new()
            .kind(Kind::MlsGroupMessage)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::H), nostr_group)
            .since(Timestamp::from(self.state.since));
        let mut events = self.fetch(filter)?;
        events.sort_by_key(|e| (e.created_at, e.id));
        let me = self.keys.public_key();
        let mut out = Vec::new();
        let mut changed = false;
        for event in events {
            let id = event.id.to_hex();
            if self.state.seen.contains(&id) {
                continue;
            }
            changed = true;
            self.state.seen.insert(id);
            // Anything that does not decrypt (a stray event, our own message
            // from before a restart) is skipped.
            if let Ok(MessageProcessingResult::ApplicationMessage(msg)) =
                self.mdk.process_message(&event)
                && msg.pubkey != me
            {
                let seq = msg
                    .tags
                    .iter()
                    .find(|t| t.kind() == TagKind::Custom(SEQ_TAG.into()))
                    .and_then(|t| t.content())
                    .and_then(|c| c.parse().ok())
                    .unwrap_or(0);
                out.push((msg.created_at.as_secs(), seq, msg.content));
            }
        }
        if changed {
            self.save_mls()?;
            self.save_state()?;
        }
        out.sort();
        Ok(out)
    }
}

impl Transport for Marmot {
    fn send(&mut self, message: &str) -> Result<()> {
        let group = self.group_id()?;
        let seq = self.state.next_seq;
        let rumor = EventBuilder::new(Kind::Custom(KIND_APP_MESSAGE), message)
            .tag(Tag::custom(
                TagKind::Custom(SEQ_TAG.into()),
                [seq.to_string()],
            ))
            .build(self.keys.public_key());
        let event = self.mdk.create_message(&group, rumor, None)?;
        // The ratchet moved: save it before the message leaves, so a
        // restart never reuses a key.
        self.save_mls()?;
        self.state.next_seq = seq + 1;
        self.state.seen.insert(event.id.to_hex());
        self.save_state()?;
        self.publish(&event)
    }

    fn receive(&mut self, wait: Duration) -> Result<Vec<String>> {
        self.group_id()?;
        let start = Instant::now();
        loop {
            let got = self.poll()?;
            if !got.is_empty() {
                return Ok(got.into_iter().map(|(_, _, text)| text).collect());
            }
            if start.elapsed() >= wait {
                return Ok(Vec::new());
            }
            std::thread::sleep(POLL_PAUSE.min(wait.saturating_sub(start.elapsed())));
        }
    }
}

impl Drop for Marmot {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            let _enter = self.rt.enter();
            self.rt.block_on(client.shutdown());
            drop(client);
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        bail!("bad hex");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| anyhow!("bad hex")))
        .collect()
}

/// Run a nostr relay on 127.0.0.1 that keeps events in memory, for a demo
/// that must not depend on the venue's network. Returns its address and a
/// handle that stops it when dropped (the runtime goes with it).
pub struct LocalRelay {
    url: String,
    relay: nostr_relay_builder::LocalRelay,
    _rt: tokio::runtime::Runtime,
}

impl LocalRelay {
    /// `port` 0 picks a free port.
    pub fn start(port: u16) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let (relay, url) = rt.block_on(async {
            let mut builder = nostr_relay_builder::RelayBuilder::default()
                .addr(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            if port != 0 {
                builder = builder.port(port);
            }
            let relay = nostr_relay_builder::LocalRelay::new(builder);
            relay.run().await?;
            let url = relay.url().await.to_string();
            Ok::<_, anyhow::Error>((relay, url))
        })?;
        Ok(LocalRelay {
            url,
            relay,
            _rt: rt,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

impl Drop for LocalRelay {
    fn drop(&mut self) {
        self.relay.shutdown();
    }
}
