//! Standard RDP Security ([MS-RDPBCGR] 5.3): RC4 encryption under the PDU layer.
//!
//! The rest of IronRDP speaks to [`StandardSecurityStream`] as if the connection were TLS. The
//! stream adds the security headers, signatures and encryption the server expects, and takes
//! them off what the server sends. It also sends the Security Exchange PDU ahead of the Client
//! Info PDU.
//!
//! [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/

use core::pin::Pin;
use core::task::{Context, Poll, ready};
use std::io;

use ironrdp_pdu::gcc::{EncryptionLevel, EncryptionMethod};
use ironrdp_pdu::mcs::ConnectResponse;
use md5::{Digest as _, Md5};
use num_bigint::BigUint;
use rand::RngCore as _;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, info};

const TPKT_VERSION: u8 = 3;
const TPKT_HEADER_LEN: usize = 4;
const X224_DATA_HEADER: [u8; 3] = [2, 0xF0, 0x80];
const MCS_DATA_HEADER_LEN: usize = 6;
const MCS_SEND_DATA_REQUEST: u8 = 25;
const MCS_SEND_DATA_INDICATION: u8 = 26;

const SEC_EXCHANGE_PKT: u16 = 0x0001;
const SEC_ENCRYPT: u16 = 0x0008;
const SEC_LICENSE_PKT: u16 = 0x0080;
const SEC_LICENSE_ENCRYPT_CS: u16 = 0x0200;
const SEC_SECURE_CHECKSUM: u16 = 0x0800;

const FASTPATH_SECURE_CHECKSUM: u8 = 0x1;
const FASTPATH_ENCRYPTED: u8 = 0x2;

const SIGNATURE_LEN: usize = 8;
const RANDOM_LEN: usize = 32;
const KEY_UPDATE_INTERVAL: u32 = 4096;
const PAD1: [u8; 40] = [0x36; 40];
const PAD2: [u8; 48] = [0x5C; 48];

const PDUTYPE_DEMANDACTIVEPDU: u16 = 0x1;

/// A byte stream that runs Standard RDP Security over `inner`.
pub(crate) struct StandardSecurityStream<S> {
    inner: S,
    layer: SecurityLayer,
    /// Server bytes that do not make a whole PDU yet.
    received: Vec<u8>,
    /// Server PDUs with the security layer taken off, waiting for IronRDP.
    readable: Vec<u8>,
    readable_pos: usize,
    eof: bool,
    /// IronRDP bytes that do not make a whole PDU yet.
    written: Vec<u8>,
    /// Client PDUs with the security layer on, waiting for the socket.
    sendable: Vec<u8>,
    sendable_pos: usize,
}

impl<S> StandardSecurityStream<S> {
    /// `leftover` is what was already read from `inner` and not consumed.
    pub(crate) fn new(inner: S, leftover: &[u8]) -> Self {
        Self {
            inner,
            layer: SecurityLayer::default(),
            received: leftover.to_vec(),
            readable: Vec::new(),
            readable_pos: 0,
            eof: false,
            written: Vec::new(),
            sendable: Vec::new(),
            sendable_pos: 0,
        }
    }
}

impl<S: AsyncWrite + Unpin> StandardSecurityStream<S> {
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.sendable_pos < self.sendable.len() {
            let written = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.sendable[self.sendable_pos..]))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.sendable_pos += written;
        }
        self.sendable.clear();
        self.sendable_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for StandardSecurityStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.readable_pos < this.readable.len() {
                let count = buf.remaining().min(this.readable.len() - this.readable_pos);
                buf.put_slice(&this.readable[this.readable_pos..this.readable_pos + count]);
                this.readable_pos += count;
                if this.readable_pos == this.readable.len() {
                    this.readable.clear();
                    this.readable_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            if let Some(length) = pdu_length(&this.received)? {
                if this.received.len() >= length {
                    let pdu: Vec<u8> = this.received.drain(..length).collect();
                    this.layer.server_pdu(&pdu, &mut this.readable)?;
                    continue;
                }
            }

            if this.eof {
                if this.received.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }

            let mut chunk = [0u8; 16 * 1024];
            let mut chunk_buf = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut chunk_buf))?;
            if chunk_buf.filled().is_empty() {
                this.eof = true;
            } else {
                this.received.extend_from_slice(chunk_buf.filled());
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StandardSecurityStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_send(cx))?;

        this.written.extend_from_slice(buf);
        while let Some(length) = pdu_length(&this.written)? {
            if this.written.len() < length {
                break;
            }
            let pdu: Vec<u8> = this.written.drain(..length).collect();
            this.layer.client_pdu(&pdu, &mut this.sendable)?;
        }

        // The bytes are taken either way. What the socket refuses now goes out on the next flush.
        if let Poll::Ready(Err(error)) = this.poll_send(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// The length of the TPKT or fast-path PDU at the start of `bytes`, once enough of it is there.
fn pdu_length(bytes: &[u8]) -> io::Result<Option<usize>> {
    let Some(&first) = bytes.first() else {
        return Ok(None);
    };
    if first == TPKT_VERSION {
        if bytes.len() < TPKT_HEADER_LEN {
            return Ok(None);
        }
        let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if length < TPKT_HEADER_LEN {
            return Err(invalid("TPKT length is shorter than its header"));
        }
        return Ok(Some(length));
    }
    if first & 0x3 != 0 {
        return Err(invalid(format!("unknown PDU action 0x{first:02x}")));
    }
    let Some(&length1) = bytes.get(1) else {
        return Ok(None);
    };
    let length = if length1 & 0x80 != 0 {
        let Some(&length2) = bytes.get(2) else {
            return Ok(None);
        };
        usize::from(u16::from_be_bytes([length1 & 0x7F, length2]))
    } else {
        usize::from(length1)
    };
    if length < 2 {
        return Err(invalid("fast-path length is shorter than its header"));
    }
    Ok(Some(length))
}

/// A fast-path PDU: header byte, length, then the rest.
fn encode_fast_path(header: u8, body: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
    let short = 2 + body.len();
    if short <= 0x7F {
        out.push(header);
        out.push(short as u8);
    } else {
        let long = u16::try_from(3 + body.len())
            .ok()
            .filter(|length| *length <= 0x7FFF)
            .ok_or_else(|| invalid("fast-path PDU is too long"))?;
        out.push(header);
        out.extend_from_slice(&(0x8000 | long).to_be_bytes());
    }
    out.extend_from_slice(body);
    Ok(())
}

fn split_fast_path(pdu: &[u8]) -> io::Result<(u8, &[u8])> {
    let header_len = if pdu.get(1).is_some_and(|length| length & 0x80 != 0) {
        3
    } else {
        2
    };
    let body = pdu.get(header_len..).ok_or_else(|| invalid("fast-path PDU is truncated"))?;
    Ok((pdu[0], body))
}

/// An MCS Send Data Request or Indication inside a TPKT.
struct SendData<'a> {
    /// Type, initiator, channel and priority, copied as they are.
    header: &'a [u8],
    kind: u8,
    channel_id: u16,
    user_data: &'a [u8],
}

impl<'a> SendData<'a> {
    fn parse(pdu: &'a [u8]) -> io::Result<Option<Self>> {
        let Some(mcs) = pdu.get(TPKT_HEADER_LEN + X224_DATA_HEADER.len()..) else {
            return Ok(None);
        };
        if pdu[TPKT_HEADER_LEN..TPKT_HEADER_LEN + 2] != X224_DATA_HEADER[..2] || mcs.len() < MCS_DATA_HEADER_LEN + 1 {
            return Ok(None);
        }
        let kind = mcs[0] >> 2;
        if kind != MCS_SEND_DATA_REQUEST && kind != MCS_SEND_DATA_INDICATION {
            return Ok(None);
        }
        let channel_id = u16::from_be_bytes([mcs[3], mcs[4]]);
        let first = mcs[MCS_DATA_HEADER_LEN];
        let (length, length_len) = match first & 0xC0 {
            0x80 => {
                let second = *mcs
                    .get(MCS_DATA_HEADER_LEN + 1)
                    .ok_or_else(|| invalid("MCS length is truncated"))?;
                (usize::from(u16::from_be_bytes([first & 0x3F, second])), 2)
            }
            0xC0 => return Err(invalid("fragmented MCS user data is not supported")),
            _ => (usize::from(first), 1),
        };
        let user_data = &mcs[MCS_DATA_HEADER_LEN + length_len..];
        if user_data.len() != length {
            return Err(invalid("MCS user data length does not match the TPKT"));
        }
        Ok(Some(Self {
            header: &mcs[..MCS_DATA_HEADER_LEN],
            kind,
            channel_id,
            user_data,
        }))
    }

    /// The same Send Data PDU around new user data.
    fn encode(&self, user_data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let start = out.len();
        out.extend_from_slice(&[TPKT_VERSION, 0, 0, 0]);
        out.extend_from_slice(&X224_DATA_HEADER);
        out.extend_from_slice(self.header);
        if user_data.len() < 0x80 {
            out.push(user_data.len() as u8);
        } else {
            let length = u16::try_from(user_data.len())
                .ok()
                .filter(|length| *length <= 0x3FFF)
                .ok_or_else(|| invalid("MCS user data is too long"))?;
            out.extend_from_slice(&(0x8000 | length).to_be_bytes());
        }
        out.extend_from_slice(user_data);
        let total = u16::try_from(out.len() - start).map_err(|_| invalid("TPKT is too long"))?;
        out[start + 2..start + 4].copy_from_slice(&total.to_be_bytes());
        Ok(())
    }
}

#[derive(Default)]
enum SecurityLayer {
    /// Until the server's settings arrive in the MCS Connect Response.
    #[default]
    AwaitingSettings,
    /// The server chose no encryption. The PDUs already look like they would under TLS.
    Plain,
    Encrypted(Box<Session>),
}

impl SecurityLayer {
    fn server_pdu(&mut self, pdu: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::AwaitingSettings => {
                if let Some(response) = connect_response(pdu) {
                    *self = Self::from_connect_response(response)?;
                }
                out.extend_from_slice(pdu);
                Ok(())
            }
            Self::Plain => {
                out.extend_from_slice(pdu);
                Ok(())
            }
            Self::Encrypted(session) => session.server_pdu(pdu, out),
        }
    }

    fn client_pdu(&mut self, pdu: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::AwaitingSettings | Self::Plain => {
                out.extend_from_slice(pdu);
                Ok(())
            }
            Self::Encrypted(session) => session.client_pdu(pdu, out),
        }
    }

    fn from_connect_response(response: ConnectResponse) -> io::Result<Self> {
        let gcc = response.conference_create_response.into_gcc_blocks();
        let security = gcc.security;
        if security.encryption_method.is_empty() && security.encryption_level == EncryptionLevel::None {
            info!("Server chose no encryption");
            return Ok(Self::Plain);
        }
        let method = Method::from_server(security.encryption_method)?;
        let server_random = security
            .server_random
            .ok_or_else(|| invalid("server sent no random"))?;
        let public_key = ServerPublicKey::parse(&security.server_cert)?;

        let mut client_random = [0u8; RANDOM_LEN];
        rand::rng().fill_bytes(&mut client_random);

        info!(?method, level = ?security.encryption_level, key_bits = public_key.modulus.len() * 8, "Standard RDP security");

        Ok(Self::Encrypted(Box::new(Session {
            keys: SessionKeys::derive(&client_random, &server_random, method),
            encrypted_client_random: Some(public_key.encrypt(&client_random)),
            io_channel_id: gcc.network.io_channel,
            message_channel_id: gcc.message_channel.map(|channel| channel.mcs_message_channel_id),
            activated: false,
            encrypt_license: false,
        })))
    }
}

fn connect_response(pdu: &[u8]) -> Option<ConnectResponse> {
    let mcs = pdu.get(TPKT_HEADER_LEN + X224_DATA_HEADER.len()..)?;
    // BER application tag 102: Connect-Response.
    if !mcs.starts_with(&[0x7F, 0x66]) {
        return None;
    }
    ironrdp_core::decode::<ConnectResponse>(mcs).ok()
}

struct Session {
    keys: SessionKeys,
    /// Sent once, ahead of the Client Info PDU.
    encrypted_client_random: Option<Vec<u8>>,
    io_channel_id: u16,
    message_channel_id: Option<u16>,
    /// The server has sent a Demand Active PDU, so licensing is over.
    activated: bool,
    /// The server asked for encrypted licensing PDUs.
    encrypt_license: bool,
}

impl Session {
    fn server_pdu(&mut self, pdu: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        if pdu[0] != TPKT_VERSION {
            let (header, body) = split_fast_path(pdu)?;
            let flags = header >> 6;
            let header = header & 0x3F;
            if flags & FASTPATH_ENCRYPTED == 0 {
                return encode_fast_path(header, body, out);
            }
            let plain = self.decrypt(body, flags & FASTPATH_SECURE_CHECKSUM != 0)?;
            return encode_fast_path(header, &plain, out);
        }

        let Some(data) = SendData::parse(pdu)? else {
            out.extend_from_slice(pdu);
            return Ok(());
        };
        if data.kind != MCS_SEND_DATA_INDICATION || data.user_data.len() < 4 {
            out.extend_from_slice(pdu);
            return Ok(());
        }

        let flags = u16::from_le_bytes([data.user_data[0], data.user_data[1]]);
        let flags_hi = &data.user_data[2..4];
        let body = &data.user_data[4..];
        let plain = if flags & SEC_ENCRYPT != 0 {
            self.decrypt(body, flags & SEC_SECURE_CHECKSUM != 0)?
        } else {
            body.to_vec()
        };

        if data.channel_id == self.io_channel_id && is_demand_active(&plain) {
            self.activated = true;
        }
        if flags & SEC_LICENSE_PKT != 0 && flags & SEC_LICENSE_ENCRYPT_CS != 0 {
            self.encrypt_license = true;
        }

        // IronRDP expects a basic security header only where TLS would carry one.
        let kept = flags & !(SEC_ENCRYPT | SEC_SECURE_CHECKSUM);
        if kept == 0 {
            return data.encode(&plain, out);
        }
        let mut user_data = Vec::with_capacity(4 + plain.len());
        user_data.extend_from_slice(&kept.to_le_bytes());
        user_data.extend_from_slice(flags_hi);
        user_data.extend_from_slice(&plain);
        data.encode(&user_data, out)
    }

    fn client_pdu(&mut self, pdu: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        if pdu[0] != TPKT_VERSION {
            let (header, body) = split_fast_path(pdu)?;
            let signed = self.encrypt(body);
            return encode_fast_path(header | (FASTPATH_ENCRYPTED << 6), &signed, out);
        }

        let Some(data) = SendData::parse(pdu)? else {
            out.extend_from_slice(pdu);
            return Ok(());
        };
        if data.kind != MCS_SEND_DATA_REQUEST {
            out.extend_from_slice(pdu);
            return Ok(());
        }

        // Which PDUs carry a basic security header under TLS, and so already have one.
        let (has_header, encrypt) = if let Some(encrypted_client_random) = self.encrypted_client_random.take() {
            // The first one is the Client Info PDU.
            data.encode(&security_exchange(&encrypted_client_random), out)?;
            debug!("Sent the Security Exchange PDU");
            (true, true)
        } else if Some(data.channel_id) == self.message_channel_id {
            (true, true)
        } else if !self.activated && data.channel_id == self.io_channel_id {
            (true, self.encrypt_license)
        } else {
            (false, true)
        };

        let (mut flags, flags_hi, body) = if has_header {
            if data.user_data.len() < 4 {
                return Err(invalid("client PDU is missing its security header"));
            }
            (
                u16::from_le_bytes([data.user_data[0], data.user_data[1]]),
                [data.user_data[2], data.user_data[3]],
                &data.user_data[4..],
            )
        } else {
            (0, [0, 0], data.user_data)
        };

        let mut user_data = Vec::with_capacity(4 + SIGNATURE_LEN + body.len());
        if encrypt {
            flags |= SEC_ENCRYPT;
            user_data.extend_from_slice(&flags.to_le_bytes());
            user_data.extend_from_slice(&flags_hi);
            user_data.extend_from_slice(&self.encrypt(body));
        } else {
            user_data.extend_from_slice(&flags.to_le_bytes());
            user_data.extend_from_slice(&flags_hi);
            user_data.extend_from_slice(body);
        }
        data.encode(&user_data, out)
    }

    /// The signature, then the encrypted data.
    fn encrypt(&mut self, plain: &[u8]) -> Vec<u8> {
        let signature = self.keys.sign(plain, None);
        let mut signed = Vec::with_capacity(SIGNATURE_LEN + plain.len());
        signed.extend_from_slice(&signature);
        signed.extend_from_slice(plain);
        self.keys.encrypt.apply(&mut signed[SIGNATURE_LEN..]);
        signed
    }

    /// Takes off and checks the signature in front of the data.
    fn decrypt(&mut self, signed: &[u8], salted: bool) -> io::Result<Vec<u8>> {
        if signed.len() < SIGNATURE_LEN {
            return Err(invalid("encrypted PDU is missing its signature"));
        }
        let (signature, data) = signed.split_at(SIGNATURE_LEN);
        let count = salted.then_some(self.keys.decrypt.packet_count);
        let mut plain = data.to_vec();
        self.keys.decrypt.apply(&mut plain);
        if self.keys.sign(&plain, count) != signature {
            return Err(invalid("server PDU signature does not match"));
        }
        Ok(plain)
    }
}

/// Share Control Header: totalLength, then pduType.
fn is_demand_active(share_control: &[u8]) -> bool {
    let Some(pdu_type) = share_control.get(2..4) else {
        return false;
    };
    let total_length = u16::from_le_bytes([share_control[0], share_control[1]]);
    total_length != 0x8000 && u16::from_le_bytes([pdu_type[0], pdu_type[1]]) & 0xF == PDUTYPE_DEMANDACTIVEPDU
}

fn security_exchange(encrypted_client_random: &[u8]) -> Vec<u8> {
    let length = encrypted_client_random.len() + 8;
    let mut user_data = Vec::with_capacity(8 + length);
    user_data.extend_from_slice(&SEC_EXCHANGE_PKT.to_le_bytes());
    user_data.extend_from_slice(&[0, 0]);
    user_data.extend_from_slice(&(length as u32).to_le_bytes());
    user_data.extend_from_slice(encrypted_client_random);
    user_data.extend_from_slice(&[0; 8]);
    user_data
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    Bit40,
    Bit56,
    Bit128,
}

impl Method {
    fn from_server(method: EncryptionMethod) -> io::Result<Self> {
        if method == EncryptionMethod::BIT_128 {
            Ok(Self::Bit128)
        } else if method == EncryptionMethod::BIT_56 {
            Ok(Self::Bit56)
        } else if method == EncryptionMethod::BIT_40 {
            Ok(Self::Bit40)
        } else {
            Err(invalid(format!("unsupported encryption method {method:?}")))
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Bit40 | Self::Bit56 => 8,
            Self::Bit128 => 16,
        }
    }

    /// The fixed bytes that cut a 64-bit key down to 40 or 56 bits.
    fn salt(self, key: &mut [u8]) {
        match self {
            Self::Bit40 => key[..3].copy_from_slice(&[0xD1, 0x26, 0x9E]),
            Self::Bit56 => key[0] = 0xD1,
            Self::Bit128 => {}
        }
    }
}

/// Keys from [MS-RDPBCGR] 5.3.5.
struct SessionKeys {
    mac_key: Vec<u8>,
    encrypt: Cipher,
    decrypt: Cipher,
}

impl SessionKeys {
    fn derive(client_random: &[u8; RANDOM_LEN], server_random: &[u8; RANDOM_LEN], method: Method) -> Self {
        let salted_hash = |salt: &[u8], input: &[u8]| -> [u8; 16] {
            let sha = Sha1::new()
                .chain_update(input)
                .chain_update(salt)
                .chain_update(client_random)
                .chain_update(server_random)
                .finalize();
            Md5::new().chain_update(salt).chain_update(sha).finalize().into()
        };
        let three_hashes = |secret: &[u8], labels: [&[u8]; 3]| -> Vec<u8> {
            labels.iter().flat_map(|label| salted_hash(secret, label)).collect()
        };
        let final_hash = |key: &[u8]| -> [u8; 16] {
            Md5::new()
                .chain_update(key)
                .chain_update(client_random)
                .chain_update(server_random)
                .finalize()
                .into()
        };

        let mut pre_master_secret = Vec::with_capacity(48);
        pre_master_secret.extend_from_slice(&client_random[..24]);
        pre_master_secret.extend_from_slice(&server_random[..24]);
        let master_secret = three_hashes(&pre_master_secret, [b"A".as_slice(), b"BB", b"CCC"]);
        let session_key_blob = three_hashes(&master_secret, [b"X".as_slice(), b"YY", b"ZZZ"]);

        let key_len = method.key_len();
        let mut mac_key = session_key_blob[..key_len].to_vec();
        let mut decrypt_key = final_hash(&session_key_blob[16..32])[..key_len].to_vec();
        let mut encrypt_key = final_hash(&session_key_blob[32..48])[..key_len].to_vec();
        method.salt(&mut mac_key);
        method.salt(&mut decrypt_key);
        method.salt(&mut encrypt_key);

        Self {
            mac_key,
            encrypt: Cipher::new(encrypt_key, method),
            decrypt: Cipher::new(decrypt_key, method),
        }
    }

    /// The MAC from [MS-RDPBCGR] 5.3.6.1, or the salted one from 5.3.6.1.1 with a packet count.
    fn sign(&self, data: &[u8], count: Option<u32>) -> [u8; SIGNATURE_LEN] {
        let mut sha = Sha1::new()
            .chain_update(&self.mac_key)
            .chain_update(PAD1)
            .chain_update((data.len() as u32).to_le_bytes())
            .chain_update(data);
        if let Some(count) = count {
            sha.update(count.to_le_bytes());
        }
        let md5 = Md5::new()
            .chain_update(&self.mac_key)
            .chain_update(PAD2)
            .chain_update(sha.finalize())
            .finalize();
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&md5[..SIGNATURE_LEN]);
        signature
    }
}

/// One direction of RC4, with the key update from [MS-RDPBCGR] 5.3.7.
struct Cipher {
    method: Method,
    initial_key: Vec<u8>,
    key: Vec<u8>,
    rc4: Rc4,
    /// Packets since the last key update.
    use_count: u32,
    /// Packets since the start, for the salted MAC.
    packet_count: u32,
}

impl Cipher {
    fn new(key: Vec<u8>, method: Method) -> Self {
        Self {
            method,
            rc4: Rc4::new(&key),
            initial_key: key.clone(),
            key,
            use_count: 0,
            packet_count: 0,
        }
    }

    fn apply(&mut self, data: &mut [u8]) {
        if self.use_count == KEY_UPDATE_INTERVAL {
            self.update_key();
            self.use_count = 0;
        }
        self.rc4.apply(data);
        self.use_count += 1;
        self.packet_count = self.packet_count.wrapping_add(1);
    }

    fn update_key(&mut self) {
        let sha = Sha1::new()
            .chain_update(&self.initial_key)
            .chain_update(PAD1)
            .chain_update(&self.key)
            .finalize();
        let md5 = Md5::new()
            .chain_update(&self.initial_key)
            .chain_update(PAD2)
            .chain_update(sha)
            .finalize();
        let mut key = md5[..self.method.key_len()].to_vec();
        Rc4::new(&key.clone()).apply(&mut key);
        self.method.salt(&mut key);
        self.rc4 = Rc4::new(&key);
        self.key = key;
    }
}

struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut state = [0u8; 256];
        for (index, byte) in state.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, usize::from(j));
        }
        Self { state, i: 0, j: 0 }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[usize::from(self.i)]);
            self.state.swap(usize::from(self.i), usize::from(self.j));
            let index = self.state[usize::from(self.i)].wrapping_add(self.state[usize::from(self.j)]);
            *byte ^= self.state[usize::from(index)];
        }
    }
}

/// The RSA key in the server certificate of the Server Security Data.
struct ServerPublicKey {
    /// Little-endian, as long as the encrypted client random must be.
    modulus: Vec<u8>,
    exponent: BigUint,
}

impl ServerPublicKey {
    fn parse(certificate: &[u8]) -> io::Result<Self> {
        let mut reader = Reader(certificate);
        let version = reader.u32()? & 0x7FFF_FFFF;
        match version {
            1 => Self::parse_proprietary(reader),
            2 => Self::parse_x509_chain(reader),
            _ => Err(invalid(format!("unknown server certificate version {version}"))),
        }
    }

    /// PROPRIETARYSERVERCERTIFICATE, [MS-RDPBCGR] 2.2.1.4.3.1.1.
    fn parse_proprietary(mut reader: Reader<'_>) -> io::Result<Self> {
        reader.take(8)?; // dwSigAlgId, dwKeyAlgId
        let blob_type = reader.u16()?;
        if blob_type != 0x0006 {
            return Err(invalid(format!("unexpected public key blob type 0x{blob_type:04x}")));
        }
        let blob_len = usize::from(reader.u16()?);
        let mut blob = Reader(reader.take(blob_len)?);
        if blob.take(4)? != b"RSA1" {
            return Err(invalid("server public key is not RSA1"));
        }
        let key_len = blob.u32()? as usize;
        blob.take(8)?; // bitlen, datalen
        let exponent = blob.u32()?;
        let modulus_len = key_len
            .checked_sub(8)
            .filter(|len| *len > 0)
            .ok_or_else(|| invalid("server public key is too short"))?;
        let modulus = blob.take(modulus_len)?.to_vec();
        Ok(Self {
            modulus,
            exponent: BigUint::from(exponent),
        })
    }

    /// X509 _CERTIFICATE_CHAIN, [MS-RDPELE] 2.2.1.4.2. The last certificate is the server's.
    fn parse_x509_chain(mut reader: Reader<'_>) -> io::Result<Self> {
        use pkcs1::der::Decode as _;

        let count = reader.u32()?;
        let mut last = None;
        for _ in 0..count {
            let len = reader.u32()? as usize;
            last = Some(reader.take(len)?);
        }
        let der = last.ok_or_else(|| invalid("server certificate chain is empty"))?;
        let certificate =
            x509_cert::Certificate::from_der(der).map_err(|e| invalid(format!("server certificate: {e}")))?;
        let public_key = certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| invalid("server public key is not byte aligned"))?;
        let key = pkcs1::RsaPublicKey::from_der(public_key).map_err(|e| invalid(format!("server RSA key: {e}")))?;
        let mut modulus = key.modulus.as_bytes().to_vec();
        modulus.reverse();
        Ok(Self {
            modulus,
            exponent: BigUint::from_bytes_be(key.public_exponent.as_bytes()),
        })
    }

    /// Raw RSA with little-endian numbers, as [MS-RDPBCGR] 5.3.4.1 asks for.
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let modulus = BigUint::from_bytes_le(&self.modulus);
        let encrypted = BigUint::from_bytes_le(data).modpow(&self.exponent, &modulus);
        let mut out = encrypted.to_bytes_le();
        out.resize(self.modulus.len(), 0);
        out
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        if self.0.len() < len {
            return Err(invalid("server certificate is truncated"));
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }

    fn u16(&mut self) -> io::Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> io::Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_matches_the_published_vector() {
        let mut data = *b"Plaintext";
        Rc4::new(b"Key").apply(&mut data);
        assert_eq!(data, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
    }

    fn session(method: Method) -> Session {
        Session {
            keys: SessionKeys::derive(&[1; RANDOM_LEN], &[2; RANDOM_LEN], method),
            encrypted_client_random: None,
            io_channel_id: 1003,
            message_channel_id: None,
            activated: true,
            encrypt_license: false,
        }
    }

    /// The server side of a session: its encrypt key is the client's decrypt key.
    fn mirror(session: &Session) -> SessionKeys {
        SessionKeys {
            mac_key: session.keys.mac_key.clone(),
            encrypt: Cipher::new(session.keys.decrypt.initial_key.clone(), session.keys.decrypt.method),
            decrypt: Cipher::new(session.keys.encrypt.initial_key.clone(), session.keys.encrypt.method),
        }
    }

    fn send_data(kind: u8, channel_id: u16, user_data: &[u8]) -> Vec<u8> {
        let header = [kind << 2, 0, 7, (channel_id >> 8) as u8, channel_id as u8, 0x70];
        let data = SendData {
            header: &header,
            kind,
            channel_id,
            user_data: &[],
        };
        let mut out = Vec::new();
        data.encode(user_data, &mut out).expect("encode");
        out
    }

    #[test]
    fn a_server_data_pdu_loses_its_security_header() {
        for method in [Method::Bit40, Method::Bit56, Method::Bit128] {
            let mut client = session(method);
            let mut server = mirror(&client);
            let plain = vec![0x5A; 300];

            let signature = server.sign(&plain, None);
            let mut encrypted = plain.clone();
            server.encrypt.apply(&mut encrypted);
            let mut user_data = Vec::new();
            user_data.extend_from_slice(&SEC_ENCRYPT.to_le_bytes());
            user_data.extend_from_slice(&[0, 0]);
            user_data.extend_from_slice(&signature);
            user_data.extend_from_slice(&encrypted);

            let mut out = Vec::new();
            client
                .server_pdu(&send_data(MCS_SEND_DATA_INDICATION, 1003, &user_data), &mut out)
                .expect("decrypt");
            assert_eq!(out, send_data(MCS_SEND_DATA_INDICATION, 1003, &plain));
        }
    }

    #[test]
    fn a_client_data_pdu_gains_a_signed_encrypted_header() {
        let mut client = session(Method::Bit128);
        let mut server = mirror(&client);
        let plain = b"confirm active".to_vec();

        let mut out = Vec::new();
        client
            .client_pdu(&send_data(MCS_SEND_DATA_REQUEST, 1003, &plain), &mut out)
            .expect("encrypt");

        let data = SendData::parse(&out).expect("parse").expect("send data");
        assert_eq!(&data.user_data[..4], &[0x08, 0, 0, 0]);
        let mut decrypted = data.user_data[12..].to_vec();
        server.decrypt.apply(&mut decrypted);
        assert_eq!(decrypted, plain);
        assert_eq!(server.sign(&decrypted, None), data.user_data[4..12]);
    }

    #[test]
    fn the_first_client_pdu_follows_the_security_exchange() {
        let mut client = session(Method::Bit128);
        client.activated = false;
        client.encrypted_client_random = Some(vec![0xAB; 64]);
        let mut info = Vec::new();
        info.extend_from_slice(&0x0040u16.to_le_bytes());
        info.extend_from_slice(&[0, 0]);
        info.extend_from_slice(b"client info");

        let mut out = Vec::new();
        client
            .client_pdu(&send_data(MCS_SEND_DATA_REQUEST, 1003, &info), &mut out)
            .expect("encrypt");

        let exchange_len = pdu_length(&out).expect("length").expect("whole");
        let exchange = SendData::parse(&out[..exchange_len]).expect("parse").expect("send data");
        assert_eq!(&exchange.user_data[..8], &[0x01, 0, 0, 0, 72, 0, 0, 0]);
        let info_out = SendData::parse(&out[exchange_len..]).expect("parse").expect("send data");
        assert_eq!(&info_out.user_data[..4], &[0x48, 0, 0, 0]);
    }

    #[test]
    fn fast_path_output_is_decrypted_and_shortened() {
        let mut client = session(Method::Bit128);
        let mut server = mirror(&client);
        let plain = vec![0x11; 200];

        let mut body = server.sign(&plain, None).to_vec();
        let mut encrypted = plain.clone();
        server.encrypt.apply(&mut encrypted);
        body.extend_from_slice(&encrypted);
        let mut pdu = Vec::new();
        encode_fast_path(FASTPATH_ENCRYPTED << 6, &body, &mut pdu).expect("encode");

        let mut out = Vec::new();
        client.server_pdu(&pdu, &mut out).expect("decrypt");
        let mut expected = Vec::new();
        encode_fast_path(0, &plain, &mut expected).expect("encode");
        assert_eq!(out, expected);
    }

    #[test]
    fn keys_update_after_4096_packets() {
        let mut client = session(Method::Bit128);
        let mut server = mirror(&client);
        for _ in 0..5000 {
            let plain = b"input".to_vec();
            let signed = client.encrypt(&plain);
            let mut decrypted = signed[SIGNATURE_LEN..].to_vec();
            server.decrypt.apply(&mut decrypted);
            assert_eq!(decrypted, plain);
        }
    }

    #[test]
    fn rsa_encrypts_little_endian() {
        // n = 3233 (61 * 53), e = 17: 65 encrypts to 2790.
        let key = ServerPublicKey {
            modulus: 3233u16.to_le_bytes().to_vec(),
            exponent: BigUint::from(17u32),
        };
        assert_eq!(key.encrypt(&[65]), 2790u16.to_le_bytes().to_vec());
    }
}
