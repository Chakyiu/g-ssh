use ironrdp_bulk::BulkCompressor;
use ironrdp_core::{ReadCursor, WriteBuf, decode};
use ironrdp_dvc::{DrdynvcClient, DvcProcessor, DynamicVirtualChannel};
use ironrdp_pdu::mcs::{DisconnectProviderUltimatum, DisconnectReason, McsMessage, SendDataIndicationCtx};
use ironrdp_pdu::rdp::autodetect::{AutoDetectReqPdu, AutoDetectRequest, AutoDetectResponse, AutoDetectRspPdu};
use ironrdp_pdu::rdp::headers::{
    CompressionFlags, IoChannelPdu, SHARE_DATA_HEADER_COMPRESSION_MASK, ShareDataCtx, ShareDataHeader, ShareDataPdu,
};
use ironrdp_pdu::rdp::multitransport::MultitransportRequestPdu;
use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode, ServerSetErrorInfoPdu};
use ironrdp_pdu::x224::X224;
use ironrdp_svc::{StaticChannelSet, SvcMessage, SvcProcessor, SvcProcessorMessages, client_encode_svc_messages};
use tracing::debug;

use crate::{SessionError, SessionErrorExt as _, SessionResult, reason_err};

/// X224 Processor output
#[derive(Debug, Clone)]
pub enum ProcessorOutput {
    /// A buffer with encoded data to send to the server.
    ResponseFrame(Vec<u8>),
    /// A graceful disconnect notification. Client should close the connection upon receiving this.
    Disconnect(DisconnectDescription),
    /// Received a [`ironrdp_pdu::rdp::headers::ServerDeactivateAll`] PDU. Client should execute the
    /// [Deactivation-Reactivation Sequence].
    ///
    /// [Deactivation-Reactivation Sequence]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dfc234ce-481a-4674-9a5d-2a7bafb14432
    DeactivateAll,
    /// Server Initiate Multitransport Request. The application should establish a
    /// sideband UDP transport using the request ID and security cookie, then send
    /// a [`MultitransportResponsePdu`] back on the IO channel.
    ///
    /// See [\[MS-RDPBCGR\] 2.2.15.1].
    ///
    /// [\[MS-RDPBCGR\] 2.2.15.1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/de783158-8b01-4818-8fb0-62523a5b3490
    /// [`MultitransportResponsePdu`]: ironrdp_pdu::rdp::multitransport::MultitransportResponsePdu
    MultitransportRequest(MultitransportRequestPdu),
    /// Auto-detect network characteristics from server ([\[MS-RDPBCGR\] 2.2.14]).
    ///
    /// Currently only surfaces [`AutoDetectRequest::NetworkCharacteristicsResult`].
    /// RTT requests are handled internally with automatic responses.
    ///
    /// [\[MS-RDPBCGR\] 2.2.14]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dc672839-4f4e-40b1-a71c-cd6a959baa38
    AutoDetect(AutoDetectRequest),
    /// Slow-path graphics update ([MS-RDPBCGR] 2.2.9.1.1.3).
    /// Raw update payload starting with `updateType(u16)`.
    GraphicsUpdate(Vec<u8>),
    /// Slow-path pointer update ([MS-RDPBCGR] 2.2.9.1.1.4).
    /// Raw pointer payload starting with `messageType(u16) + pad(u16)`.
    PointerUpdate(Vec<u8>),
}

#[derive(Debug, Clone)]
pub enum DisconnectDescription {
    /// Includes the reason from the MCS Disconnect Provider Ultimatum.
    /// This is the least-specific disconnect reason and is only used
    /// when a more specific disconnect code is not available.
    McsDisconnect(DisconnectReason),

    /// Includes the error information sent by the RDP server when there
    /// is a connection or disconnection failure.
    ErrorInfo(ErrorInfo),
}

pub struct Processor {
    static_channels: StaticChannelSet,
    user_channel_id: u16,
    io_channel_id: u16,
    message_channel_id: Option<u16>,
    share_id: u32,
}

impl Processor {
    pub fn new(
        static_channels: StaticChannelSet,
        user_channel_id: u16,
        io_channel_id: u16,
        message_channel_id: Option<u16>,
        share_id: u32,
    ) -> Self {
        Self {
            static_channels,
            user_channel_id,
            io_channel_id,
            message_channel_id,
            share_id,
        }
    }

    pub fn set_share_id(&mut self, share_id: u32) {
        self.share_id = share_id;
    }

    pub fn get_svc_processor<T: SvcProcessor + 'static>(&self) -> Option<&T> {
        self.static_channels
            .get_by_type::<T>()
            .and_then(|svc| svc.channel_processor_downcast_ref())
    }

    pub fn get_svc_processor_mut<T: SvcProcessor + 'static>(&mut self) -> Option<&mut T> {
        self.static_channels
            .get_by_type_mut::<T>()
            .and_then(|svc| svc.channel_processor_downcast_mut())
    }

    /// Completes user's SVC request with data, required to sent it over the network and returns
    /// a buffer with encoded data.
    pub fn process_svc_processor_messages<C: SvcProcessor + 'static>(
        &self,
        messages: SvcProcessorMessages<C>,
    ) -> SessionResult<Vec<u8>> {
        let channel_id = self
            .static_channels
            .get_channel_id_by_type::<C>()
            .ok_or_else(|| reason_err!("SVC", "channel not found"))?;

        process_svc_messages(messages.into(), channel_id, self.user_channel_id)
    }

    pub fn get_dvc<T: DvcProcessor + 'static>(&self) -> Option<&DynamicVirtualChannel> {
        self.get_svc_processor::<DrdynvcClient>()?.get_dvc_by_type_id::<T>()
    }

    pub fn get_dvc_by_channel_id(&self, channel_id: u32) -> Option<&DynamicVirtualChannel> {
        self.get_svc_processor::<DrdynvcClient>()?
            .get_dvc_by_channel_id(channel_id)
    }

    /// Processes a received PDU. Returns a vector of [`ProcessorOutput`] that must be processed
    /// in the returned order.
    ///
    /// `bulk_decompressor` is the session's, shared with Fast-Path output.
    pub fn process(
        &mut self,
        frame: &[u8],
        bulk_decompressor: &mut Option<BulkCompressor>,
    ) -> SessionResult<Vec<ProcessorOutput>> {
        let data_ctx: SendDataIndicationCtx<'_> =
            ironrdp_pdu::mcs::decode_send_data_indication(frame).map_err(SessionError::decode)?;
        let channel_id = data_ctx.channel_id;

        if channel_id == self.io_channel_id {
            self.process_io_channel(data_ctx, bulk_decompressor)
        } else if self.message_channel_id == Some(channel_id) {
            self.process_message_channel(data_ctx)
        } else if let Some(svc) = self.static_channels.get_by_channel_id_mut(channel_id) {
            let response_pdus = svc.process(data_ctx.user_data).map_err(SessionError::pdu)?;
            process_svc_messages(response_pdus, channel_id, data_ctx.initiator_id)
                .map(|data| vec![ProcessorOutput::ResponseFrame(data)])
        } else {
            Err(reason_err!("X224", "unexpected channel received: ID {channel_id}"))
        }
    }

    fn process_io_channel(
        &self,
        data_ctx: SendDataIndicationCtx<'_>,
        bulk_decompressor: &mut Option<BulkCompressor>,
    ) -> SessionResult<Vec<ProcessorOutput>> {
        debug_assert_eq!(data_ctx.channel_id, self.io_channel_id);

        let io_channel = match decompress_share_data(data_ctx, bulk_decompressor)? {
            Some(ctx) => IoChannelPdu::Data(ctx),
            None => ironrdp_pdu::rdp::headers::decode_io_channel(data_ctx).map_err(SessionError::decode)?,
        };

        match io_channel {
            IoChannelPdu::Data(ctx) => {
                match ctx.pdu {
                    ShareDataPdu::SaveSessionInfo(session_info) => {
                        debug!("Got Session Save Info PDU: {session_info:?}");
                        Ok(Vec::new())
                    }
                    // FIXME: workaround fix to not terminate the session on "unhandled PDU: Set Keyboard Indicators PDU"
                    ShareDataPdu::SetKeyboardIndicators(data) => {
                        debug!("Got Keyboard Indicators PDU: {data:?}");
                        Ok(Vec::new())
                    }
                    ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(ErrorInfo::ProtocolIndependentCode(
                        ProtocolIndependentCode::None,
                    ))) => {
                        debug!("Received None server error");
                        Ok(Vec::new())
                    }
                    ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(e)) => {
                        // This is a part of server-side graceful disconnect procedure defined
                        // in [MS-RDPBCGR].
                        //
                        // [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/149070b0-ecec-4c20-af03-934bbc48adb8
                        let desc = DisconnectDescription::ErrorInfo(e);
                        Ok(vec![ProcessorOutput::Disconnect(desc)])
                    }
                    ShareDataPdu::ShutdownDenied => {
                        debug!("ShutdownDenied received, session will be closed");

                        // As defined in [MS-RDPBCGR], when `ShareDataPdu::ShutdownDenied` is received, we
                        // need to send a disconnect ultimatum to the server if we want to proceed with the
                        // session shutdown.
                        //
                        // [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/27915739-8f77-487e-9927-55008af7fd68
                        let ultimatum = McsMessage::DisconnectProviderUltimatum(
                            DisconnectProviderUltimatum::from_reason(DisconnectReason::UserRequested),
                        );

                        let encoded_pdu = ironrdp_core::encode_vec(&X224(ultimatum)).map_err(SessionError::encode);

                        Ok(vec![
                            ProcessorOutput::ResponseFrame(encoded_pdu?),
                            ProcessorOutput::Disconnect(DisconnectDescription::McsDisconnect(
                                DisconnectReason::UserRequested,
                            )),
                        ])
                    }
                    ShareDataPdu::Update(data) => {
                        debug!("Got slow-path graphics update ({} bytes)", data.len());
                        Ok(vec![ProcessorOutput::GraphicsUpdate(data)])
                    }
                    ShareDataPdu::Pointer(data) => {
                        debug!("Got slow-path pointer update ({} bytes)", data.len());
                        Ok(vec![ProcessorOutput::PointerUpdate(data)])
                    }
                    _ => Err(reason_err!(
                        "IO channel",
                        "unhandled PDU: {:?}",
                        ctx.pdu.as_short_name()
                    )),
                }
            }
            IoChannelPdu::MultitransportRequest(pdu) => {
                debug!(
                    "Received Initiate Multitransport Request: request_id={}",
                    pdu.request_id
                );
                Ok(vec![ProcessorOutput::MultitransportRequest(pdu)])
            }
            IoChannelPdu::DeactivateAll(_) => Ok(vec![ProcessorOutput::DeactivateAll]),
        }
    }

    /// Process an auto-detect request received on the MCS message channel.
    ///
    /// During continuous auto-detection ([MS-RDPBCGR] 2.2.14) the server sends
    /// RTT (and bandwidth) requests on the message channel; the client answers
    /// RTT requests and surfaces the final Network Characteristics Result.
    fn process_message_channel(&self, data_ctx: SendDataIndicationCtx<'_>) -> SessionResult<Vec<ProcessorOutput>> {
        let Some(message_channel_id) = self.message_channel_id else {
            return Err(reason_err!("message channel", "no message channel negotiated"));
        };

        let req = decode::<AutoDetectReqPdu>(data_ctx.user_data).map_err(SessionError::decode)?;

        match req.request {
            AutoDetectRequest::RttRequest { sequence_number, .. } => {
                let response = AutoDetectRspPdu::new(AutoDetectResponse::RttResponse { sequence_number });
                let mut frame = WriteBuf::new();
                ironrdp_pdu::mcs::encode_send_data_request(
                    self.user_channel_id,
                    message_channel_id,
                    &response,
                    &mut frame,
                )
                .map_err(SessionError::encode)?;
                debug!(sequence_number, "Responded to auto-detect RTT request");
                Ok(vec![ProcessorOutput::ResponseFrame(frame.into_inner())])
            }
            req @ AutoDetectRequest::NetworkCharacteristicsResult { .. } => {
                debug!(?req, "Received network characteristics from server");
                Ok(vec![ProcessorOutput::AutoDetect(req)])
            }
            req => {
                debug!(?req, "Auto-detect request not yet implemented");
                Ok(Vec::new())
            }
        }
    }

    /// Send a pdu on the static global channel. Typically used to send input events
    pub fn encode_static(&self, output: &mut WriteBuf, pdu: ShareDataPdu) -> SessionResult<usize> {
        let written = ironrdp_pdu::rdp::headers::encode_share_data(
            self.user_channel_id,
            self.io_channel_id,
            self.share_id,
            pdu,
            output,
        )
        .map_err(SessionError::encode)?;
        Ok(written)
    }
}

/// Processes a vector of [`SvcMessage`] in preparation for sending them to the server on the `channel_id` channel.
///
/// This includes chunkifying the messages, adding MCS, x224, and tpkt headers, and encoding them into a buffer.
/// The messages returned here are ready to be sent to the server.
///
/// The caller is responsible for ensuring that the `channel_id` corresponds to the correct channel.
fn process_svc_messages(messages: Vec<SvcMessage>, channel_id: u16, initiator_id: u16) -> SessionResult<Vec<u8>> {
    client_encode_svc_messages(messages, channel_id, initiator_id).map_err(SessionError::encode)
}

/// The Share Control Header and the Share Data Header, in front of every Share Data PDU body
/// ([MS-RDPBCGR] 2.2.8.1.1.1.1 and 2.2.8.1.1.1.2).
const SHARE_HEADERS_SIZE: usize = 18;
const PDUTYPE_DATAPDU: u16 = 0x7;
/// The rest of `pduType` is the protocol version.
const PDU_TYPE_MASK: u16 = 0xF;

/// Decompresses and decodes a Share Data PDU whose body is bulk-compressed. `None` for any other
/// IO channel PDU, which decodes as it is.
///
/// ironrdp-pdu 0.9 decodes the body of a Share Data PDU as if it were plain, so the compressed
/// body has to be found from the headers first.
fn decompress_share_data(
    data_ctx: SendDataIndicationCtx<'_>,
    bulk_decompressor: &mut Option<BulkCompressor>,
) -> SessionResult<Option<ShareDataCtx>> {
    let mut src = ReadCursor::new(data_ctx.user_data);
    if src.len() < SHARE_HEADERS_SIZE {
        return Ok(None);
    }
    let _total_length = src.read_u16();
    let pdu_type = src.read_u16();
    let pdu_source = src.read_u16();
    let share_id = src.read_u32();
    // pad1, streamId, uncompressedLength and pduType2.
    let leading = src.read_slice(5);
    let compressed_type = src.read_u8();
    let compressed_length = src.read_u16();

    let flags = CompressionFlags::from_bits_retain(compressed_type & !SHARE_DATA_HEADER_COMPRESSION_MASK);
    if pdu_type & PDU_TYPE_MASK != PDUTYPE_DATAPDU || flags.is_empty() {
        return Ok(None);
    }

    let decompressor = bulk_decompressor.as_mut().ok_or_else(|| {
        reason_err!(
            "IO channel",
            "compressed Share Data PDU, but no compression was negotiated"
        )
    })?;
    // compressedLength counts both headers, as xrdp writes it and FreeRDP reads it.
    let body_length = usize::from(compressed_length)
        .checked_sub(SHARE_HEADERS_SIZE)
        .filter(|length| *length <= src.len())
        .ok_or_else(|| {
            reason_err!(
                "IO channel",
                "compressedLength {compressed_length} does not fit the PDU"
            )
        })?;
    let body = src.read_slice(body_length);
    let data = decompressor
        .decompress(body, u32::from(compressed_type))
        .map_err(|e| reason_err!("IO channel", "bulk decompression failed: {e}"))?;
    debug!(
        compressed_size = body.len(),
        decompressed_size = data.len(),
        "Decompressed slow-path PDU"
    );

    let mut share_data = leading.to_vec();
    share_data.push(compressed_type & SHARE_DATA_HEADER_COMPRESSION_MASK);
    share_data.extend_from_slice(&compressed_length.to_le_bytes());
    share_data.extend_from_slice(data);
    let header = decode::<ShareDataHeader>(&share_data).map_err(SessionError::decode)?;

    Ok(Some(ShareDataCtx {
        initiator_id: data_ctx.initiator_id,
        channel_id: data_ctx.channel_id,
        share_id,
        pdu_source,
        pdu: header.share_data_pdu,
    }))
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use ironrdp_bulk::{CompressionType, flags};
    use ironrdp_core::encode_vec;
    use ironrdp_pdu::mcs::SendDataIndication;
    use ironrdp_pdu::rdp::session_info::{InfoData, InfoType, SaveSessionInfoPdu};

    use super::*;

    const IO_CHANNEL_ID: u16 = 1003;
    const PDUTYPE2_UPDATE: u8 = 0x02;
    const PDUTYPE2_SAVE_SESSION_INFO: u8 = 0x26;
    const PACKET_COMPR_TYPE_64K: u8 = 0x01;

    fn processor() -> Processor {
        Processor::new(StaticChannelSet::new(), 1007, IO_CHANNEL_ID, None, 0x0001_03ea)
    }

    fn decompressor() -> Option<BulkCompressor> {
        Some(BulkCompressor::new(CompressionType::Rdp5).expect("decompressor"))
    }

    /// `body` as a server sends it: compressed, with its compressedType byte.
    fn compress(body: &[u8]) -> (Vec<u8>, u8) {
        let mut compressor = BulkCompressor::new(CompressionType::Rdp5).expect("compressor");
        let (size, flags) = compressor.compress(body).expect("compress");
        assert_ne!(flags & flags::PACKET_COMPRESSED, 0, "the test data has to compress");
        let flags = u8::try_from(flags & !flags::COMPRESSION_TYPE_MASK).expect("flags fit in a byte");
        (compressor.compressed_data(size).to_vec(), flags | PACKET_COMPR_TYPE_64K)
    }

    /// A Share Data PDU on the IO channel, laid out the way xrdp writes one.
    fn share_data_frame(pdu_type2: u8, compressed_type: u8, body: &[u8]) -> Vec<u8> {
        let length = u16::try_from(SHARE_HEADERS_SIZE + body.len()).expect("PDU fits");
        let mut user_data = Vec::new();
        user_data.extend_from_slice(&length.to_le_bytes());
        user_data.extend_from_slice(&(0x10 | PDUTYPE_DATAPDU).to_le_bytes());
        user_data.extend_from_slice(&1002u16.to_le_bytes());
        user_data.extend_from_slice(&0x0001_03eau32.to_le_bytes());
        // pad1, streamId, uncompressedLength.
        user_data.extend_from_slice(&[0, 1, 0, 0]);
        user_data.extend_from_slice(&[pdu_type2, compressed_type]);
        user_data.extend_from_slice(&length.to_le_bytes());
        user_data.extend_from_slice(body);
        encode_vec(&X224(McsMessage::SendDataIndication(SendDataIndication {
            initiator_id: 1002,
            channel_id: IO_CHANNEL_ID,
            user_data: Cow::Owned(user_data),
        })))
        .expect("encode frame")
    }

    fn graphics_update() -> Vec<u8> {
        (0..1024u16).map(|i| u8::try_from(i % 61).expect("below 61")).collect()
    }

    #[test]
    fn a_compressed_graphics_update_is_decompressed() {
        let update = graphics_update();
        let (compressed, compressed_type) = compress(&update);
        let frame = share_data_frame(PDUTYPE2_UPDATE, compressed_type, &compressed);

        let outputs = processor()
            .process(&frame, &mut decompressor())
            .expect("process the update");

        assert!(matches!(outputs.as_slice(), [ProcessorOutput::GraphicsUpdate(data)] if *data == update));
    }

    #[test]
    fn a_compressed_pdu_is_decompressed_before_it_is_decoded() {
        let session_info = encode_vec(&SaveSessionInfoPdu {
            info_type: InfoType::PlainNotify,
            info_data: InfoData::PlainNotify,
        })
        .expect("encode Save Session Info");
        let (compressed, compressed_type) = compress(&session_info);
        let frame = share_data_frame(PDUTYPE2_SAVE_SESSION_INFO, compressed_type, &compressed);

        let outputs = processor()
            .process(&frame, &mut decompressor())
            .expect("process Save Session Info");

        assert!(outputs.is_empty());
    }

    #[test]
    fn a_plain_update_is_left_alone() {
        let update = graphics_update();
        let frame = share_data_frame(PDUTYPE2_UPDATE, 0, &update);

        let outputs = processor()
            .process(&frame, &mut decompressor())
            .expect("process the update");

        assert!(matches!(outputs.as_slice(), [ProcessorOutput::GraphicsUpdate(data)] if *data == update));
    }

    #[test]
    fn compressed_data_without_compression_negotiated_is_an_error() {
        let (compressed, compressed_type) = compress(&graphics_update());
        let frame = share_data_frame(PDUTYPE2_UPDATE, compressed_type, &compressed);

        assert!(processor().process(&frame, &mut None).is_err());
    }
}
