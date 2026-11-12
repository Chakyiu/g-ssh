//! The rectangles of a framebuffer update, drawn into one BGRA picture.
//!
//! Pixels arrive in the format this client asked for: 32 bits, little-endian,
//! red at bit 16 and blue at bit 0. On the wire that is B, G, R and a spare
//! byte, so a raw pixel only needs its alpha set. ZRLE drops the spare byte
//! and keeps B, G, R. Tight sends three bytes too, but always R, G, B.

use std::sync::Arc;

use flate2::{Decompress, FlushDecompress, Status};
use tokio::io::{AsyncRead, AsyncReadExt};
use zune_jpeg::zune_core::bytestream::ZCursor;
use zune_jpeg::zune_core::colorspace::ColorSpace;
use zune_jpeg::zune_core::options::DecoderOptions;
use zune_jpeg::JpegDecoder;

use super::VncError;
use crate::desktop::DesktopFrame;

pub(super) const RAW: i32 = 0;
pub(super) const COPY_RECT: i32 = 1;
pub(super) const HEXTILE: i32 = 5;
pub(super) const ZLIB: i32 = 6;
pub(super) const TIGHT: i32 = 7;
pub(super) const ZRLE: i32 = 16;
pub(super) const DESKTOP_SIZE: i32 = -223;
pub(super) const LAST_RECT: i32 = -224;
pub(super) const CURSOR: i32 = -239;
pub(super) const EXTENDED_DESKTOP_SIZE: i32 = -308;

/// Tight JPEG quality, 0 (smallest) to 9 (best).
pub(super) const fn jpeg_quality(level: i32) -> i32 {
    -32 + level
}

/// zlib effort for the server, 0 (fastest) to 9 (smallest).
pub(super) const fn compress_level(level: i32) -> i32 {
    -256 + level
}

/// The largest desktop side accepted. Bigger is a broken server.
const MAX_SIDE: u16 = 16384;
/// Compressed bytes one rectangle may carry.
const MAX_COMPRESSED: usize = 64 << 20;
const OPAQUE: u8 = 255;

const HEXTILE_RAW: u8 = 1;
const HEXTILE_BACKGROUND: u8 = 1 << 1;
const HEXTILE_FOREGROUND: u8 = 1 << 2;
const HEXTILE_ANY_SUBRECTS: u8 = 1 << 3;
const HEXTILE_COLOURED: u8 = 1 << 4;

const ZRLE_TILE: u16 = 64;

const TIGHT_FILL: u8 = 0x08;
const TIGHT_JPEG: u8 = 0x09;
const TIGHT_EXPLICIT_FILTER: u8 = 0x04;
const TIGHT_FILTER_COPY: u8 = 0;
const TIGHT_FILTER_PALETTE: u8 = 1;
const TIGHT_FILTER_GRADIENT: u8 = 2;
/// Tight sends less data than this as it is, without zlib or a length.
const TIGHT_MIN_TO_COMPRESS: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl Rect {
    fn area(self) -> usize {
        usize::from(self.w) * usize::from(self.h)
    }

    /// `(start, length)` of each tile along one side.
    fn spans(start: u16, length: u16, tile: u16) -> impl Iterator<Item = (u16, u16)> {
        (0..length)
            .step_by(usize::from(tile))
            .map(move |offset| (start + offset, tile.min(length - offset)))
    }

    /// The tiles of this rectangle, row by row.
    fn tiles(self, tile: u16) -> impl Iterator<Item = Rect> {
        Self::spans(self.y, self.h, tile).flat_map(move |(y, h)| {
            Self::spans(self.x, self.w, tile).map(move |(x, w)| Rect { x, y, w, h })
        })
    }
}

/// The whole remote desktop, BGRA.
pub(super) struct Framebuffer {
    width: u16,
    height: u16,
    bgra: Vec<u8>,
}

impl Framebuffer {
    pub(super) fn new(width: u16, height: u16) -> Result<Self, VncError> {
        if width == 0 || height == 0 || width > MAX_SIDE || height > MAX_SIDE {
            return Err(VncError::Protocol(format!(
                "The server described a {width} × {height} desktop, which this client cannot show."
            )));
        }
        let mut bgra = vec![0u8; usize::from(width) * usize::from(height) * 4];
        for pixel in bgra.as_chunks_mut::<4>().0 {
            pixel[3] = OPAQUE;
        }
        Ok(Self {
            width,
            height,
            bgra,
        })
    }

    pub(super) fn width(&self) -> u16 {
        self.width
    }

    pub(super) fn height(&self) -> u16 {
        self.height
    }

    /// A copy for the view. The framebuffer keeps changing under it.
    pub(super) fn frame(&self) -> DesktopFrame {
        DesktopFrame {
            width: u32::from(self.width),
            height: u32::from(self.height),
            bgra: Arc::new(self.bgra.clone()),
        }
    }

    fn check(&self, rect: Rect) -> Result<(), VncError> {
        let fits = u32::from(rect.x) + u32::from(rect.w) <= u32::from(self.width)
            && u32::from(rect.y) + u32::from(rect.h) <= u32::from(self.height);
        if fits {
            Ok(())
        } else {
            Err(VncError::Protocol(
                "The server drew outside its desktop.".to_string(),
            ))
        }
    }

    /// Byte offset of `(x, y)`.
    fn offset(&self, x: u16, y: u16) -> usize {
        (usize::from(y) * usize::from(self.width) + usize::from(x)) * 4
    }

    /// The rows of `rect`, each a slice of BGRA bytes. `rect` must fit.
    fn rows(&mut self, rect: Rect) -> impl Iterator<Item = &mut [u8]> {
        let stride = usize::from(self.width) * 4;
        let start = self.offset(rect.x, rect.y);
        let width = usize::from(rect.w) * 4;
        let rows = usize::from(rect.h);
        self.bgra[start..]
            .chunks_mut(stride)
            .take(rows)
            .map(move |row| &mut row[..width])
    }

    fn fill(&mut self, rect: Rect, pixel: [u8; 4]) {
        for row in self.rows(rect) {
            row.as_chunks_mut::<4>().0.fill(pixel);
        }
    }

    /// Pixels row by row, `rect.w` to a row.
    fn put(&mut self, rect: Rect, pixels: &[[u8; 4]]) {
        if rect.w == 0 {
            return;
        }
        for (row, source) in self.rows(rect).zip(pixels.chunks(usize::from(rect.w))) {
            let row = row.as_chunks_mut::<4>().0;
            row[..source.len()].copy_from_slice(source);
        }
    }

    /// Wire pixels of `size` bytes each, turned into BGRA by `convert`.
    fn put_bytes(&mut self, rect: Rect, data: &[u8], size: usize, convert: fn(&[u8]) -> [u8; 4]) {
        if rect.w == 0 {
            return;
        }
        for (row, source) in self.rows(rect).zip(data.chunks(usize::from(rect.w) * size)) {
            let row = row.as_chunks_mut::<4>().0;
            for (out, pixel) in row.iter_mut().zip(source.chunks_exact(size)) {
                *out = convert(pixel);
            }
        }
    }

    /// Both rectangles must fit. They may overlap.
    fn copy(&mut self, from_x: u16, from_y: u16, rect: Rect) {
        let width = usize::from(rect.w) * 4;
        let mut copy_row = |row: u16| {
            let from = self.offset(from_x, from_y + row);
            let to = self.offset(rect.x, rect.y + row);
            self.bgra.copy_within(from..from + width, to);
        };
        if rect.y > from_y {
            (0..rect.h).rev().for_each(&mut copy_row);
        } else {
            (0..rect.h).for_each(&mut copy_row);
        }
    }
}

/// B, G, R and a spare byte, or ZRLE's three-byte pixel: the same order.
fn bgr(bytes: &[u8]) -> [u8; 4] {
    [bytes[0], bytes[1], bytes[2], OPAQUE]
}

/// Tight's three-byte pixel.
fn rgb(bytes: &[u8]) -> [u8; 4] {
    [bytes[2], bytes[1], bytes[0], OPAQUE]
}

/// zlib streams live across rectangles, so they live here.
pub(super) struct Decoders {
    zrle: Decompress,
    zlib: Decompress,
    tight: [Decompress; 4],
    compressed: Vec<u8>,
    inflated: Vec<u8>,
}

impl Default for Decoders {
    fn default() -> Self {
        Self {
            zrle: Decompress::new(true),
            zlib: Decompress::new(true),
            tight: std::array::from_fn(|_| Decompress::new(true)),
            compressed: Vec::new(),
            inflated: Vec::new(),
        }
    }
}

/// What an update said besides pixels.
#[derive(Default)]
pub(super) struct UpdateNews {
    /// The desktop changed size, so the next request asks for all of it.
    pub resized: bool,
    pub layout: Option<Layout>,
}

/// The server's screens, from an ExtendedDesktopSize rectangle.
pub(super) struct Layout {
    /// 0 the server, 1 this client's request, 2 another client's.
    pub reason: u16,
    /// 0 done. Otherwise why the request was turned down.
    pub status: u16,
    pub screens: Vec<Screen>,
}

impl Layout {
    /// This client asked for a size and the server said no.
    pub(super) fn is_refusal(&self) -> bool {
        self.reason == 1 && self.status != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Screen {
    pub id: u32,
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub flags: u32,
}

/// One FramebufferUpdate, after its message type.
pub(super) async fn update<R: AsyncRead + Unpin>(
    reader: &mut R,
    framebuffer: &mut Framebuffer,
    decoders: &mut Decoders,
) -> Result<UpdateNews, VncError> {
    let mut header = [0u8; 3];
    reader.read_exact(&mut header).await?;
    let count = u16::from_be_bytes([header[1], header[2]]);
    let mut news = UpdateNews::default();
    for _ in 0..count {
        let mut head = [0u8; 12];
        reader.read_exact(&mut head).await?;
        let rect = Rect {
            x: u16::from_be_bytes([head[0], head[1]]),
            y: u16::from_be_bytes([head[2], head[3]]),
            w: u16::from_be_bytes([head[4], head[5]]),
            h: u16::from_be_bytes([head[6], head[7]]),
        };
        match i32::from_be_bytes([head[8], head[9], head[10], head[11]]) {
            RAW => raw(reader, framebuffer, rect, decoders).await?,
            COPY_RECT => copy_rect(reader, framebuffer, rect).await?,
            HEXTILE => hextile(reader, framebuffer, rect).await?,
            ZLIB => zlib(reader, framebuffer, rect, decoders).await?,
            TIGHT => tight(reader, framebuffer, rect, decoders).await?,
            ZRLE => zrle(reader, framebuffer, rect, decoders).await?,
            DESKTOP_SIZE => news.resized |= resize(framebuffer, rect)?,
            EXTENDED_DESKTOP_SIZE => {
                let layout = layout(reader, rect).await?;
                if !layout.is_refusal() {
                    news.resized |= resize(framebuffer, rect)?;
                }
                news.layout = Some(layout);
            }
            CURSOR => skip_cursor(reader, rect).await?,
            LAST_RECT => break,
            other => {
                return Err(VncError::Protocol(format!(
                    "The server sent a rectangle in encoding {other}, which this client did not ask for."
                )))
            }
        }
    }
    Ok(news)
}

/// Read and drop `length` bytes.
pub(super) async fn skip<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut length: usize,
) -> Result<(), VncError> {
    let mut scratch = [0u8; 4096];
    while length > 0 {
        let chunk = length.min(scratch.len());
        reader.read_exact(&mut scratch[..chunk]).await?;
        length -= chunk;
    }
    Ok(())
}

async fn read_into<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    length: usize,
) -> Result<(), VncError> {
    if length > MAX_COMPRESSED.max(usize::from(MAX_SIDE) * usize::from(MAX_SIDE) * 4) {
        return Err(VncError::Protocol(
            "The server sent a rectangle too large to read.".to_string(),
        ));
    }
    buf.resize(length, 0);
    reader.read_exact(buf).await?;
    Ok(())
}

async fn read_compressed<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    length: usize,
) -> Result<(), VncError> {
    if length > MAX_COMPRESSED {
        return Err(VncError::Protocol(
            "The server sent a rectangle too large to read.".to_string(),
        ));
    }
    read_into(reader, buf, length).await
}

fn resize(framebuffer: &mut Framebuffer, rect: Rect) -> Result<bool, VncError> {
    if (rect.w, rect.h) == (framebuffer.width, framebuffer.height) {
        return Ok(false);
    }
    *framebuffer = Framebuffer::new(rect.w, rect.h)?;
    Ok(true)
}

async fn raw<R: AsyncRead + Unpin>(
    reader: &mut R,
    framebuffer: &mut Framebuffer,
    rect: Rect,
    decoders: &mut Decoders,
) -> Result<(), VncError> {
    framebuffer.check(rect)?;
    read_into(reader, &mut decoders.inflated, rect.area() * 4).await?;
    framebuffer.put_bytes(rect, &decoders.inflated, 4, bgr);
    Ok(())
}

async fn copy_rect<R: AsyncRead + Unpin>(
    reader: &mut R,
    framebuffer: &mut Framebuffer,
    rect: Rect,
) -> Result<(), VncError> {
    let from_x = reader.read_u16().await?;
    let from_y = reader.read_u16().await?;
    framebuffer.check(rect)?;
    framebuffer.check(Rect {
        x: from_x,
        y: from_y,
        ..rect
    })?;
    framebuffer.copy(from_x, from_y, rect);
    Ok(())
}

async fn read_pixel<R: AsyncRead + Unpin>(reader: &mut R) -> Result<[u8; 4], VncError> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes).await?;
    Ok(bgr(&bytes))
}

/// 16 × 16 tiles. Each is raw, or a background with solid subrectangles.
/// The background and foreground carry over from one tile to the next.
async fn hextile<R: AsyncRead + Unpin>(
    reader: &mut R,
    framebuffer: &mut Framebuffer,
    rect: Rect,
) -> Result<(), VncError> {
    framebuffer.check(rect)?;
    let mut background = [0, 0, 0, OPAQUE];
    let mut foreground = [0, 0, 0, OPAQUE];
    let mut bytes = Vec::with_capacity(16 * 16 * 4);
    for tile in rect.tiles(16) {
        let mask = reader.read_u8().await?;
        if mask & HEXTILE_RAW != 0 {
            read_into(reader, &mut bytes, tile.area() * 4).await?;
            framebuffer.put_bytes(tile, &bytes, 4, bgr);
            continue;
        }
        if mask & HEXTILE_BACKGROUND != 0 {
            background = read_pixel(reader).await?;
        }
        framebuffer.fill(tile, background);
        if mask & HEXTILE_FOREGROUND != 0 {
            foreground = read_pixel(reader).await?;
        }
        if mask & HEXTILE_ANY_SUBRECTS == 0 {
            continue;
        }
        let count = usize::from(reader.read_u8().await?);
        let coloured = mask & HEXTILE_COLOURED != 0;
        let size = if coloured { 6 } else { 2 };
        read_into(reader, &mut bytes, count * size).await?;
        for subrect in bytes.chunks_exact(size) {
            let (colour, geometry) = if coloured {
                (bgr(&subrect[..4]), &subrect[4..])
            } else {
                (foreground, subrect)
            };
            let x = u16::from(geometry[0] >> 4);
            let y = u16::from(geometry[0] & 0x0f);
            let w = u16::from(geometry[1] >> 4) + 1;
            let h = u16::from(geometry[1] & 0x0f) + 1;
            if x + w > tile.w || y + h > tile.h {
                return Err(VncError::Protocol(
                    "A Hextile tile drew outside itself.".to_string(),
                ));
            }
            framebuffer.fill(
                Rect {
                    x: tile.x + x,
                    y: tile.y + y,
                    w,
                    h,
                },
                colour,
            );
        }
    }
    Ok(())
}

/// Raw pixels through one zlib stream that lasts the whole session.
async fn zlib<R: AsyncRead + Unpin>(
    reader: &mut R,
    framebuffer: &mut Framebuffer,
    rect: Rect,
    decoders: &mut Decoders,
) -> Result<(), VncError> {
    framebuffer.check(rect)?;
    let length = reader.read_u32().await? as usize;
    read_compressed(reader, &mut decoders.compressed, length).await?;
    let expected = rect.area() * 4;
    inflate(
        &mut decoders.zlib,
        &decoders.compressed,
        &mut decoders.inflated,
        expected,
    )?;
    exactly(&decoders.inflated, expected)?;
    framebuffer.put_bytes(rect, &decoders.inflated, 4, bgr);
    Ok(())
}

/// 64 × 64 tiles through one zlib stream that lasts the whole session. A
/// tile is raw, solid, a packed palette, or runs of colours.
async fn zrle<R: AsyncRead + Unpin>(
    reader: &mut R,
    framebuffer: &mut Framebuffer,
    rect: Rect,
    decoders: &mut Decoders,
) -> Result<(), VncError> {
    framebuffer.check(rect)?;
    let length = reader.read_u32().await? as usize;
    read_compressed(reader, &mut decoders.compressed, length).await?;
    // A run of single pixels is the worst case: four bytes a pixel.
    let limit = rect.area() * 4 + rect.tiles(ZRLE_TILE).count() * 512 + 4096;
    inflate(
        &mut decoders.zrle,
        &decoders.compressed,
        &mut decoders.inflated,
        limit,
    )?;
    zrle_tiles(framebuffer, rect, &decoders.inflated)
}

fn zrle_tiles(framebuffer: &mut Framebuffer, rect: Rect, data: &[u8]) -> Result<(), VncError> {
    let mut input = Bytes::new(data);
    let mut pixels = vec![[0u8; 4]; usize::from(ZRLE_TILE) * usize::from(ZRLE_TILE)];
    let mut palette = Vec::with_capacity(128);
    for tile in rect.tiles(ZRLE_TILE) {
        let count = tile.area();
        let pixels = &mut pixels[..count];
        let subencoding = input.u8()?;
        match subencoding {
            0 => {
                let bytes = input.take(count * 3)?.as_chunks::<3>().0;
                for (pixel, bytes) in pixels.iter_mut().zip(bytes) {
                    *pixel = bgr(bytes);
                }
            }
            1 => pixels.fill(bgr(input.take(3)?)),
            2..=16 => {
                read_palette(&mut input, &mut palette, usize::from(subencoding))?;
                let bits = match subencoding {
                    2 => 1,
                    3..=4 => 2,
                    _ => 4,
                };
                let width = usize::from(tile.w);
                let row_bytes = (width * bits).div_ceil(8);
                for row in pixels.chunks_mut(width) {
                    let packed = input.take(row_bytes)?;
                    for (x, pixel) in row.iter_mut().enumerate() {
                        let bit = x * bits;
                        let index = (packed[bit / 8] >> (8 - bits - bit % 8)) & ((1 << bits) - 1);
                        *pixel = palette_colour(&palette, index)?;
                    }
                }
            }
            128 => {
                let mut filled = 0;
                while filled < count {
                    let colour = bgr(input.take(3)?);
                    let run = run_length(&mut input, count - filled)?;
                    pixels[filled..filled + run].fill(colour);
                    filled += run;
                }
            }
            130..=255 => {
                read_palette(&mut input, &mut palette, usize::from(subencoding - 128))?;
                let mut filled = 0;
                while filled < count {
                    let index = input.u8()?;
                    let colour = palette_colour(&palette, index & 0x7f)?;
                    let run = if index & 0x80 != 0 {
                        run_length(&mut input, count - filled)?
                    } else {
                        1
                    };
                    pixels[filled..filled + run].fill(colour);
                    filled += run;
                }
            }
            other => {
                return Err(VncError::Protocol(format!(
                    "The server sent ZRLE subencoding {other}, which does not exist."
                )))
            }
        }
        framebuffer.put(tile, pixels);
    }
    Ok(())
}

fn read_palette(
    input: &mut Bytes<'_>,
    palette: &mut Vec<[u8; 4]>,
    size: usize,
) -> Result<(), VncError> {
    palette.clear();
    let bytes = input.take(size * 3)?.as_chunks::<3>().0;
    palette.extend(bytes.iter().map(|pixel| bgr(pixel)));
    Ok(())
}

fn palette_colour(palette: &[[u8; 4]], index: u8) -> Result<[u8; 4], VncError> {
    palette.get(usize::from(index)).copied().ok_or_else(|| {
        VncError::Protocol("The server used a colour missing from its palette.".to_string())
    })
}

/// One plus the sum of the bytes, which go on while they are 255.
fn run_length(input: &mut Bytes<'_>, room: usize) -> Result<usize, VncError> {
    let mut length = 1;
    loop {
        let byte = input.u8()?;
        length += usize::from(byte);
        if byte != 255 {
            break;
        }
    }
    if length > room {
        return Err(VncError::Protocol(
            "A ZRLE run went past its tile.".to_string(),
        ));
    }
    Ok(length)
}

/// Fill, JPEG, or zlib on one of four streams with an optional filter:
/// a palette, or the gradient that predicts each pixel from its neighbours.
async fn tight<R: AsyncRead + Unpin>(
    reader: &mut R,
    framebuffer: &mut Framebuffer,
    rect: Rect,
    decoders: &mut Decoders,
) -> Result<(), VncError> {
    framebuffer.check(rect)?;
    let control = reader.read_u8().await?;
    for (index, stream) in decoders.tight.iter_mut().enumerate() {
        if control & (1 << index) != 0 {
            *stream = Decompress::new(true);
        }
    }
    match control >> 4 {
        TIGHT_FILL => {
            let mut colour = [0u8; 3];
            reader.read_exact(&mut colour).await?;
            framebuffer.fill(rect, rgb(&colour));
        }
        TIGHT_JPEG => {
            let length = compact_length(reader).await?;
            read_compressed(reader, &mut decoders.compressed, length).await?;
            let pixels = jpeg(&decoders.compressed, rect)?;
            framebuffer.put_bytes(rect, &pixels, 4, bgr);
        }
        basic if basic < TIGHT_FILL => {
            tight_basic(reader, framebuffer, rect, decoders, basic).await?;
        }
        other => {
            return Err(VncError::Protocol(format!(
                "The server sent Tight subencoding {other}, which this client does not know."
            )))
        }
    }
    Ok(())
}

async fn tight_basic<R: AsyncRead + Unpin>(
    reader: &mut R,
    framebuffer: &mut Framebuffer,
    rect: Rect,
    decoders: &mut Decoders,
    control: u8,
) -> Result<(), VncError> {
    let stream = usize::from(control & 0x03);
    let filter = if control & TIGHT_EXPLICIT_FILTER != 0 {
        reader.read_u8().await?
    } else {
        TIGHT_FILTER_COPY
    };
    match filter {
        TIGHT_FILTER_COPY => {
            let data = tight_data(reader, decoders, stream, rect.area() * 3).await?;
            framebuffer.put_bytes(rect, data, 3, rgb);
        }
        TIGHT_FILTER_PALETTE => {
            let size = usize::from(reader.read_u8().await?) + 1;
            let mut bytes = vec![0u8; size * 3];
            reader.read_exact(&mut bytes).await?;
            let palette: Vec<[u8; 4]> = bytes
                .as_chunks::<3>()
                .0
                .iter()
                .map(|pixel| rgb(pixel))
                .collect();
            let packed = size == 2;
            let row_bytes = if packed {
                usize::from(rect.w).div_ceil(8)
            } else {
                usize::from(rect.w)
            };
            let data =
                tight_data(reader, decoders, stream, row_bytes * usize::from(rect.h)).await?;
            let pixels = indexed(rect, data, &palette, packed)?;
            framebuffer.put(rect, &pixels);
        }
        TIGHT_FILTER_GRADIENT => {
            let data = tight_data(reader, decoders, stream, rect.area() * 3).await?;
            framebuffer.put(rect, &gradient(rect, data));
        }
        other => {
            return Err(VncError::Protocol(format!(
                "The server sent Tight filter {other}, which this client does not know."
            )))
        }
    }
    Ok(())
}

/// `length` bytes of filtered data: as they are when short, else through
/// the chosen zlib stream.
async fn tight_data<'d, R: AsyncRead + Unpin>(
    reader: &mut R,
    decoders: &'d mut Decoders,
    stream: usize,
    length: usize,
) -> Result<&'d [u8], VncError> {
    if length < TIGHT_MIN_TO_COMPRESS {
        read_into(reader, &mut decoders.inflated, length).await?;
        return Ok(&decoders.inflated);
    }
    let compressed = compact_length(reader).await?;
    read_compressed(reader, &mut decoders.compressed, compressed).await?;
    inflate(
        &mut decoders.tight[stream],
        &decoders.compressed,
        &mut decoders.inflated,
        length,
    )?;
    exactly(&decoders.inflated, length)?;
    Ok(&decoders.inflated)
}

/// One to three bytes, seven bits each, the last byte all eight.
async fn compact_length<R: AsyncRead + Unpin>(reader: &mut R) -> Result<usize, VncError> {
    let first = reader.read_u8().await?;
    let mut length = usize::from(first & 0x7f);
    if first & 0x80 != 0 {
        let second = reader.read_u8().await?;
        length |= usize::from(second & 0x7f) << 7;
        if second & 0x80 != 0 {
            length |= usize::from(reader.read_u8().await?) << 14;
        }
    }
    Ok(length)
}

/// Palette indices: a bit a pixel for two colours, each row padded to a
/// byte, else a byte a pixel.
fn indexed(
    rect: Rect,
    data: &[u8],
    palette: &[[u8; 4]],
    packed: bool,
) -> Result<Vec<[u8; 4]>, VncError> {
    let width = usize::from(rect.w);
    let mut pixels = Vec::with_capacity(rect.area());
    if width == 0 {
        return Ok(pixels);
    }
    if packed {
        for row in data.chunks_exact(width.div_ceil(8)) {
            for x in 0..width {
                let bit = (row[x / 8] >> (7 - x % 8)) & 1;
                pixels.push(palette[usize::from(bit)]);
            }
        }
    } else {
        for &index in data {
            pixels.push(palette_colour(palette, index)?);
        }
    }
    Ok(pixels)
}

/// Each colour component is the difference from left + above - above-left,
/// clamped to a byte.
fn gradient(rect: Rect, data: &[u8]) -> Vec<[u8; 4]> {
    let width = usize::from(rect.w);
    let mut pixels = Vec::with_capacity(rect.area());
    if width == 0 {
        return pixels;
    }
    let mut above = vec![0u8; width * 3];
    let mut current = vec![0u8; width * 3];
    for row in data.chunks_exact(width * 3) {
        for x in 0..width {
            for c in 0..3 {
                let up = i32::from(above[x * 3 + c]);
                let (left, up_left) = if x == 0 {
                    (0, 0)
                } else {
                    (
                        i32::from(current[(x - 1) * 3 + c]),
                        i32::from(above[(x - 1) * 3 + c]),
                    )
                };
                let estimate = (left + up - up_left).clamp(0, 255) as u8;
                current[x * 3 + c] = estimate.wrapping_add(row[x * 3 + c]);
            }
            pixels.push(rgb(&current[x * 3..x * 3 + 3]));
        }
        std::mem::swap(&mut above, &mut current);
    }
    pixels
}

/// BGRA, the size of `rect`.
fn jpeg(data: &[u8], rect: Rect) -> Result<Vec<u8>, VncError> {
    let options = DecoderOptions::default().jpeg_set_out_colorspace(ColorSpace::BGRA);
    let mut decoder = JpegDecoder::new_with_options(ZCursor::new(data), options);
    let pixels = decoder.decode().map_err(|error| {
        VncError::Protocol(format!(
            "The server sent a JPEG that did not decode: {error:?}"
        ))
    })?;
    let size = decoder.info().map(|info| (info.width, info.height));
    if size != Some((rect.w, rect.h)) || pixels.len() != rect.area() * 4 {
        return Err(VncError::Protocol(
            "The server sent a JPEG of the wrong size.".to_string(),
        ));
    }
    Ok(pixels)
}

async fn skip_cursor<R: AsyncRead + Unpin>(reader: &mut R, rect: Rect) -> Result<(), VncError> {
    let pixels = rect.area() * 4;
    let mask = usize::from(rect.w).div_ceil(8) * usize::from(rect.h);
    skip(reader, pixels + mask).await
}

async fn layout<R: AsyncRead + Unpin>(reader: &mut R, rect: Rect) -> Result<Layout, VncError> {
    let mut head = [0u8; 4];
    reader.read_exact(&mut head).await?;
    let mut bytes = vec![0u8; usize::from(head[0]) * 16];
    reader.read_exact(&mut bytes).await?;
    let screens = bytes
        .as_chunks::<16>()
        .0
        .iter()
        .map(|screen| Screen {
            id: u32::from_be_bytes([screen[0], screen[1], screen[2], screen[3]]),
            x: u16::from_be_bytes([screen[4], screen[5]]),
            y: u16::from_be_bytes([screen[6], screen[7]]),
            width: u16::from_be_bytes([screen[8], screen[9]]),
            height: u16::from_be_bytes([screen[10], screen[11]]),
            flags: u32::from_be_bytes([screen[12], screen[13], screen[14], screen[15]]),
        })
        .collect();
    Ok(Layout {
        reason: rect.x,
        status: rect.y,
        screens,
    })
}

/// Feed one rectangle's bytes through a stream that lives across
/// rectangles. Every byte has to go in, or the next rectangle starts in the
/// wrong place. The server flushes at the end of each rectangle, so once the
/// input is used up everything is out.
fn inflate(
    stream: &mut Decompress,
    mut input: &[u8],
    out: &mut Vec<u8>,
    limit: usize,
) -> Result<(), VncError> {
    out.clear();
    loop {
        if out.capacity() - out.len() < 4096 {
            if out.len() > limit {
                return Err(too_long());
            }
            out.reserve(out.len().clamp(16 * 1024, 4 << 20));
        }
        let consumed_before = stream.total_in();
        let produced_before = out.len();
        let status = stream
            .decompress_vec(input, out, FlushDecompress::Sync)
            .map_err(|error| {
                VncError::Protocol(format!("The server's compressed data is broken: {error}"))
            })?;
        let consumed = (stream.total_in() - consumed_before) as usize;
        input = &input[consumed..];
        if out.len() > limit {
            return Err(too_long());
        }
        let has_room = out.len() < out.capacity();
        if status == Status::StreamEnd || (input.is_empty() && has_room) {
            return Ok(());
        }
        if consumed == 0 && out.len() == produced_before && has_room {
            return Err(VncError::Protocol(
                "The server's compressed data stopped short.".to_string(),
            ));
        }
    }
}

fn too_long() -> VncError {
    VncError::Protocol("The server's compressed data was longer than its rectangle.".to_string())
}

fn exactly(data: &[u8], length: usize) -> Result<(), VncError> {
    if data.len() == length {
        Ok(())
    } else {
        Err(VncError::Protocol(
            "The server's compressed data was shorter than its rectangle.".to_string(),
        ))
    }
}

/// Reads through a decompressed buffer.
struct Bytes<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Bytes<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], VncError> {
        let end = self
            .at
            .checked_add(length)
            .filter(|&end| end <= self.data.len())
            .ok_or_else(|| {
                VncError::Protocol("The server's ZRLE data stopped short.".to_string())
            })?;
        let bytes = &self.data[self.at..end];
        self.at = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, VncError> {
        Ok(self.take(1)?[0])
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::write::ZlibEncoder;
    use flate2::Compression;

    use super::*;

    const RED: [u8; 4] = [0, 0, 255, OPAQUE];
    const GREEN: [u8; 4] = [0, 255, 0, OPAQUE];
    const BLUE: [u8; 4] = [255, 0, 0, OPAQUE];
    const BLACK: [u8; 4] = [0, 0, 0, OPAQUE];

    /// An 8 × 8 JPEG of R 200, G 100, B 50, from PIL at quality 95.
    const JPEG: &str = concat!(
        "ffd8ffe000104a46494600010100000100010000ffdb00430002010101010102",
        "0101010202020202040302020202050404030406050606060506060607090806",
        "0709070606080b08090a0a0a0a0a06080b0c0b0a0c090a0a0affdb0043010202",
        "02020202050303050a0706070a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0affc0",
        "0011080008000803011100021101031101ffc400140001000000000000000000",
        "00000000000005ffc40014100100000000000000000000000000000000ffc400",
        "14010100000000000000000000000000000008ffc40014110100000000000000",
        "000000000000000000ffda000c03010002110311003f003c57361fffd9",
    );

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// One update: padding, the rectangle count, then the rectangles.
    fn message(rects: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0];
        bytes.extend_from_slice(&(rects.len() as u16).to_be_bytes());
        for rect in rects {
            bytes.extend_from_slice(rect);
        }
        bytes
    }

    fn rect(x: u16, y: u16, w: u16, h: u16, encoding: i32, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in [x, y, w, h] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&encoding.to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    /// The wire pixel this client asked for: B, G, R, spare.
    fn wire(pixel: [u8; 4]) -> [u8; 4] {
        [pixel[0], pixel[1], pixel[2], 0]
    }

    /// Tight's three bytes, R, G, B.
    fn tight_pixel(pixel: [u8; 4]) -> [u8; 3] {
        [pixel[2], pixel[1], pixel[0]]
    }

    /// A zlib stream that, like a server's, lives across rectangles and is
    /// flushed at the end of each.
    struct Deflater(ZlibEncoder<Vec<u8>>);

    impl Deflater {
        fn new() -> Self {
            Self(ZlibEncoder::new(Vec::new(), Compression::default()))
        }

        fn chunk(&mut self, data: &[u8]) -> Vec<u8> {
            self.0.write_all(data).unwrap();
            self.0.flush().unwrap();
            std::mem::take(self.0.get_mut())
        }
    }

    fn compact(length: usize) -> Vec<u8> {
        let mut bytes = vec![(length & 0x7f) as u8];
        if length > 0x7f {
            bytes[0] |= 0x80;
            bytes.push(((length >> 7) & 0x7f) as u8);
            if length > 0x3fff {
                bytes[1] |= 0x80;
                bytes.push((length >> 14) as u8);
            }
        }
        bytes
    }

    fn decode(framebuffer: &mut Framebuffer, decoders: &mut Decoders, bytes: &[u8]) -> UpdateNews {
        try_decode(framebuffer, decoders, bytes).unwrap()
    }

    fn try_decode(
        framebuffer: &mut Framebuffer,
        decoders: &mut Decoders,
        bytes: &[u8],
    ) -> Result<UpdateNews, VncError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut reader = bytes;
        let news = runtime.block_on(update(&mut reader, framebuffer, decoders))?;
        assert!(reader.is_empty(), "{} bytes left unread", reader.len());
        Ok(news)
    }

    fn pixel(framebuffer: &Framebuffer, x: u16, y: u16) -> [u8; 4] {
        let at = framebuffer.offset(x, y);
        framebuffer.bgra[at..at + 4].try_into().unwrap()
    }

    #[test]
    fn raw_pixels_get_an_opaque_alpha() {
        let mut framebuffer = Framebuffer::new(4, 4).unwrap();
        let body: Vec<u8> = [RED, GREEN, BLUE, RED]
            .iter()
            .flat_map(|p| wire(*p))
            .collect();
        let bytes = message(&[rect(1, 1, 2, 2, RAW, &body)]);
        decode(&mut framebuffer, &mut Decoders::default(), &bytes);
        assert_eq!(pixel(&framebuffer, 1, 1), RED);
        assert_eq!(pixel(&framebuffer, 2, 1), GREEN);
        assert_eq!(pixel(&framebuffer, 1, 2), BLUE);
        assert_eq!(pixel(&framebuffer, 0, 0), BLACK);
    }

    #[test]
    fn copy_rect_handles_an_overlapping_move_down() {
        let mut framebuffer = Framebuffer::new(2, 3).unwrap();
        let body: Vec<u8> = [RED, RED, GREEN, GREEN, BLUE, BLUE]
            .iter()
            .flat_map(|p| wire(*p))
            .collect();
        let mut decoders = Decoders::default();
        decode(
            &mut framebuffer,
            &mut decoders,
            &message(&[rect(0, 0, 2, 3, RAW, &body)]),
        );
        // Rows 0..2 move down one row.
        let bytes = message(&[rect(0, 1, 2, 2, COPY_RECT, &[0, 0, 0, 0])]);
        decode(&mut framebuffer, &mut decoders, &bytes);
        assert_eq!(pixel(&framebuffer, 0, 0), RED);
        assert_eq!(pixel(&framebuffer, 0, 1), RED);
        assert_eq!(pixel(&framebuffer, 1, 2), GREEN);
    }

    #[test]
    fn hextile_keeps_background_and_foreground_across_tiles() {
        let mut framebuffer = Framebuffer::new(32, 16).unwrap();
        let mut body = Vec::new();
        // Tile one: red background, a green foreground subrect at (2, 3) 4 × 2.
        body.push(HEXTILE_BACKGROUND | HEXTILE_FOREGROUND | HEXTILE_ANY_SUBRECTS);
        body.extend_from_slice(&wire(RED));
        body.extend_from_slice(&wire(GREEN));
        body.extend_from_slice(&[1, 0x23, 0x31]);
        // Tile two: same colours, one coloured blue subrect at (0, 0) 1 × 1.
        body.push(HEXTILE_ANY_SUBRECTS | HEXTILE_COLOURED);
        body.push(1);
        body.extend_from_slice(&wire(BLUE));
        body.extend_from_slice(&[0x00, 0x00]);
        decode(
            &mut framebuffer,
            &mut Decoders::default(),
            &message(&[rect(0, 0, 32, 16, HEXTILE, &body)]),
        );
        assert_eq!(pixel(&framebuffer, 0, 0), RED);
        assert_eq!(pixel(&framebuffer, 2, 3), GREEN);
        assert_eq!(pixel(&framebuffer, 5, 4), GREEN);
        assert_eq!(pixel(&framebuffer, 6, 4), RED);
        assert_eq!(pixel(&framebuffer, 16, 0), BLUE);
        assert_eq!(pixel(&framebuffer, 17, 0), RED);
    }

    #[test]
    fn hextile_raw_tile_and_a_subrect_outside_its_tile() {
        let mut framebuffer = Framebuffer::new(2, 1).unwrap();
        let mut body = vec![HEXTILE_RAW];
        body.extend_from_slice(&wire(GREEN));
        body.extend_from_slice(&wire(BLUE));
        let mut decoders = Decoders::default();
        decode(
            &mut framebuffer,
            &mut decoders,
            &message(&[rect(0, 0, 2, 1, HEXTILE, &body)]),
        );
        assert_eq!(pixel(&framebuffer, 1, 0), BLUE);

        let mut body = vec![HEXTILE_BACKGROUND | HEXTILE_FOREGROUND | HEXTILE_ANY_SUBRECTS];
        body.extend_from_slice(&wire(RED));
        body.extend_from_slice(&wire(GREEN));
        body.extend_from_slice(&[1, 0x00, 0x20]);
        let result = try_decode(
            &mut framebuffer,
            &mut decoders,
            &message(&[rect(0, 0, 2, 1, HEXTILE, &body)]),
        );
        assert!(matches!(result, Err(VncError::Protocol(_))));
    }

    #[test]
    fn zlib_rectangles_share_one_stream() {
        let mut framebuffer = Framebuffer::new(2, 2).unwrap();
        let mut decoders = Decoders::default();
        let mut deflater = Deflater::new();
        for (y, colour) in [(0, RED), (1, BLUE)] {
            let data: Vec<u8> = [colour, colour].iter().flat_map(|p| wire(*p)).collect();
            let chunk = deflater.chunk(&data);
            let mut body = (chunk.len() as u32).to_be_bytes().to_vec();
            body.extend_from_slice(&chunk);
            decode(
                &mut framebuffer,
                &mut decoders,
                &message(&[rect(0, y, 2, 1, ZLIB, &body)]),
            );
        }
        assert_eq!(pixel(&framebuffer, 1, 0), RED);
        assert_eq!(pixel(&framebuffer, 0, 1), BLUE);
    }

    fn zrle_rect(deflater: &mut Deflater, x: u16, y: u16, w: u16, h: u16, tiles: &[u8]) -> Vec<u8> {
        let chunk = deflater.chunk(tiles);
        let mut body = (chunk.len() as u32).to_be_bytes().to_vec();
        body.extend_from_slice(&chunk);
        rect(x, y, w, h, ZRLE, &body)
    }

    fn cpixel(pixel: [u8; 4]) -> [u8; 3] {
        [pixel[0], pixel[1], pixel[2]]
    }

    #[test]
    fn zrle_solid_raw_and_packed_palette_tiles() {
        let mut framebuffer = Framebuffer::new(70, 4).unwrap();
        let mut decoders = Decoders::default();
        let mut deflater = Deflater::new();
        // A 70-wide rectangle is a 64-wide tile and a 6-wide one.
        let mut tiles = vec![1];
        tiles.extend_from_slice(&cpixel(GREEN));
        // Second tile, 6 × 4: two colours, one bit a pixel, rows padded.
        tiles.push(2);
        tiles.extend_from_slice(&cpixel(RED));
        tiles.extend_from_slice(&cpixel(BLUE));
        tiles.extend_from_slice(&[0b1000_0000, 0b0100_0000, 0b0010_0000, 0b0001_0000]);
        let bytes = message(&[zrle_rect(&mut deflater, 0, 0, 70, 4, &tiles)]);
        decode(&mut framebuffer, &mut decoders, &bytes);
        assert_eq!(pixel(&framebuffer, 63, 3), GREEN);
        assert_eq!(pixel(&framebuffer, 64, 0), BLUE);
        assert_eq!(pixel(&framebuffer, 65, 0), RED);
        assert_eq!(pixel(&framebuffer, 65, 1), BLUE);
        assert_eq!(pixel(&framebuffer, 67, 3), BLUE);

        // The same stream carries on into the next rectangle: a raw 2 × 1 tile.
        let mut tiles = vec![0];
        tiles.extend_from_slice(&cpixel(BLUE));
        tiles.extend_from_slice(&cpixel(RED));
        let bytes = message(&[zrle_rect(&mut deflater, 0, 0, 2, 1, &tiles)]);
        decode(&mut framebuffer, &mut decoders, &bytes);
        assert_eq!(pixel(&framebuffer, 0, 0), BLUE);
        assert_eq!(pixel(&framebuffer, 1, 0), RED);
    }

    #[test]
    fn zrle_plain_and_palette_runs() {
        let mut framebuffer = Framebuffer::new(300, 1).unwrap();
        let mut decoders = Decoders::default();
        let mut deflater = Deflater::new();
        // Plain RLE over a 64 × 1 tile: 3 red, then 61 green.
        let mut tiles = vec![128];
        tiles.extend_from_slice(&cpixel(RED));
        tiles.push(2);
        tiles.extend_from_slice(&cpixel(GREEN));
        tiles.push(60);
        let bytes = message(&[zrle_rect(&mut deflater, 0, 0, 64, 1, &tiles)]);
        decode(&mut framebuffer, &mut decoders, &bytes);
        assert_eq!(pixel(&framebuffer, 2, 0), RED);
        assert_eq!(pixel(&framebuffer, 3, 0), GREEN);
        assert_eq!(pixel(&framebuffer, 63, 0), GREEN);

        // Palette RLE: a single blue, then a run of 63 red.
        let mut tiles = vec![130];
        tiles.extend_from_slice(&cpixel(BLUE));
        tiles.extend_from_slice(&cpixel(RED));
        tiles.extend_from_slice(&[0x00, 0x81, 62]);
        let bytes = message(&[zrle_rect(&mut deflater, 64, 0, 64, 1, &tiles)]);
        decode(&mut framebuffer, &mut decoders, &bytes);
        assert_eq!(pixel(&framebuffer, 64, 0), BLUE);
        assert_eq!(pixel(&framebuffer, 65, 0), RED);
        assert_eq!(pixel(&framebuffer, 127, 0), RED);
    }

    #[test]
    fn zrle_run_past_its_tile_is_an_error() {
        let mut framebuffer = Framebuffer::new(4, 1).unwrap();
        let mut deflater = Deflater::new();
        let mut tiles = vec![128];
        tiles.extend_from_slice(&cpixel(RED));
        tiles.push(10);
        let bytes = message(&[zrle_rect(&mut deflater, 0, 0, 4, 1, &tiles)]);
        let result = try_decode(&mut framebuffer, &mut Decoders::default(), &bytes);
        assert!(matches!(result, Err(VncError::Protocol(_))));
    }

    fn tight_rect(x: u16, y: u16, w: u16, h: u16, body: &[u8]) -> Vec<u8> {
        rect(x, y, w, h, TIGHT, body)
    }

    #[test]
    fn tight_fill_and_jpeg() {
        let mut framebuffer = Framebuffer::new(16, 8).unwrap();
        let mut decoders = Decoders::default();
        let mut fill = vec![TIGHT_FILL << 4];
        fill.extend_from_slice(&tight_pixel(GREEN));
        let jpeg = hex(JPEG);
        let mut photo = vec![TIGHT_JPEG << 4];
        photo.extend_from_slice(&compact(jpeg.len()));
        photo.extend_from_slice(&jpeg);
        let bytes = message(&[
            tight_rect(0, 0, 8, 8, &fill),
            tight_rect(8, 0, 8, 8, &photo),
        ]);
        decode(&mut framebuffer, &mut decoders, &bytes);
        assert_eq!(pixel(&framebuffer, 7, 7), GREEN);
        let [b, g, r, a] = pixel(&framebuffer, 12, 4);
        assert_eq!(a, OPAQUE);
        for (got, want) in [(r, 200), (g, 100), (b, 50)] {
            assert!(got.abs_diff(want) <= 3, "{r} {g} {b}");
        }
    }

    #[test]
    fn tight_copy_filter_short_and_through_a_kept_stream() {
        let mut framebuffer = Framebuffer::new(4, 2).unwrap();
        let mut decoders = Decoders::default();
        // Three bytes: sent as they are.
        let mut short = vec![0];
        short.extend_from_slice(&tight_pixel(RED));
        decode(
            &mut framebuffer,
            &mut decoders,
            &message(&[tight_rect(0, 0, 1, 1, &short)]),
        );
        assert_eq!(pixel(&framebuffer, 0, 0), RED);

        // Twelve bytes and more go through stream 1, which carries on.
        let mut deflater = Deflater::new();
        for (y, colour) in [(0, BLUE), (1, GREEN)] {
            let data: Vec<u8> = [colour; 4].iter().flat_map(|p| tight_pixel(*p)).collect();
            let chunk = deflater.chunk(&data);
            let mut body = vec![0x01 << 4];
            body.extend_from_slice(&compact(chunk.len()));
            body.extend_from_slice(&chunk);
            decode(
                &mut framebuffer,
                &mut decoders,
                &message(&[tight_rect(0, y, 4, 1, &body)]),
            );
        }
        assert_eq!(pixel(&framebuffer, 3, 0), BLUE);
        assert_eq!(pixel(&framebuffer, 3, 1), GREEN);

        // The reset bit starts stream 1 again.
        let mut deflater = Deflater::new();
        let data: Vec<u8> = [RED; 4].iter().flat_map(|p| tight_pixel(*p)).collect();
        let chunk = deflater.chunk(&data);
        let mut body = vec![(0x01 << 4) | 0x02];
        body.extend_from_slice(&compact(chunk.len()));
        body.extend_from_slice(&chunk);
        decode(
            &mut framebuffer,
            &mut decoders,
            &message(&[tight_rect(0, 0, 4, 1, &body)]),
        );
        assert_eq!(pixel(&framebuffer, 2, 0), RED);
    }

    #[test]
    fn tight_two_colour_palette_packs_a_bit_a_pixel() {
        let mut framebuffer = Framebuffer::new(10, 2).unwrap();
        let mut body = vec![(TIGHT_EXPLICIT_FILTER) << 4, TIGHT_FILTER_PALETTE, 1];
        body.extend_from_slice(&tight_pixel(RED));
        body.extend_from_slice(&tight_pixel(BLUE));
        // Two rows of 10 pixels, two bytes each: under 12, so not compressed.
        body.extend_from_slice(&[0b1000_0000, 0b0100_0000, 0b0000_0000, 0b1100_0000]);
        decode(
            &mut framebuffer,
            &mut Decoders::default(),
            &message(&[tight_rect(0, 0, 10, 2, &body)]),
        );
        assert_eq!(pixel(&framebuffer, 0, 0), BLUE);
        assert_eq!(pixel(&framebuffer, 1, 0), RED);
        assert_eq!(pixel(&framebuffer, 9, 0), BLUE);
        assert_eq!(pixel(&framebuffer, 8, 1), BLUE);
        assert_eq!(pixel(&framebuffer, 7, 1), RED);
    }

    #[test]
    fn tight_byte_palette_and_gradient() {
        let mut framebuffer = Framebuffer::new(3, 2).unwrap();
        let mut decoders = Decoders::default();
        let mut body = vec![TIGHT_EXPLICIT_FILTER << 4, TIGHT_FILTER_PALETTE, 2];
        for colour in [RED, GREEN, BLUE] {
            body.extend_from_slice(&tight_pixel(colour));
        }
        body.extend_from_slice(&[2, 1, 0, 0, 1, 2]);
        decode(
            &mut framebuffer,
            &mut decoders,
            &message(&[tight_rect(0, 0, 3, 2, &body)]),
        );
        assert_eq!(pixel(&framebuffer, 0, 0), BLUE);
        assert_eq!(pixel(&framebuffer, 2, 1), BLUE);
        assert_eq!(pixel(&framebuffer, 1, 1), GREEN);

        // Gradient of a flat grey: the first pixel carries the value, the
        // rest are differences of zero from their prediction.
        let mut data = vec![0u8; 3 * 2 * 3];
        data[..3].copy_from_slice(&[90, 90, 90]);
        let mut deflater = Deflater::new();
        let chunk = deflater.chunk(&data);
        let mut body = vec![TIGHT_EXPLICIT_FILTER << 4, TIGHT_FILTER_GRADIENT];
        body.extend_from_slice(&compact(chunk.len()));
        body.extend_from_slice(&chunk);
        decode(
            &mut framebuffer,
            &mut decoders,
            &message(&[tight_rect(0, 0, 3, 2, &body)]),
        );
        for (x, y) in [(0, 0), (2, 0), (0, 1), (2, 1)] {
            assert_eq!(
                pixel(&framebuffer, x, y),
                [90, 90, 90, OPAQUE],
                "({x}, {y})"
            );
        }
    }

    #[test]
    fn gradient_follows_the_specification() {
        // One row of two pixels: the second predicts from the first.
        let rect = Rect {
            x: 0,
            y: 0,
            w: 2,
            h: 2,
        };
        let data = [10, 20, 30, 5, 5, 5, 1, 1, 1, 0, 0, 0];
        let pixels = gradient(rect, &data);
        assert_eq!(pixels[0], rgb(&[10, 20, 30]));
        assert_eq!(pixels[1], rgb(&[15, 25, 35]));
        // Below the first: above + 1.
        assert_eq!(pixels[2], rgb(&[11, 21, 31]));
        // left 11 + up 15 - up-left 10 = 16.
        assert_eq!(pixels[3], rgb(&[16, 26, 36]));
    }

    #[test]
    fn compact_lengths_of_one_two_and_three_bytes() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for length in [5usize, 300, 100_000] {
            let bytes = compact(length);
            let mut reader = &bytes[..];
            assert_eq!(
                runtime.block_on(compact_length(&mut reader)).unwrap(),
                length
            );
        }
    }

    #[test]
    fn desktop_size_and_layout_resize_the_framebuffer() {
        let mut framebuffer = Framebuffer::new(4, 4).unwrap();
        let mut decoders = Decoders::default();
        let news = decode(
            &mut framebuffer,
            &mut decoders,
            &message(&[rect(0, 0, 8, 6, DESKTOP_SIZE, &[])]),
        );
        assert!(news.resized);
        assert_eq!((framebuffer.width(), framebuffer.height()), (8, 6));

        let mut body = vec![1, 0, 0, 0];
        body.extend_from_slice(&7u32.to_be_bytes());
        for value in [0u16, 0, 10, 5] {
            body.extend_from_slice(&value.to_be_bytes());
        }
        body.extend_from_slice(&0u32.to_be_bytes());
        let news = decode(
            &mut framebuffer,
            &mut decoders,
            &message(&[rect(0, 0, 10, 5, EXTENDED_DESKTOP_SIZE, &body)]),
        );
        assert!(news.resized);
        let layout = news.layout.unwrap();
        assert!(!layout.is_refusal());
        assert_eq!(layout.screens[0].id, 7);
        assert_eq!((framebuffer.width(), framebuffer.height()), (10, 5));

        // This client's request (reason 1) turned down (status 1): no resize.
        let news = decode(
            &mut framebuffer,
            &mut decoders,
            &message(&[rect(1, 1, 10, 5, EXTENDED_DESKTOP_SIZE, &[0, 0, 0, 0])]),
        );
        assert!(!news.resized);
        assert!(news.layout.unwrap().is_refusal());
    }

    #[test]
    fn cursor_shapes_are_skipped_and_last_rect_ends_the_update() {
        let mut framebuffer = Framebuffer::new(2, 1).unwrap();
        // A 9 × 2 cursor: 72 bytes of pixels and a 2-byte-wide mask.
        let cursor = rect(0, 0, 9, 2, CURSOR, &[0u8; 9 * 2 * 4 + 2 * 2]);
        let mut fill = vec![TIGHT_FILL << 4];
        fill.extend_from_slice(&tight_pixel(RED));
        let mut bytes = vec![0, 0xff, 0xff];
        bytes.extend_from_slice(&cursor);
        bytes.extend_from_slice(&tight_rect(0, 0, 2, 1, &fill));
        bytes.extend_from_slice(&rect(0, 0, 0, 0, LAST_RECT, &[]));
        decode(&mut framebuffer, &mut Decoders::default(), &bytes);
        assert_eq!(pixel(&framebuffer, 1, 0), RED);
    }

    #[test]
    fn a_rectangle_outside_the_desktop_is_refused() {
        let mut framebuffer = Framebuffer::new(4, 4).unwrap();
        let bytes = message(&[rect(3, 0, 2, 1, RAW, &[0u8; 8])]);
        let result = try_decode(&mut framebuffer, &mut Decoders::default(), &bytes);
        assert!(matches!(result, Err(VncError::Protocol(_))));

        let bytes = message(&[rect(0, 0, 1, 1, COPY_RECT, &[0, 4, 0, 0])]);
        let result = try_decode(&mut framebuffer, &mut Decoders::default(), &bytes);
        assert!(matches!(result, Err(VncError::Protocol(_))));
    }

    #[test]
    fn an_unasked_encoding_is_an_error() {
        let mut framebuffer = Framebuffer::new(4, 4).unwrap();
        let bytes = message(&[rect(0, 0, 1, 1, 2, &[])]);
        let result = try_decode(&mut framebuffer, &mut Decoders::default(), &bytes);
        assert!(matches!(result, Err(VncError::Protocol(_))));
    }
}
