//! 4-byte big-endian length-prefixed framing for Nearby Connections over TCP/RFCOMM.

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum single frame size accepted from a peer (64 MiB safety ceiling).
pub const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("peer closed connection immediately before sending any bytes (reachability probe)")]
    ConnectionClosedImmediately,
    #[error("unexpected EOF while reading frame")]
    UnexpectedEof,
    #[error("frame size {0} exceeds maximum allowed ({MAX_FRAME_SIZE})")]
    FrameTooLarge(usize),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Read a single 4-byte big-endian length-prefixed frame from `reader`.
pub async fn recv_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    let mut read_hdr = 0usize;
    while read_hdr < 4 {
        let n = reader.read(&mut len_buf[read_hdr..]).await?;
        if n == 0 {
            if read_hdr == 0 {
                return Err(FrameError::ConnectionClosedImmediately);
            }
            return Err(FrameError::UnexpectedEof);
        }
        read_hdr += n;
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge(len));
    }

    let mut payload = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut payload).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                FrameError::UnexpectedEof
            } else {
                FrameError::Io(e)
            }
        })?;
    }
    Ok(payload)
}

/// Write a single 4-byte big-endian length-prefixed frame to `writer`.
pub async fn send_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), FrameError> {
    let len = u32::try_from(payload.len())
        .map_err(|_| FrameError::FrameTooLarge(payload.len()))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}
