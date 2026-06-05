//! Length-prefixed message framing for reliable **side-channel** streams.
//!
//! The live screen rides unreliable datagrams (see [`crate::transport`]). Some
//! features want a *reliable, ordered* request/response exchange instead —
//! scrollback history, large clipboard blobs, port forwarding — carried on a
//! QUIC bidirectional stream. A QUIC stream is a reliable byte pipe with no
//! message boundaries, so we frame each message with a 4-byte big-endian length
//! prefix.
//!
//! These helpers are generic over any [`AsyncRead`]/[`AsyncWrite`] (quinn's
//! stream halves implement both), so the framing has no QUIC dependency and is
//! unit-testable over an in-memory duplex. Every read is bounded by an explicit
//! cap so a hostile (but authenticated) peer can't make us allocate unbounded
//! memory from a forged length prefix.

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Default ceiling on a single framed message (8 MiB). Generous for a screen of
/// history rows; small enough to bound memory. Callers may pass a tighter cap.
pub const MAX_MESSAGE_LEN: usize = 8 * 1024 * 1024;

/// Write one length-prefixed message: a 4-byte big-endian length, then the bytes.
/// The caller is responsible for `flush`/`finish` semantics on the stream.
pub async fn write_message<W>(w: &mut W, msg: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let len = u32::try_from(msg.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too large to frame"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(msg).await?;
    Ok(())
}

/// Read one length-prefixed message, rejecting any frame larger than `max`.
///
/// Returns `Ok(None)` on a clean end-of-stream at a message boundary (the peer
/// finished the stream), so a read loop can terminate gracefully. A truncated
/// frame (EOF mid-message) or an over-cap length is an error.
pub async fn read_message<R>(r: &mut R, max: usize) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    // A clean EOF *before* any length bytes means the stream ended at a boundary.
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("framed message length {len} exceeds cap {max}"),
        ));
    }
    let mut buf = vec![0u8; len];
    // EOF *here* is a truncated frame — a real error, not a clean close.
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A written message reads back byte-for-byte through the framing.
    #[tokio::test]
    async fn round_trips_messages() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let msgs: Vec<Vec<u8>> = vec![
            b"hello".to_vec(),
            Vec::new(),                 // empty message is legal
            vec![0xABu8; 50_000],       // multi-chunk
            b"\x00\x01\x02binary".to_vec(),
        ];

        let writer_msgs = msgs.clone();
        let writer = tokio::spawn(async move {
            for m in &writer_msgs {
                write_message(&mut a, m).await.unwrap();
            }
            // Drop `a` to signal end-of-stream at a boundary.
            drop(a);
        });

        let mut got = Vec::new();
        while let Some(m) = read_message(&mut b, MAX_MESSAGE_LEN).await.unwrap() {
            got.push(m);
        }
        writer.await.unwrap();
        assert_eq!(got, msgs);
    }

    /// A length prefix over the cap is rejected without allocating it.
    #[tokio::test]
    async fn rejects_oversize_frame() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // Hand-write a length prefix claiming 1 MiB, with a tiny cap.
        tokio::spawn(async move {
            a.write_all(&(1_000_000u32).to_be_bytes()).await.unwrap();
            let _ = a.write_all(b"partial").await;
        });
        let err = read_message(&mut b, 1024).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// EOF in the middle of a frame is an error, not a clean close.
    #[tokio::test]
    async fn truncated_frame_is_error() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            a.write_all(&(10u32).to_be_bytes()).await.unwrap();
            a.write_all(b"abc").await.unwrap(); // only 3 of 10 bytes
            drop(a);
        });
        let err = read_message(&mut b, MAX_MESSAGE_LEN).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
