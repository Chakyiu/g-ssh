//! From the version banner to the server's description of its desktop.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{auth, decode, VncError};

/// Longest refusal reason or desktop name kept. The rest is read and dropped.
const MAX_TEXT: usize = 4096;

/// Apple uses 128 bytes. Anything far past that is not a real key exchange.
const MAX_APPLE_KEY: usize = 1024;

const SECURITY_INVALID: u32 = 0;
const SECURITY_NONE: u8 = 1;
const SECURITY_VNC: u8 = 2;
const SECURITY_APPLE: u8 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Version {
    V3_3,
    V3_7,
    V3_8,
}

impl Version {
    /// Banners other than 3.7 and 3.8 are 3.3 by the specification. Later
    /// ones (Apple's 3.889, RealVNC's 4.x and 5.x) all speak 3.8.
    fn from_banner(banner: &[u8; 12]) -> Result<Self, VncError> {
        let digits = |range: std::ops::Range<usize>| {
            std::str::from_utf8(&banner[range])
                .ok()
                .and_then(|text| text.parse::<u16>().ok())
        };
        let (Some(major), Some(minor)) = (digits(4..7), digits(8..11)) else {
            return Err(not_vnc());
        };
        if &banner[..4] != b"RFB " || banner[7] != b'.' || banner[11] != b'\n' {
            return Err(not_vnc());
        }
        Ok(match (major, minor) {
            (3, 7) => Self::V3_7,
            (3, minor) if minor >= 8 => Self::V3_8,
            (major, _) if major > 3 => Self::V3_8,
            _ => Self::V3_3,
        })
    }

    fn banner(self) -> &'static [u8; 12] {
        match self {
            Self::V3_3 => b"RFB 003.003\n",
            Self::V3_7 => b"RFB 003.007\n",
            Self::V3_8 => b"RFB 003.008\n",
        }
    }
}

fn not_vnc() -> VncError {
    VncError::Protocol("This is not a VNC server. Check the port.".to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Security {
    None,
    Vnc,
    Apple,
}

impl Security {
    fn code(self) -> u8 {
        match self {
            Self::None => SECURITY_NONE,
            Self::Vnc => SECURITY_VNC,
            Self::Apple => SECURITY_APPLE,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Vnc => "vnc password",
            Self::Apple => "apple account",
        }
    }
}

/// The server's desktop as it first describes it.
pub(super) struct ServerInit {
    pub width: u16,
    pub height: u16,
    pub name: String,
    /// How this session signed in, for the log.
    pub security: &'static str,
}

pub(super) async fn sign_in<R, W>(
    reader: &mut R,
    writer: &mut W,
    username: &str,
    password: &str,
) -> Result<ServerInit, VncError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut banner = [0u8; 12];
    reader.read_exact(&mut banner).await.map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            not_vnc()
        } else {
            error.into()
        }
    })?;
    let version = Version::from_banner(&banner)?;
    writer.write_all(version.banner()).await?;

    let security = if version == Version::V3_3 {
        // The server picks, and only None or a VNC password exist.
        match reader.read_u32().await? {
            SECURITY_INVALID => return Err(refused(reader).await),
            code if code == u32::from(SECURITY_NONE) => Security::None,
            code if code == u32::from(SECURITY_VNC) => {
                if password.is_empty() {
                    return Err(password_needed());
                }
                Security::Vnc
            }
            code => return Err(unsupported(&[u8::try_from(code).unwrap_or(u8::MAX)])),
        }
    } else {
        let count = reader.read_u8().await?;
        if count == 0 {
            return Err(refused(reader).await);
        }
        let mut offered = vec![0u8; usize::from(count)];
        reader.read_exact(&mut offered).await?;
        let chosen = choose(&offered, username, password)?;
        writer.write_all(&[chosen.code()]).await?;
        chosen
    };

    match security {
        Security::None => {}
        Security::Vnc => {
            let mut challenge = [0u8; 16];
            reader.read_exact(&mut challenge).await?;
            writer
                .write_all(&auth::vnc_response(password, &challenge))
                .await?;
        }
        Security::Apple => {
            let mut head = [0u8; 4];
            reader.read_exact(&mut head).await?;
            let generator = [head[0], head[1]];
            let length = usize::from(u16::from_be_bytes([head[2], head[3]]));
            if length == 0 || length > MAX_APPLE_KEY {
                return Err(VncError::Protocol(
                    "The Mac sent a key exchange this client cannot use.".to_string(),
                ));
            }
            let mut prime = vec![0u8; length];
            reader.read_exact(&mut prime).await?;
            let mut server_key = vec![0u8; length];
            reader.read_exact(&mut server_key).await?;
            let reply = auth::apple_response(&generator, &prime, &server_key, username, password)?;
            writer.write_all(&reply).await?;
        }
    }

    // 3.8 always reports the outcome. Earlier versions only after a password.
    if version == Version::V3_8 || security != Security::None {
        let status = reader.read_u32().await?;
        if status != 0 {
            let reason = if version == Version::V3_8 {
                read_text(reader)
                    .await
                    .ok()
                    .filter(|text| !text.trim().is_empty())
            } else {
                None
            };
            return Err(rejected(security, reason));
        }
    }

    // Shared: other viewers stay connected.
    writer.write_all(&[1]).await?;
    let width = reader.read_u16().await?;
    let height = reader.read_u16().await?;
    // The server's own pixel format. This client asks for its own instead.
    decode::skip(reader, 16).await?;
    let name = read_text(reader).await?;
    Ok(ServerInit {
        width,
        height,
        name,
        security: security.label(),
    })
}

/// A user name means the Mac's own sign-in is wanted. Otherwise a VNC
/// password if there is one, then no password at all.
fn choose(offered: &[u8], username: &str, password: &str) -> Result<Security, VncError> {
    let has = |code: u8| offered.contains(&code);
    if has(SECURITY_APPLE) && !username.is_empty() {
        return Ok(Security::Apple);
    }
    if has(SECURITY_VNC) && !password.is_empty() {
        return Ok(Security::Vnc);
    }
    if has(SECURITY_NONE) {
        return Ok(Security::None);
    }
    if has(SECURITY_VNC) {
        return Err(password_needed());
    }
    if has(SECURITY_APPLE) {
        return Err(VncError::Protocol(
            "This Mac signs in with a user name and password. Add the user name to this host."
                .to_string(),
        ));
    }
    Err(unsupported(offered))
}

fn password_needed() -> VncError {
    VncError::Auth("This server asks for a password.".to_string())
}

fn unsupported(offered: &[u8]) -> VncError {
    let names: Vec<String> = offered.iter().map(|&code| security_name(code)).collect();
    VncError::Protocol(format!(
        "The server only offers {}. This client signs in with no password, a VNC password, or a Mac's user name and password.",
        names.join(", ")
    ))
}

fn security_name(code: u8) -> String {
    match code {
        5 | 6 => "RealVNC encryption".to_string(),
        16 => "Tight".to_string(),
        18 => "TLS".to_string(),
        19 => "VeNCrypt".to_string(),
        20 => "SASL".to_string(),
        129..=134 => "RSA-AES".to_string(),
        other => format!("type {other}"),
    }
}

fn rejected(security: Security, reason: Option<String>) -> VncError {
    if let Some(reason) = reason {
        let reason = super::sentence(reason.trim());
        return match security {
            Security::None => VncError::Protocol(reason),
            Security::Vnc | Security::Apple => VncError::Auth(reason),
        };
    }
    match security {
        Security::None => VncError::Protocol("The server refused the connection.".to_string()),
        Security::Vnc => VncError::Auth("The server did not accept the password.".to_string()),
        Security::Apple => {
            VncError::Auth("The Mac did not accept the user name and password.".to_string())
        }
    }
}

/// The server said no before any security was chosen, with its reason.
async fn refused<R: AsyncRead + Unpin>(reader: &mut R) -> VncError {
    match read_text(reader).await {
        Ok(reason) if !reason.trim().is_empty() => {
            VncError::Protocol(super::sentence(reason.trim()))
        }
        _ => VncError::Protocol("The server refused the connection.".to_string()),
    }
}

/// A length, then that many bytes of text.
async fn read_text<R: AsyncRead + Unpin>(reader: &mut R) -> Result<String, VncError> {
    let length = reader.read_u32().await? as usize;
    let kept = length.min(MAX_TEXT);
    let mut bytes = vec![0u8; kept];
    reader.read_exact(&mut bytes).await?;
    decode::skip(reader, length - kept).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn banner(text: &str) -> [u8; 12] {
        text.as_bytes().try_into().unwrap()
    }

    #[test]
    fn versions_fold_into_the_three_that_exist() {
        let version = |text| Version::from_banner(&banner(text)).unwrap();
        assert_eq!(version("RFB 003.003\n"), Version::V3_3);
        assert_eq!(version("RFB 003.006\n"), Version::V3_3);
        assert_eq!(version("RFB 003.007\n"), Version::V3_7);
        assert_eq!(version("RFB 003.008\n"), Version::V3_8);
        assert_eq!(version("RFB 003.889\n"), Version::V3_8);
        assert_eq!(version("RFB 004.001\n"), Version::V3_8);
        assert_eq!(version("RFB 005.000\n"), Version::V3_8);
    }

    #[test]
    fn an_ssh_banner_is_not_vnc() {
        let error = Version::from_banner(&banner("SSH-2.0-Open")).unwrap_err();
        assert!(error.to_string().contains("not a VNC server"));
    }

    #[test]
    fn a_user_name_picks_the_mac_sign_in() {
        assert_eq!(choose(&[30, 2], "ada", "pw").unwrap(), Security::Apple);
        assert_eq!(choose(&[30, 2], "", "pw").unwrap(), Security::Vnc);
        assert_eq!(choose(&[2], "ada", "pw").unwrap(), Security::Vnc);
    }

    #[test]
    fn no_password_falls_back_to_none_or_asks() {
        assert_eq!(choose(&[2, 1], "", "").unwrap(), Security::None);
        assert!(matches!(choose(&[2], "", ""), Err(VncError::Auth(_))));
        assert!(matches!(
            choose(&[30], "", "pw"),
            Err(VncError::Protocol(_))
        ));
    }

    #[test]
    fn unsupported_types_are_named() {
        let error = choose(&[19, 16], "", "pw").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("VeNCrypt"), "{message}");
        assert!(message.contains("Tight"), "{message}");
    }
}
