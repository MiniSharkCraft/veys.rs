/// Kích thước cố định của Frame Header trong HTTP/2 (9 bytes)
#[allow(dead_code)]
pub const FRAME_HEADER_SIZE: usize = 9;
/// Default Max Frame Size mặc định theo RFC 9113 (16,384 bytes)
#[allow(dead_code)]
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;
/// Hard limit Max Frame Size tối đa cho phép (16,777,215 bytes = 2^24 - 1)
#[allow(dead_code)]
pub const MAX_ALLOWED_FRAME_SIZE: u32 = 16_777_215;

/// Mã lỗi HTTP/2 chuẩn (RFC 9113 Section 7)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Http2ErrorCode {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

impl Http2ErrorCode {
    pub fn from_u32(val: u32) -> Self {
        match val {
            0x0 => Self::NoError,
            0x1 => Self::ProtocolError,
            0x2 => Self::InternalError,
            0x3 => Self::FlowControlError,
            0x4 => Self::SettingsTimeout,
            0x5 => Self::StreamClosed,
            0x6 => Self::FrameSizeError,
            0x7 => Self::RefusedStream,
            0x8 => Self::Cancel,
            0x9 => Self::CompressionError,
            0xa => Self::ConnectError,
            0xb => Self::EnhanceYourCalm,
            0xc => Self::InadequateSecurity,
            0xd => Self::Http11Required,
            _ => Self::ProtocolError,
        }
    }
}

/// Các loại Frame HTTP/2 (RFC 9113 Section 6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
    Unknown(u8),
}

impl From<u8> for FrameType {
    fn from(val: u8) -> Self {
        match val {
            0x0 => Self::Data,
            0x1 => Self::Headers,
            0x2 => Self::Priority,
            0x3 => Self::RstStream,
            0x4 => Self::Settings,
            0x5 => Self::PushPromise,
            0x6 => Self::Ping,
            0x7 => Self::GoAway,
            0x8 => Self::WindowUpdate,
            0x9 => Self::Continuation,
            other => Self::Unknown(other),
        }
    }
}

impl From<FrameType> for u8 {
    fn from(ft: FrameType) -> u8 {
        match ft {
            FrameType::Data => 0x0,
            FrameType::Headers => 0x1,
            FrameType::Priority => 0x2,
            FrameType::RstStream => 0x3,
            FrameType::Settings => 0x4,
            FrameType::PushPromise => 0x5,
            FrameType::Ping => 0x6,
            FrameType::GoAway => 0x7,
            FrameType::WindowUpdate => 0x8,
            FrameType::Continuation => 0x9,
            FrameType::Unknown(val) => val,
        }
    }
}

/// Flags cho các loại Frame
pub mod flags {
    pub const END_STREAM: u8 = 0x1;
    pub const ACK: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

/// HTTP/2 Frame Header (9 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub length: u32,
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: u32,
}

impl FrameHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, Http2ErrorCode> {
        if buf.len() < FRAME_HEADER_SIZE {
            return Err(Http2ErrorCode::FrameSizeError);
        }

        let length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        let frame_type = FrameType::from(buf[3]);
        let flags = buf[4];

        let raw_stream_id = ((buf[5] as u32) << 24)
            | ((buf[6] as u32) << 16)
            | ((buf[7] as u32) << 8)
            | (buf[8] as u32);
        // Bit cao nhất (reserved bit) bị mask về 0 theo RFC 9113
        let stream_id = raw_stream_id & 0x7FFF_FFFF;

        Ok(Self {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }

    pub fn encode(&self) -> [u8; FRAME_HEADER_SIZE] {
        let mut buf = [0u8; FRAME_HEADER_SIZE];
        buf[0] = ((self.length >> 16) & 0xFF) as u8;
        buf[1] = ((self.length >> 8) & 0xFF) as u8;
        buf[2] = (self.length & 0xFF) as u8;
        buf[3] = u8::from(self.frame_type);
        buf[4] = self.flags;

        let sid = self.stream_id & 0x7FFF_FFFF;
        buf[5] = ((sid >> 24) & 0xFF) as u8;
        buf[6] = ((sid >> 16) & 0xFF) as u8;
        buf[7] = ((sid >> 8) & 0xFF) as u8;
        buf[8] = (sid & 0xFF) as u8;

        buf
    }
}

/// Các ID cấu hình SETTINGS (RFC 9113 Section 6.5.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SettingId {
    HeaderTableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6,
    Unknown(u16),
}

impl From<u16> for SettingId {
    fn from(val: u16) -> Self {
        match val {
            0x1 => Self::HeaderTableSize,
            0x2 => Self::EnablePush,
            0x3 => Self::MaxConcurrentStreams,
            0x4 => Self::InitialWindowSize,
            0x5 => Self::MaxFrameSize,
            0x6 => Self::MaxHeaderListSize,
            other => Self::Unknown(other),
        }
    }
}

impl From<SettingId> for u16 {
    fn from(id: SettingId) -> u16 {
        match id {
            SettingId::HeaderTableSize => 0x1,
            SettingId::EnablePush => 0x2,
            SettingId::MaxConcurrentStreams => 0x3,
            SettingId::InitialWindowSize => 0x4,
            SettingId::MaxFrameSize => 0x5,
            SettingId::MaxHeaderListSize => 0x6,
            SettingId::Unknown(val) => val,
        }
    }
}

/// Enum đại diện cho Payload đã parse của Frame
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum FramePayload {
    Data {
        data: Vec<u8>,
        end_stream: bool,
    },
    Headers {
        header_block: Vec<u8>,
        end_stream: bool,
        end_headers: bool,
    },
    Priority {
        stream_dependency: u32,
        weight: u8,
        exclusive: bool,
    },
    RstStream {
        error_code: Http2ErrorCode,
    },
    Settings {
        settings: Vec<(SettingId, u32)>,
        ack: bool,
    },
    PushPromise {
        promised_stream_id: u32,
        header_block: Vec<u8>,
    },
    Ping {
        opaque_data: [u8; 8],
        ack: bool,
    },
    GoAway {
        last_stream_id: u32,
        error_code: Http2ErrorCode,
        debug_data: Vec<u8>,
    },
    WindowUpdate {
        window_size_increment: u32,
    },
    Continuation {
        header_block: Vec<u8>,
        end_headers: bool,
    },
    Unknown {
        payload: Vec<u8>,
    },
}

/// Struct hoàn chỉnh chứa Header & Payload của một Frame
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: FramePayload,
}

impl Frame {
    pub fn parse(header: FrameHeader, payload_bytes: &[u8]) -> Result<Self, Http2ErrorCode> {
        if payload_bytes.len() != header.length as usize {
            return Err(Http2ErrorCode::FrameSizeError);
        }

        let payload = match header.frame_type {
            FrameType::Data => {
                if header.stream_id == 0 {
                    return Err(Http2ErrorCode::ProtocolError);
                }

                let mut data_start = 0;
                let mut data_end = payload_bytes.len();

                if (header.flags & flags::PADDED) != 0 {
                    if payload_bytes.is_empty() {
                        return Err(Http2ErrorCode::FrameSizeError);
                    }
                    let pad_len = payload_bytes[0] as usize;
                    data_start = 1;
                    if data_start + pad_len > payload_bytes.len() {
                        return Err(Http2ErrorCode::ProtocolError);
                    }
                    data_end = payload_bytes.len() - pad_len;
                }

                let data = payload_bytes[data_start..data_end].to_vec();
                let end_stream = (header.flags & flags::END_STREAM) != 0;

                FramePayload::Data { data, end_stream }
            }

            FrameType::Headers => {
                if header.stream_id == 0 {
                    return Err(Http2ErrorCode::ProtocolError);
                }

                let mut offset = 0;
                let mut pad_len = 0;

                if (header.flags & flags::PADDED) != 0 {
                    if payload_bytes.is_empty() {
                        return Err(Http2ErrorCode::FrameSizeError);
                    }
                    pad_len = payload_bytes[0] as usize;
                    offset += 1;
                }

                if (header.flags & flags::PRIORITY) != 0 {
                    if payload_bytes.len() < offset + 5 {
                        return Err(Http2ErrorCode::FrameSizeError);
                    }
                    offset += 5; // Bỏ qua 4 bytes Stream Dep + 1 byte Weight
                }

                if offset + pad_len > payload_bytes.len() {
                    return Err(Http2ErrorCode::ProtocolError);
                }

                let header_block = payload_bytes[offset..(payload_bytes.len() - pad_len)].to_vec();
                let end_stream = (header.flags & flags::END_STREAM) != 0;
                let end_headers = (header.flags & flags::END_HEADERS) != 0;

                FramePayload::Headers {
                    header_block,
                    end_stream,
                    end_headers,
                }
            }

            FrameType::Priority => {
                if header.stream_id == 0 {
                    return Err(Http2ErrorCode::ProtocolError);
                }
                if payload_bytes.len() != 5 {
                    return Err(Http2ErrorCode::FrameSizeError);
                }

                let raw_dep = ((payload_bytes[0] as u32) << 24)
                    | ((payload_bytes[1] as u32) << 16)
                    | ((payload_bytes[2] as u32) << 8)
                    | (payload_bytes[3] as u32);

                let exclusive = (raw_dep & 0x8000_0000) != 0;
                let stream_dependency = raw_dep & 0x7FFF_FFFF;
                let weight = payload_bytes[4];

                FramePayload::Priority {
                    stream_dependency,
                    weight,
                    exclusive,
                }
            }

            FrameType::RstStream => {
                if header.stream_id == 0 {
                    return Err(Http2ErrorCode::ProtocolError);
                }
                if payload_bytes.len() != 4 {
                    return Err(Http2ErrorCode::FrameSizeError);
                }

                let code_raw = ((payload_bytes[0] as u32) << 24)
                    | ((payload_bytes[1] as u32) << 16)
                    | ((payload_bytes[2] as u32) << 8)
                    | (payload_bytes[3] as u32);

                FramePayload::RstStream {
                    error_code: Http2ErrorCode::from_u32(code_raw),
                }
            }

            FrameType::Settings => {
                if header.stream_id != 0 {
                    return Err(Http2ErrorCode::ProtocolError);
                }
                let ack = (header.flags & flags::ACK) != 0;
                if ack && !payload_bytes.is_empty() {
                    return Err(Http2ErrorCode::FrameSizeError);
                }
                if !payload_bytes.len().is_multiple_of(6) {
                    return Err(Http2ErrorCode::FrameSizeError);
                }

                let mut settings = Vec::new();
                for chunk in payload_bytes.chunks_exact(6) {
                    let id_raw = ((chunk[0] as u16) << 8) | (chunk[1] as u16);
                    let val_raw = ((chunk[2] as u32) << 24)
                        | ((chunk[3] as u32) << 16)
                        | ((chunk[4] as u32) << 8)
                        | (chunk[5] as u32);

                    settings.push((SettingId::from(id_raw), val_raw));
                }

                FramePayload::Settings { settings, ack }
            }

            FrameType::PushPromise => {
                // VeySRS không hỗ trợ Server Push -> PUSH_PROMISE từ client là Protocol Error
                return Err(Http2ErrorCode::ProtocolError);
            }

            FrameType::Ping => {
                if header.stream_id != 0 {
                    return Err(Http2ErrorCode::ProtocolError);
                }
                if payload_bytes.len() != 8 {
                    return Err(Http2ErrorCode::FrameSizeError);
                }
                let ack = (header.flags & flags::ACK) != 0;
                let mut opaque_data = [0u8; 8];
                opaque_data.copy_from_slice(payload_bytes);

                FramePayload::Ping { opaque_data, ack }
            }

            FrameType::GoAway => {
                if header.stream_id != 0 {
                    return Err(Http2ErrorCode::ProtocolError);
                }
                if payload_bytes.len() < 8 {
                    return Err(Http2ErrorCode::FrameSizeError);
                }

                let raw_last_sid = ((payload_bytes[0] as u32) << 24)
                    | ((payload_bytes[1] as u32) << 16)
                    | ((payload_bytes[2] as u32) << 8)
                    | (payload_bytes[3] as u32);
                let last_stream_id = raw_last_sid & 0x7FFF_FFFF;

                let err_raw = ((payload_bytes[4] as u32) << 24)
                    | ((payload_bytes[5] as u32) << 16)
                    | ((payload_bytes[6] as u32) << 8)
                    | (payload_bytes[7] as u32);

                let debug_data = payload_bytes[8..].to_vec();

                FramePayload::GoAway {
                    last_stream_id,
                    error_code: Http2ErrorCode::from_u32(err_raw),
                    debug_data,
                }
            }

            FrameType::WindowUpdate => {
                if payload_bytes.len() != 4 {
                    return Err(Http2ErrorCode::FrameSizeError);
                }

                let raw_inc = ((payload_bytes[0] as u32) << 24)
                    | ((payload_bytes[1] as u32) << 16)
                    | ((payload_bytes[2] as u32) << 8)
                    | (payload_bytes[3] as u32);

                let window_size_increment = raw_inc & 0x7FFF_FFFF;
                if window_size_increment == 0 {
                    return Err(Http2ErrorCode::ProtocolError);
                }

                FramePayload::WindowUpdate {
                    window_size_increment,
                }
            }

            FrameType::Continuation => {
                if header.stream_id == 0 {
                    return Err(Http2ErrorCode::ProtocolError);
                }
                let end_headers = (header.flags & flags::END_HEADERS) != 0;
                FramePayload::Continuation {
                    header_block: payload_bytes.to_vec(),
                    end_headers,
                }
            }

            FrameType::Unknown(_) => FramePayload::Unknown {
                payload: payload_bytes.to_vec(),
            },
        };

        Ok(Self { header, payload })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();

        match &self.payload {
            FramePayload::Data { data, .. } => {
                body.extend_from_slice(data);
            }
            FramePayload::Headers { header_block, .. } => {
                body.extend_from_slice(header_block);
            }
            FramePayload::Priority {
                stream_dependency,
                weight,
                exclusive,
            } => {
                let dep = if *exclusive {
                    stream_dependency | 0x8000_0000
                } else {
                    stream_dependency & 0x7FFF_FFFF
                };
                body.extend_from_slice(&dep.to_be_bytes());
                body.push(*weight);
            }
            FramePayload::RstStream { error_code } => {
                body.extend_from_slice(&(*error_code as u32).to_be_bytes());
            }
            FramePayload::Settings { settings, .. } => {
                for (id, val) in settings {
                    let id_u16: u16 = (*id).into();
                    body.extend_from_slice(&id_u16.to_be_bytes());
                    body.extend_from_slice(&val.to_be_bytes());
                }
            }
            FramePayload::PushPromise {
                promised_stream_id,
                header_block,
            } => {
                let sid = promised_stream_id & 0x7FFF_FFFF;
                body.extend_from_slice(&sid.to_be_bytes());
                body.extend_from_slice(header_block);
            }
            FramePayload::Ping { opaque_data, .. } => {
                body.extend_from_slice(opaque_data);
            }
            FramePayload::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            } => {
                let sid = last_stream_id & 0x7FFF_FFFF;
                body.extend_from_slice(&sid.to_be_bytes());
                body.extend_from_slice(&(*error_code as u32).to_be_bytes());
                body.extend_from_slice(debug_data);
            }
            FramePayload::WindowUpdate {
                window_size_increment,
            } => {
                let inc = window_size_increment & 0x7FFF_FFFF;
                body.extend_from_slice(&inc.to_be_bytes());
            }
            FramePayload::Continuation { header_block, .. } => {
                body.extend_from_slice(header_block);
            }
            FramePayload::Unknown { payload } => {
                body.extend_from_slice(payload);
            }
        }

        let mut header = self.header.clone();
        header.length = body.len() as u32;

        let mut out = Vec::with_capacity(FRAME_HEADER_SIZE + body.len());
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(&body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_header_parse_and_encode() {
        let header = FrameHeader {
            length: 1234,
            frame_type: FrameType::Headers,
            flags: flags::END_STREAM | flags::END_HEADERS,
            stream_id: 15,
        };

        let encoded = header.encode();
        assert_eq!(encoded.len(), 9);

        let parsed = FrameHeader::parse(&encoded).unwrap();
        assert_eq!(parsed.length, 1234);
        assert_eq!(parsed.frame_type, FrameType::Headers);
        assert_eq!(parsed.flags, flags::END_STREAM | flags::END_HEADERS);
        assert_eq!(parsed.stream_id, 15);
    }

    #[test]
    fn test_settings_frame_parse_and_encode() {
        let frame = Frame {
            header: FrameHeader {
                length: 12,
                frame_type: FrameType::Settings,
                flags: 0,
                stream_id: 0,
            },
            payload: FramePayload::Settings {
                settings: vec![
                    (SettingId::MaxConcurrentStreams, 100),
                    (SettingId::InitialWindowSize, 65535),
                ],
                ack: false,
            },
        };

        let raw = frame.encode();
        let parsed_header = FrameHeader::parse(&raw[..9]).unwrap();
        let parsed_frame = Frame::parse(parsed_header, &raw[9..]).unwrap();

        assert_eq!(parsed_frame.header.stream_id, 0);
        if let FramePayload::Settings { settings, ack } = parsed_frame.payload {
            assert!(!ack);
            assert_eq!(settings.len(), 2);
            assert_eq!(settings[0], (SettingId::MaxConcurrentStreams, 100));
            assert_eq!(settings[1], (SettingId::InitialWindowSize, 65535));
        } else {
            panic!("Expected Settings payload");
        }
    }

    #[test]
    fn test_ping_frame_ack() {
        let ping_frame = Frame {
            header: FrameHeader {
                length: 8,
                frame_type: FrameType::Ping,
                flags: flags::ACK,
                stream_id: 0,
            },
            payload: FramePayload::Ping {
                opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
                ack: true,
            },
        };

        let raw = ping_frame.encode();
        let parsed_header = FrameHeader::parse(&raw[..9]).unwrap();
        let parsed_frame = Frame::parse(parsed_header, &raw[9..]).unwrap();

        if let FramePayload::Ping { opaque_data, ack } = parsed_frame.payload {
            assert!(ack);
            assert_eq!(opaque_data, [1, 2, 3, 4, 5, 6, 7, 8]);
        } else {
            panic!("Expected Ping payload");
        }
    }

    #[test]
    fn test_invalid_stream_id_for_settings() {
        let header = FrameHeader {
            length: 0,
            frame_type: FrameType::Settings,
            flags: 0,
            stream_id: 1, // Must be 0
        };
        let res = Frame::parse(header, &[]);
        assert_eq!(res, Err(Http2ErrorCode::ProtocolError));
    }
}
