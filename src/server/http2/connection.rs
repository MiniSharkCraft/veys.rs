use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use crate::config::{ConfigManager, ServerConfig};
use crate::router::RequestHandler;
use crate::server::http::{BodySource, HttpRequest, HttpResponse, Method};
use crate::server::http2::flow::{FlowControl, DEFAULT_INITIAL_WINDOW_SIZE};
use crate::server::http2::frame::{
    flags, Frame, FrameHeader, FramePayload, FrameType, Http2ErrorCode, SettingId,
    FRAME_HEADER_SIZE,
};
use crate::server::http2::hpack::{HpackDecoder, HpackEncoder};
use crate::server::http2::stream::{Stream, StreamState};

/// Chuỗi Magic Client Preface tiêu chuẩn (24 bytes) theo RFC 9113 Section 3.4
pub const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// HTTP/2 Connection Driver chính xử lý một kết nối HTTP/2 qua TcpStream
pub struct Http2Connection<'a> {
    config: &'a ServerConfig,
    config_manager: &'a ConfigManager,
    hpack_decoder: HpackDecoder,
    hpack_encoder: HpackEncoder,
    flow_control: FlowControl,
    max_frame_size: u32,
    max_concurrent_streams: usize,
    active_streams: HashMap<u32, Stream>,
    last_stream_id: u32,
}

impl<'a> Http2Connection<'a> {
    pub fn new(config: &'a ServerConfig, config_manager: &'a ConfigManager) -> Self {
        Self {
            config,
            config_manager,
            hpack_decoder: HpackDecoder::new(4096, config.http2_max_header_block_size),
            hpack_encoder: HpackEncoder::new(4096),
            flow_control: FlowControl::new(config.http2_initial_window_size),
            max_frame_size: config.http2_max_frame_size,
            max_concurrent_streams: config.http2_max_concurrent_streams,
            active_streams: HashMap::new(),
            last_stream_id: 0,
        }
    }

    /// Khởi tạo và xử lý vòng đời kết nối HTTP/2
    pub fn handle_connection(
        &mut self,
        stream: &mut TcpStream,
        initial_buffered: &[u8],
        peer_addr: Option<SocketAddr>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(initial_buffered);

        // 1. Kiểm tra Client Connection Preface (24 bytes)
        while buffer.len() < CLIENT_PREFACE.len() {
            let mut temp = [0u8; 1024];
            let n = stream.read(&mut temp)?;
            if n == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&temp[..n]);
        }

        if &buffer[..CLIENT_PREFACE.len()] != CLIENT_PREFACE {
            self.send_goaway(stream, 0, Http2ErrorCode::ProtocolError)?;
            return Ok(());
        }
        buffer.drain(..CLIENT_PREFACE.len());

        // 2. Gửi Server Initial SETTINGS Frame
        self.send_server_settings(stream)?;

        let handler = RequestHandler::new(self.config, self.config_manager);

        // 3. Main Loop đọc và xử lý Frame
        loop {
            while buffer.len() < FRAME_HEADER_SIZE {
                let mut temp = [0u8; 4096];
                match stream.read(&mut temp) {
                    Ok(0) => return Ok(()),
                    Ok(n) => buffer.extend_from_slice(&temp[..n]),
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        return Ok(());
                    }
                    Err(e) => return Err(Box::new(e)),
                }
            }

            let header = match FrameHeader::parse(&buffer[..FRAME_HEADER_SIZE]) {
                Ok(h) => h,
                Err(code) => {
                    self.send_goaway(stream, self.last_stream_id, code)?;
                    return Ok(());
                }
            };

            if header.length > self.max_frame_size {
                self.send_goaway(stream, self.last_stream_id, Http2ErrorCode::FrameSizeError)?;
                return Ok(());
            }

            let total_frame_len = FRAME_HEADER_SIZE + header.length as usize;
            while buffer.len() < total_frame_len {
                let mut temp = [0u8; 4096];
                match stream.read(&mut temp) {
                    Ok(0) => return Ok(()),
                    Ok(n) => buffer.extend_from_slice(&temp[..n]),
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        return Ok(());
                    }
                    Err(e) => return Err(Box::new(e)),
                }
            }

            let payload_bytes = &buffer[FRAME_HEADER_SIZE..total_frame_len];
            let frame = match Frame::parse(header, payload_bytes) {
                Ok(f) => f,
                Err(code) => {
                    self.send_goaway(stream, self.last_stream_id, code)?;
                    return Ok(());
                }
            };

            buffer.drain(..total_frame_len);

            if let Err(err) = self.process_frame(stream, &frame, &handler, peer_addr) {
                let _ = self.send_goaway(stream, self.last_stream_id, err);
                break;
            }
        }
        Ok(())
    }

    fn send_server_settings(&mut self, stream: &mut TcpStream) -> Result<(), std::io::Error> {
        let settings_frame = Frame {
            header: FrameHeader {
                length: 18,
                frame_type: FrameType::Settings,
                flags: 0,
                stream_id: 0,
            },
            payload: FramePayload::Settings {
                settings: vec![
                    (
                        SettingId::MaxConcurrentStreams,
                        self.max_concurrent_streams as u32,
                    ),
                    (SettingId::InitialWindowSize, DEFAULT_INITIAL_WINDOW_SIZE),
                    (SettingId::MaxFrameSize, self.max_frame_size),
                ],
                ack: false,
            },
        };

        stream.write_all(&settings_frame.encode())?;
        stream.flush()?;
        Ok(())
    }

    fn process_frame(
        &mut self,
        stream: &mut TcpStream,
        frame: &Frame,
        handler: &RequestHandler,
        peer_addr: Option<SocketAddr>,
    ) -> Result<(), Http2ErrorCode> {
        let sid = frame.header.stream_id;

        match &frame.payload {
            FramePayload::Settings { settings, ack } => {
                if *ack {
                    return Ok(());
                }

                for (id, val) in settings {
                    match id {
                        SettingId::MaxFrameSize => {
                            if *val < 16_384 || *val > 16_777_215 {
                                return Err(Http2ErrorCode::FrameSizeError);
                            }
                            self.max_frame_size = *val;
                        }
                        SettingId::InitialWindowSize => {
                            self.flow_control.update_initial_window_size(*val)?;
                        }
                        SettingId::MaxConcurrentStreams => {
                            self.max_concurrent_streams = *val as usize;
                        }
                        _ => {}
                    }
                }

                // Gửi SETTINGS ACK
                let ack_frame = Frame {
                    header: FrameHeader {
                        length: 0,
                        frame_type: FrameType::Settings,
                        flags: flags::ACK,
                        stream_id: 0,
                    },
                    payload: FramePayload::Settings {
                        settings: Vec::new(),
                        ack: true,
                    },
                };
                let _ = stream.write_all(&ack_frame.encode());
                let _ = stream.flush();
            }

            FramePayload::Ping { opaque_data, ack } => {
                if !ack {
                    let ping_ack = Frame {
                        header: FrameHeader {
                            length: 8,
                            frame_type: FrameType::Ping,
                            flags: flags::ACK,
                            stream_id: 0,
                        },
                        payload: FramePayload::Ping {
                            opaque_data: *opaque_data,
                            ack: true,
                        },
                    };
                    let _ = stream.write_all(&ping_ack.encode());
                    let _ = stream.flush();
                }
            }

            FramePayload::Headers {
                header_block,
                end_stream,
                end_headers,
            } => {
                if sid == 0 || !Stream::is_client_initiated(sid) {
                    return Err(Http2ErrorCode::ProtocolError);
                }

                if sid <= self.last_stream_id {
                    return Err(Http2ErrorCode::ProtocolError);
                }
                self.last_stream_id = sid;

                if self.active_streams.len() >= self.max_concurrent_streams {
                    return Err(Http2ErrorCode::RefusedStream);
                }

                let mut st = Stream::new(sid, self.flow_control.initial_stream_window_size())?;
                st.transition_to(StreamState::Open)?;

                let decoded_headers = self.hpack_decoder.decode_header_block(header_block)?;
                st.append_request_headers(decoded_headers, *end_headers);

                if *end_stream {
                    st.received_end_stream = true;
                    let _ = st.transition_to(StreamState::HalfClosedRemote);
                    self.dispatch_h2_request(stream, &st, handler, peer_addr)?;
                } else {
                    self.active_streams.insert(sid, st);
                }
            }

            FramePayload::Data { data, end_stream } => {
                if let Some(mut st) = self.active_streams.remove(&sid) {
                    st.append_request_data(data, *end_stream)?;
                    if *end_stream {
                        self.dispatch_h2_request(stream, &st, handler, peer_addr)?;
                    } else {
                        self.active_streams.insert(sid, st);
                    }
                } else {
                    return Err(Http2ErrorCode::StreamClosed);
                }
            }

            FramePayload::WindowUpdate {
                window_size_increment,
            } => {
                if sid == 0 {
                    self.flow_control
                        .connection_window_mut()
                        .update(*window_size_increment)?;
                } else if let Some(st) = self.active_streams.get_mut(&sid) {
                    st.window.update(*window_size_increment)?;
                }
            }

            FramePayload::RstStream { .. } => {
                self.active_streams.remove(&sid);
            }

            FramePayload::GoAway { .. } => {
                return Err(Http2ErrorCode::NoError);
            }

            _ => {}
        }

        Ok(())
    }

    fn dispatch_h2_request(
        &mut self,
        stream: &mut TcpStream,
        h2_stream: &Stream,
        handler: &RequestHandler,
        peer_addr: Option<SocketAddr>,
    ) -> Result<(), Http2ErrorCode> {
        let mut method = Method::Get;
        let mut uri = "/".to_string();
        let mut headers = Vec::new();

        for (name, val) in &h2_stream.request_headers {
            if name == ":method" {
                method = Method::from(val.as_str());
            } else if name == ":path" {
                uri = val.clone();
            } else if !name.starts_with(':') {
                headers.push((name.clone(), val.clone()));
            }
        }

        let req = HttpRequest {
            method,
            uri,
            version: "HTTP/2.0".to_string(),
            headers,
            body: h2_stream.request_body.clone(),
        };

        // Execution RequestHandler độc lập với Giao thức
        let resp = handler.handle_request(&req, peer_addr);

        // Convert HttpResponse -> HTTP/2 HEADERS & DATA frames
        self.send_h2_response(stream, h2_stream.id, &resp)?;
        Ok(())
    }

    fn send_h2_response(
        &mut self,
        stream: &mut TcpStream,
        stream_id: u32,
        resp: &HttpResponse,
    ) -> Result<(), Http2ErrorCode> {
        let status_str = resp.status.code().to_string();
        let mut h2_headers = vec![(":status", status_str.as_str())];

        for (k, v) in &resp.headers {
            h2_headers.push((k.as_str(), v.as_str()));
        }

        let encoded_headers = self.hpack_encoder.encode_headers(&h2_headers);

        let has_body = match &resp.body_source {
            BodySource::Bytes(b) => !b.is_empty(),
            BodySource::File(..) | BodySource::FileRange(..) => true,
        };

        let headers_flags = if has_body {
            flags::END_HEADERS
        } else {
            flags::END_HEADERS | flags::END_STREAM
        };

        let headers_frame = Frame {
            header: FrameHeader {
                length: encoded_headers.len() as u32,
                frame_type: FrameType::Headers,
                flags: headers_flags,
                stream_id,
            },
            payload: FramePayload::Headers {
                header_block: encoded_headers,
                end_stream: !has_body,
                end_headers: true,
            },
        };

        if stream.write_all(&headers_frame.encode()).is_err() {
            return Err(Http2ErrorCode::InternalError);
        }

        if has_body {
            match &resp.body_source {
                BodySource::Bytes(bytes) => {
                    let data_frame = Frame {
                        header: FrameHeader {
                            length: bytes.len() as u32,
                            frame_type: FrameType::Data,
                            flags: flags::END_STREAM,
                            stream_id,
                        },
                        payload: FramePayload::Data {
                            data: bytes.clone(),
                            end_stream: true,
                        },
                    };
                    let _ = stream.write_all(&data_frame.encode());
                }
                BodySource::File(path, _size) => {
                    if let Ok(mut file) = std::fs::File::open(path) {
                        let mut buffer = [0u8; 16384];
                        loop {
                            let n = match file.read(&mut buffer) {
                                Ok(0) => break,
                                Ok(n) => n,
                                Err(_) => break,
                            };
                            let is_last = n < buffer.len();
                            let data_frame = Frame {
                                header: FrameHeader {
                                    length: n as u32,
                                    frame_type: FrameType::Data,
                                    flags: if is_last { flags::END_STREAM } else { 0 },
                                    stream_id,
                                },
                                payload: FramePayload::Data {
                                    data: buffer[..n].to_vec(),
                                    end_stream: is_last,
                                },
                            };
                            let _ = stream.write_all(&data_frame.encode());
                            if is_last {
                                break;
                            }
                        }
                    }
                }
                BodySource::FileRange(path, offset, length) => {
                    if let Ok(mut f) = std::fs::File::open(path) {
                        use std::io::Seek;
                        let _ = f.seek(std::io::SeekFrom::Start(*offset));
                        let mut remaining = *length;
                        let mut buffer = [0u8; 16384];

                        while remaining > 0 {
                            let to_read = (remaining as usize).min(buffer.len());
                            let n = match f.read(&mut buffer[..to_read]) {
                                Ok(0) => break,
                                Ok(n) => n,
                                Err(_) => break,
                            };
                            remaining -= n as u64;
                            let is_last = remaining == 0;

                            let data_frame = Frame {
                                header: FrameHeader {
                                    length: n as u32,
                                    frame_type: FrameType::Data,
                                    flags: if is_last { flags::END_STREAM } else { 0 },
                                    stream_id,
                                },
                                payload: FramePayload::Data {
                                    data: buffer[..n].to_vec(),
                                    end_stream: is_last,
                                },
                            };
                            let _ = stream.write_all(&data_frame.encode());
                        }
                    }
                }
            }
        }

        let _ = stream.flush();
        Ok(())
    }

    fn send_goaway(
        &mut self,
        stream: &mut TcpStream,
        last_stream_id: u32,
        error_code: Http2ErrorCode,
    ) -> Result<(), std::io::Error> {
        let goaway = Frame {
            header: FrameHeader {
                length: 8,
                frame_type: FrameType::GoAway,
                flags: 0,
                stream_id: 0,
            },
            payload: FramePayload::GoAway {
                last_stream_id,
                error_code,
                debug_data: Vec::new(),
            },
        };
        stream.write_all(&goaway.encode())?;
        stream.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_preface_constant() {
        assert_eq!(CLIENT_PREFACE.len(), 24);
        assert_eq!(CLIENT_PREFACE, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    }
}
