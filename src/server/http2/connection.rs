use flate2::read::GzEncoder;
use flate2::Compression;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;

use crate::config::{ConfigManager, ServerConfig};
use crate::router::RequestHandler;
use crate::server::http::{BodySource, HttpRequest, HttpResponse, Method};
use crate::server::http2::flow::{FlowControl, Window};
use crate::server::http2::frame::{
    flags, Frame, FrameHeader, FramePayload, FrameType, Http2ErrorCode, SettingId,
    DEFAULT_MAX_FRAME_SIZE, FRAME_HEADER_SIZE,
};
use crate::server::http2::hpack::{HpackDecoder, HpackEncoder};
use crate::server::http2::stream::{Stream, StreamState};

/// Chuỗi Magic Client Preface tiêu chuẩn (24 bytes) theo RFC 9113 Section 3.4
pub const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub trait Http2Io: Read + Write {}
impl<T: Read + Write> Http2Io for T {}

struct PendingResponse {
    stream_id: u32,
    body: PendingBody,
}

enum PendingHeaderSource {
    Proxy(crate::server::proxy::H2ProxyPending),
    FastCgi(crate::server::fastcgi::H2FastCgiPending),
}

struct PendingHeaderResponse {
    stream_id: u32,
    source: PendingHeaderSource,
    compress: bool,
    compression_level: u32,
}

enum BodyRead {
    Data(Vec<u8>, bool),
    Pending,
    Done,
}

enum PendingBody {
    Bytes {
        data: Vec<u8>,
        offset: usize,
    },
    File {
        file: File,
        remaining: u64,
    },
    Reader {
        reader: Box<dyn Read + Send>,
        remaining: Option<u64>,
    },
}

impl PendingBody {
    fn read_chunk(&mut self, max: usize) -> Result<BodyRead, Http2ErrorCode> {
        match self {
            Self::Bytes { data, offset } => {
                let end = (*offset + max).min(data.len());
                let chunk = data[*offset..end].to_vec();
                *offset = end;
                Ok(BodyRead::Data(chunk, *offset == data.len()))
            }
            Self::File { file, remaining } => {
                let mut buf = vec![0u8; (*remaining as usize).min(max)];
                let n = file
                    .read(&mut buf)
                    .map_err(|_| Http2ErrorCode::InternalError)?;
                if n == 0 {
                    return Err(Http2ErrorCode::InternalError);
                }
                buf.truncate(n);
                *remaining -= n as u64;
                Ok(BodyRead::Data(buf, *remaining == 0))
            }
            Self::Reader { reader, remaining } => {
                let want = remaining
                    .map(|left| left.min(max as u64) as usize)
                    .unwrap_or(max);
                if want == 0 {
                    return Ok(BodyRead::Done);
                }
                let mut buf = vec![0u8; want];
                match reader.read(&mut buf) {
                    Ok(0) => {
                        if remaining.is_some_and(|left| left != 0) {
                            Err(Http2ErrorCode::InternalError)
                        } else {
                            Ok(BodyRead::Done)
                        }
                    }
                    Ok(n) => {
                        buf.truncate(n);
                        if let Some(left) = remaining {
                            *left = left
                                .checked_sub(n as u64)
                                .ok_or(Http2ErrorCode::InternalError)?;
                        }
                        Ok(BodyRead::Data(buf, remaining.is_some_and(|left| left == 0)))
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || error.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        Ok(BodyRead::Pending)
                    }
                    Err(_) => Err(Http2ErrorCode::InternalError),
                }
            }
        }
    }
}

/// HTTP/2 Connection Driver chính xử lý một kết nối HTTP/2 qua TcpStream
pub struct Http2Connection<'a> {
    config: &'a ServerConfig,
    config_manager: &'a ConfigManager,
    secure: bool,
    hpack_decoder: HpackDecoder,
    hpack_encoder: HpackEncoder,
    flow_control: FlowControl,
    max_frame_size: u32,
    peer_max_frame_size: u32,
    peer_connection_window: Window,
    peer_initial_stream_window_size: u32,
    send_stream_windows: HashMap<u32, Window>,
    max_concurrent_streams: usize,
    active_streams: HashMap<u32, Stream>,
    last_stream_id: u32,
    pending_headers_stream_id: Option<u32>,
    pending_header_block: Vec<u8>,
    read_buffer: Vec<u8>,
    deferred_frames: VecDeque<Frame>,
    pending_responses: VecDeque<PendingResponse>,
    pending_header_responses: VecDeque<PendingHeaderResponse>,
    closed_streams: VecDeque<u32>,
}

impl<'a> Http2Connection<'a> {
    pub fn new(config: &'a ServerConfig, config_manager: &'a ConfigManager) -> Self {
        Self {
            config,
            config_manager,
            secure: false,
            hpack_decoder: HpackDecoder::new(4096, config.http2_max_header_block_size),
            hpack_encoder: HpackEncoder::new(4096),
            flow_control: FlowControl::new(config.http2_initial_window_size),
            max_frame_size: config.http2_max_frame_size,
            peer_max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            peer_connection_window: Window::new(65_535),
            peer_initial_stream_window_size: 65_535,
            send_stream_windows: HashMap::new(),
            max_concurrent_streams: config.http2_max_concurrent_streams,
            active_streams: HashMap::new(),
            last_stream_id: 0,
            pending_headers_stream_id: None,
            pending_header_block: Vec::new(),
            read_buffer: Vec::new(),
            deferred_frames: VecDeque::new(),
            pending_responses: VecDeque::new(),
            pending_header_responses: VecDeque::new(),
            closed_streams: VecDeque::new(),
        }
    }

    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Khởi tạo và xử lý vòng đời kết nối HTTP/2
    pub fn handle_connection(
        &mut self,
        stream: &mut dyn Http2Io,
        initial_buffered: &[u8],
        peer_addr: Option<SocketAddr>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.read_buffer.clear();
        self.read_buffer.extend_from_slice(initial_buffered);

        // 1. Kiểm tra Client Connection Preface (24 bytes)
        while self.read_buffer.len() < CLIENT_PREFACE.len() {
            let mut temp = [0u8; 1024];
            let n = stream.read(&mut temp)?;
            if n == 0 {
                return Ok(());
            }
            self.read_buffer.extend_from_slice(&temp[..n]);
        }

        if &self.read_buffer[..CLIENT_PREFACE.len()] != CLIENT_PREFACE {
            self.send_goaway(stream, 0, Http2ErrorCode::ProtocolError)?;
            return Ok(());
        }
        self.read_buffer.drain(..CLIENT_PREFACE.len());

        // 2. Gửi Server Initial SETTINGS Frame
        self.send_server_settings(stream)?;

        let handler = RequestHandler::new(self.config, self.config_manager);

        // 3. Main Loop đọc và xử lý Frame
        'main: loop {
            match self.poll_pending_headers(stream) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(err) => {
                    let _ = self.send_goaway(stream, self.last_stream_id, err);
                    break;
                }
            }
            match self.schedule_pending_responses(stream) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(err) => {
                    let _ = self.send_goaway(stream, self.last_stream_id, err);
                    break;
                }
            }
            if let Some(frame) = self.deferred_frames.pop_front() {
                if let Err(err) = self.process_frame(stream, &frame, &handler, peer_addr) {
                    let _ = self.send_goaway(stream, self.last_stream_id, err);
                    break;
                }
                continue;
            }
            let mut read_timed_out = false;
            while self.read_buffer.len() < FRAME_HEADER_SIZE {
                let mut temp = [0u8; 4096];
                match stream.read(&mut temp) {
                    Ok(0) => return Ok(()),
                    Ok(n) => self.read_buffer.extend_from_slice(&temp[..n]),
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        read_timed_out = true;
                        break;
                    }
                    Err(e) => return Err(Box::new(e)),
                }
            }
            if read_timed_out {
                continue 'main;
            }

            let header = match FrameHeader::parse(&self.read_buffer[..FRAME_HEADER_SIZE]) {
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
            let mut read_timed_out = false;
            while self.read_buffer.len() < total_frame_len {
                let mut temp = [0u8; 4096];
                match stream.read(&mut temp) {
                    Ok(0) => return Ok(()),
                    Ok(n) => self.read_buffer.extend_from_slice(&temp[..n]),
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        read_timed_out = true;
                        break;
                    }
                    Err(e) => return Err(Box::new(e)),
                }
            }
            if read_timed_out {
                continue 'main;
            }

            let payload_bytes = &self.read_buffer[FRAME_HEADER_SIZE..total_frame_len];
            let frame = match Frame::parse(header, payload_bytes) {
                Ok(f) => f,
                Err(code) => {
                    self.send_goaway(stream, self.last_stream_id, code)?;
                    return Ok(());
                }
            };

            self.read_buffer.drain(..total_frame_len);

            if let Err(err) = self.process_frame(stream, &frame, &handler, peer_addr) {
                let _ = self.send_goaway(stream, self.last_stream_id, err);
                break;
            }
        }
        Ok(())
    }

    fn send_server_settings(&mut self, stream: &mut dyn Http2Io) -> Result<(), std::io::Error> {
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
                    (
                        SettingId::InitialWindowSize,
                        self.flow_control.initial_stream_window_size(),
                    ),
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
        stream: &mut dyn Http2Io,
        frame: &Frame,
        handler: &RequestHandler,
        peer_addr: Option<SocketAddr>,
    ) -> Result<(), Http2ErrorCode> {
        let sid = frame.header.stream_id;

        // CONTINUATION state machine enforcement
        if let Some(expected_sid) = self.pending_headers_stream_id {
            if sid != expected_sid || frame.header.frame_type != FrameType::Continuation {
                return Err(Http2ErrorCode::ProtocolError);
            }
        } else if frame.header.frame_type == FrameType::Continuation {
            return Err(Http2ErrorCode::ProtocolError);
        }

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
                            // This is the maximum frame size the peer accepts from us.
                            self.peer_max_frame_size = *val;
                        }
                        SettingId::InitialWindowSize => {
                            // This setting changes the peer's receive window.  The current
                            // synchronous response path never sends more than 16 KiB in a
                            // DATA frame, so it does not alter our inbound receive windows.
                            if *val > 2_147_483_647 {
                                return Err(Http2ErrorCode::FlowControlError);
                            }
                            let delta = *val as i64 - self.peer_initial_stream_window_size as i64;
                            for stream in self.active_streams.values_mut() {
                                stream.send_window.adjust(delta)?;
                            }
                            for window in self.send_stream_windows.values_mut() {
                                window.adjust(delta)?;
                            }
                            self.peer_initial_stream_window_size = *val;
                        }
                        // SETTINGS_MAX_CONCURRENT_STREAMS limits streams initiated by
                        // this endpoint.  This server does not initiate request streams,
                        // and a client must not be able to raise our inbound cap.
                        SettingId::MaxConcurrentStreams => {}
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

                if !self.can_accept_new_stream() {
                    let reset = Frame {
                        header: FrameHeader {
                            length: 4,
                            frame_type: FrameType::RstStream,
                            flags: 0,
                            stream_id: sid,
                        },
                        payload: FramePayload::RstStream {
                            error_code: Http2ErrorCode::RefusedStream,
                        },
                    };
                    stream
                        .write_all(&reset.encode())
                        .map_err(|_| Http2ErrorCode::InternalError)?;
                    self.mark_closed_stream(sid);
                    return Ok(());
                }

                let mut st = Stream::new(sid, self.flow_control.initial_stream_window_size())?;
                st.send_window = Window::new(self.peer_initial_stream_window_size);
                self.send_stream_windows
                    .insert(sid, Window::new(self.peer_initial_stream_window_size));
                st.transition_to(StreamState::Open)?;
                st.received_end_stream = *end_stream;
                self.active_streams.insert(sid, st);

                if *end_headers {
                    let decoded_headers = self.hpack_decoder.decode_header_block(header_block)?;
                    let st = self.active_streams.get_mut(&sid).unwrap();
                    st.append_request_headers(decoded_headers, true);
                    if *end_stream {
                        let _ = st.transition_to(StreamState::HalfClosedRemote);
                        let st_clone = st.clone();
                        self.dispatch_h2_request(stream, &st_clone, handler, peer_addr)?;
                        self.active_streams.remove(&sid);
                    }
                } else {
                    if header_block.len() > self.config.http2_max_header_block_size {
                        return Err(Http2ErrorCode::EnhanceYourCalm);
                    }
                    self.pending_headers_stream_id = Some(sid);
                    self.pending_header_block.clear();
                    self.pending_header_block.extend_from_slice(header_block);
                }
            }

            FramePayload::Continuation {
                header_block,
                end_headers,
            } => {
                let pending_len = self
                    .pending_header_block
                    .len()
                    .checked_add(header_block.len())
                    .ok_or(Http2ErrorCode::EnhanceYourCalm)?;
                if pending_len > self.config.http2_max_header_block_size {
                    return Err(Http2ErrorCode::EnhanceYourCalm);
                }
                self.pending_header_block.extend_from_slice(header_block);
                if *end_headers {
                    self.pending_headers_stream_id = None;
                    let decoded_headers = self
                        .hpack_decoder
                        .decode_header_block(&self.pending_header_block)?;
                    self.pending_header_block.clear();

                    if let Some(st) = self.active_streams.get_mut(&sid) {
                        st.append_request_headers(decoded_headers, true);
                        if st.received_end_stream {
                            let _ = st.transition_to(StreamState::HalfClosedRemote);
                            let st_clone = st.clone();
                            self.dispatch_h2_request(stream, &st_clone, handler, peer_addr)?;
                            self.active_streams.remove(&sid);
                        }
                    }
                }
            }

            FramePayload::Data { data, end_stream } => {
                let data_len = data.len() as u32;

                if let Some(mut st) = self.active_streams.remove(&sid) {
                    if data_len > 0 {
                        if data_len as i32 > self.flow_control.connection_window().available() {
                            return Err(Http2ErrorCode::FlowControlError);
                        }
                        if data_len as i32 > st.window.available() {
                            return Err(Http2ErrorCode::FlowControlError);
                        }

                        self.flow_control
                            .connection_window_mut()
                            .consume(data_len)?;
                        st.window.consume(data_len)?;

                        // Replenish windows to prevent client from stalling
                        self.flow_control.connection_window_mut().update(data_len)?;
                        st.window.update(data_len)?;

                        let conn_update_frame = Frame {
                            header: FrameHeader {
                                length: 4,
                                frame_type: FrameType::WindowUpdate,
                                flags: 0,
                                stream_id: 0,
                            },
                            payload: FramePayload::WindowUpdate {
                                window_size_increment: data_len,
                            },
                        };
                        stream
                            .write_all(&conn_update_frame.encode())
                            .map_err(|_| Http2ErrorCode::InternalError)?;

                        let stream_update_frame = Frame {
                            header: FrameHeader {
                                length: 4,
                                frame_type: FrameType::WindowUpdate,
                                flags: 0,
                                stream_id: sid,
                            },
                            payload: FramePayload::WindowUpdate {
                                window_size_increment: data_len,
                            },
                        };
                        stream
                            .write_all(&stream_update_frame.encode())
                            .map_err(|_| Http2ErrorCode::InternalError)?;
                    }

                    if data.len()
                        > self
                            .config
                            .max_request_size
                            .saturating_sub(st.request_body.len())
                    {
                        return Err(Http2ErrorCode::EnhanceYourCalm);
                    }
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
                    self.peer_connection_window.update(*window_size_increment)?;
                } else if let Some(st) = self.active_streams.get_mut(&sid) {
                    st.send_window.update(*window_size_increment)?;
                    self.send_stream_windows
                        .entry(sid)
                        .or_insert_with(|| Window::new(self.peer_initial_stream_window_size))
                        .update(*window_size_increment)?;
                } else if let Some(window) = self.send_stream_windows.get_mut(&sid) {
                    window.update(*window_size_increment)?;
                } else if self.closed_streams.contains(&sid) {
                    // A WINDOW_UPDATE may already be in flight when a stream closes.
                } else {
                    return Err(Http2ErrorCode::ProtocolError);
                }
            }

            FramePayload::RstStream { .. } => {
                self.active_streams.remove(&sid);
                self.send_stream_windows.remove(&sid);
                self.pending_responses.retain(|p| p.stream_id != sid);
                self.pending_header_responses.retain(|p| p.stream_id != sid);
                self.mark_closed_stream(sid);
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
        stream: &mut dyn Http2Io,
        h2_stream: &Stream,
        handler: &RequestHandler,
        peer_addr: Option<SocketAddr>,
    ) -> Result<(), Http2ErrorCode> {
        validate_request_headers(h2_stream)?;
        let mut method = Method::Get;
        let mut uri = "/".to_string();
        let mut headers = Vec::new();
        let mut authority = None;

        for (name, val) in &h2_stream.request_headers {
            if name == ":method" {
                method = Method::from(val.as_str());
            } else if name == ":path" {
                uri = val.clone();
            } else if name == ":authority" {
                authority = Some(val.clone());
            } else if !name.starts_with(':') {
                headers.push((name.clone(), val.clone()));
            }
        }

        if let Some(authority) = authority {
            headers.push(("Host".to_string(), authority));
        }

        validate_content_length(&headers, h2_stream.request_body.len())?;

        let req = HttpRequest {
            method,
            uri,
            version: "HTTP/2.0".to_string(),
            headers,
            body: h2_stream.request_body.clone(),
        };
        let forwarding_peer =
            peer_addr.unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));

        // Use the same trusted dynamic routes as HTTP/1.1 before falling back
        // to static RequestHandler dispatch. Dynamic response bodies are kept
        // as bounded upstream readers and are consumed by the fair scheduler.
        let effective_config = handler.effective_config(&req);
        if crate::server::proxy::route_matches_request(&req, &effective_config) {
            match crate::server::proxy::begin_h2_response(
                &req,
                &effective_config,
                forwarding_peer,
                self.secure,
            ) {
                Ok(Some(source)) => {
                    self.pending_header_responses
                        .push_back(PendingHeaderResponse {
                            stream_id: h2_stream.id,
                            source: PendingHeaderSource::Proxy(source),
                            compress: accepts_gzip(req.get_header("Accept-Encoding")),
                            compression_level: effective_config.compression_level,
                        });
                    return Ok(());
                }
                Ok(None) => {}
                Err(_) => {
                    let response = HttpResponse::new(crate::server::http::StatusCode::BadGateway)
                        .with_body(
                            b"502 Bad Gateway: proxy upstream failure".to_vec(),
                            "text/plain; charset=utf-8",
                        );
                    self.queue_h2_response(stream, h2_stream.id, &response)?;
                    return Ok(());
                }
            }
        }
        if crate::server::fastcgi::route_matches_request(&req, &effective_config) {
            match crate::server::fastcgi::begin_h2_response(
                &req,
                &effective_config,
                self.secure,
                forwarding_peer,
            ) {
                Ok(Some(source)) => {
                    self.pending_header_responses
                        .push_back(PendingHeaderResponse {
                            stream_id: h2_stream.id,
                            source: PendingHeaderSource::FastCgi(source),
                            compress: accepts_gzip(req.get_header("Accept-Encoding")),
                            compression_level: effective_config.compression_level,
                        });
                    return Ok(());
                }
                Ok(None) => {}
                Err(_) => {
                    let response = HttpResponse::new(crate::server::http::StatusCode::BadGateway)
                        .with_body(
                            b"502 Bad Gateway: FastCGI upstream failure".to_vec(),
                            "text/plain; charset=utf-8",
                        );
                    self.queue_h2_response(stream, h2_stream.id, &response)?;
                    return Ok(());
                }
            }
        }
        let resp = handler.handle_request(&req, peer_addr);

        // Convert HttpResponse -> HTTP/2 HEADERS & DATA frames
        self.queue_h2_response(stream, h2_stream.id, &resp)?;
        Ok(())
    }

    fn queue_h2_response(
        &mut self,
        stream: &mut dyn Http2Io,
        stream_id: u32,
        resp: &HttpResponse,
    ) -> Result<(), Http2ErrorCode> {
        self.queue_h2_stream_response(stream, stream_id, resp, None)
    }

    fn poll_pending_headers(&mut self, stream: &mut dyn Http2Io) -> Result<bool, Http2ErrorCode> {
        let rounds = self.pending_header_responses.len();
        let mut progressed = false;
        for _ in 0..rounds {
            let Some(mut pending) = self.pending_header_responses.pop_front() else {
                break;
            };
            let result = match &mut pending.source {
                PendingHeaderSource::Proxy(source) => source.poll(),
                PendingHeaderSource::FastCgi(source) => source.poll(),
            };
            match result {
                Ok(None) => self.pending_header_responses.push_back(pending),
                Ok(Some((response, reader, remaining))) => {
                    let (response, reader, remaining) = if pending.compress
                        && reader.is_some()
                        && dynamic_response_compressible(&response)
                    {
                        let mut response = response;
                        remove_header(&mut response.headers, "Content-Length");
                        remove_header(&mut response.headers, "Content-Encoding");
                        response
                            .headers
                            .push(("Content-Encoding".to_string(), "gzip".to_string()));
                        ensure_vary(&mut response.headers);
                        let reader = reader.map(|source| {
                            Box::new(GzEncoder::new(
                                source,
                                Compression::new(pending.compression_level),
                            )) as Box<dyn Read + Send>
                        });
                        (response, reader, None)
                    } else {
                        (response, reader, remaining)
                    };
                    self.queue_h2_stream_response(
                        stream,
                        pending.stream_id,
                        &response,
                        reader.map(|reader| PendingBody::Reader { reader, remaining }),
                    )?;
                    progressed = true;
                }
                Err(_) => {
                    let reset = Frame {
                        header: FrameHeader {
                            length: 4,
                            frame_type: FrameType::RstStream,
                            flags: 0,
                            stream_id: pending.stream_id,
                        },
                        payload: FramePayload::RstStream {
                            error_code: Http2ErrorCode::InternalError,
                        },
                    };
                    stream
                        .write_all(&reset.encode())
                        .map_err(|_| Http2ErrorCode::InternalError)?;
                    self.send_stream_windows.remove(&pending.stream_id);
                    self.mark_closed_stream(pending.stream_id);
                    progressed = true;
                }
            }
        }
        if progressed {
            stream.flush().map_err(|_| Http2ErrorCode::InternalError)?;
        }
        Ok(progressed)
    }

    fn queue_h2_stream_response(
        &mut self,
        stream: &mut dyn Http2Io,
        stream_id: u32,
        resp: &HttpResponse,
        dynamic_body: Option<PendingBody>,
    ) -> Result<(), Http2ErrorCode> {
        let status_str = resp.status.code().to_string();
        let mut h2_headers = vec![(":status", status_str.as_str())];

        for (k, v) in &resp.headers {
            h2_headers.push((k.as_str(), v.as_str()));
        }

        let encoded_headers = self.hpack_encoder.encode_headers(&h2_headers);

        let has_body = dynamic_body.is_some()
            || match &resp.body_source {
                BodySource::Bytes(b) => !b.is_empty(),
                BodySource::File(_, size) => *size > 0,
                BodySource::FileRange(_, _, size) => *size > 0,
                BodySource::GzipFile(_, size, _) => *size > 0,
            };

        let max = self.peer_max_frame_size as usize;
        let first = encoded_headers.len().min(max);
        let mut first_flags = if first == encoded_headers.len() {
            flags::END_HEADERS
        } else {
            0
        };
        if !has_body {
            first_flags |= flags::END_STREAM;
        }
        let frame = Frame {
            header: FrameHeader {
                length: first as u32,
                frame_type: FrameType::Headers,
                flags: first_flags,
                stream_id,
            },
            payload: FramePayload::Headers {
                header_block: encoded_headers[..first].to_vec(),
                end_stream: !has_body,
                end_headers: first == encoded_headers.len(),
            },
        };
        stream
            .write_all(&frame.encode())
            .map_err(|_| Http2ErrorCode::InternalError)?;
        let mut offset = first;
        while offset < encoded_headers.len() {
            let end = (offset + max).min(encoded_headers.len());
            let final_fragment = end == encoded_headers.len();
            let frame = Frame {
                header: FrameHeader {
                    length: (end - offset) as u32,
                    frame_type: FrameType::Continuation,
                    flags: if final_fragment {
                        flags::END_HEADERS
                    } else {
                        0
                    },
                    stream_id,
                },
                payload: FramePayload::Continuation {
                    header_block: encoded_headers[offset..end].to_vec(),
                    end_headers: final_fragment,
                },
            };
            stream
                .write_all(&frame.encode())
                .map_err(|_| Http2ErrorCode::InternalError)?;
            offset = end;
        }
        if !has_body {
            // END_STREAM was emitted with the HEADERS frame, so release the
            // stream accounting immediately rather than leaking a slot.
            self.send_stream_windows.remove(&stream_id);
            self.mark_closed_stream(stream_id);
        } else {
            let body = if let Some(body) = dynamic_body {
                body
            } else {
                match &resp.body_source {
                    BodySource::Bytes(data) => PendingBody::Bytes {
                        data: data.clone(),
                        offset: 0,
                    },
                    BodySource::File(file, size) => PendingBody::File {
                        file: file
                            .try_clone()
                            .map_err(|_| Http2ErrorCode::InternalError)?,
                        remaining: *size,
                    },
                    BodySource::FileRange(file, start, length) => {
                        let mut f = file
                            .try_clone()
                            .map_err(|_| Http2ErrorCode::InternalError)?;
                        f.seek(SeekFrom::Start(*start))
                            .map_err(|_| Http2ErrorCode::InternalError)?;
                        PendingBody::File {
                            file: f,
                            remaining: *length,
                        }
                    }
                    BodySource::GzipFile(file, _, level) => PendingBody::Reader {
                        reader: Box::new(GzEncoder::new(
                            file.try_clone()
                                .map_err(|_| Http2ErrorCode::InternalError)?,
                            Compression::new(*level),
                        )),
                        remaining: None,
                    },
                }
            };
            self.pending_responses
                .push_back(PendingResponse { stream_id, body });
        }
        stream.flush().map_err(|_| Http2ErrorCode::InternalError)?;
        Ok(())
    }

    fn schedule_pending_responses(
        &mut self,
        stream: &mut dyn Http2Io,
    ) -> Result<bool, Http2ErrorCode> {
        let rounds = self.pending_responses.len();
        if rounds == 0 || self.peer_connection_window.available() <= 0 {
            return Ok(false);
        }
        let quota = (self.peer_connection_window.available() as usize / rounds).max(1);
        let mut sent = false;
        for _ in 0..rounds {
            let mut pending = match self.pending_responses.pop_front() {
                Some(p) => p,
                None => break,
            };
            let stream_window = match self.send_stream_windows.get(&pending.stream_id) {
                Some(w) => w.available(),
                None => continue,
            };
            if stream_window <= 0 || self.peer_connection_window.available() <= 0 {
                self.pending_responses.push_back(pending);
                continue;
            }
            let amount = quota
                .min(self.peer_max_frame_size as usize)
                .min(self.peer_connection_window.available() as usize)
                .min(stream_window as usize);
            let read = match pending.body.read_chunk(amount) {
                Ok(read) => read,
                Err(error_code) => {
                    let reset = Frame {
                        header: FrameHeader {
                            length: 4,
                            frame_type: FrameType::RstStream,
                            flags: 0,
                            stream_id: pending.stream_id,
                        },
                        payload: FramePayload::RstStream { error_code },
                    };
                    stream
                        .write_all(&reset.encode())
                        .map_err(|_| Http2ErrorCode::InternalError)?;
                    self.send_stream_windows.remove(&pending.stream_id);
                    self.mark_closed_stream(pending.stream_id);
                    sent = true;
                    continue;
                }
            };
            let (data, done) = match read {
                BodyRead::Data(data, done) => (data, done),
                BodyRead::Pending => {
                    self.pending_responses.push_back(pending);
                    continue;
                }
                BodyRead::Done => (Vec::new(), true),
            };
            if data.is_empty() && !done {
                self.pending_responses.push_back(pending);
                continue;
            }
            if data.is_empty() && done {
                let frame = Frame {
                    header: FrameHeader {
                        length: 0,
                        frame_type: FrameType::Data,
                        flags: flags::END_STREAM,
                        stream_id: pending.stream_id,
                    },
                    payload: FramePayload::Data {
                        data: Vec::new(),
                        end_stream: true,
                    },
                };
                stream
                    .write_all(&frame.encode())
                    .map_err(|_| Http2ErrorCode::InternalError)?;
                sent = true;
                self.send_stream_windows.remove(&pending.stream_id);
                self.mark_closed_stream(pending.stream_id);
                continue;
            }
            self.peer_connection_window.consume(data.len() as u32)?;
            self.send_stream_windows
                .get_mut(&pending.stream_id)
                .ok_or(Http2ErrorCode::StreamClosed)?
                .consume(data.len() as u32)?;
            let frame = Frame {
                header: FrameHeader {
                    length: data.len() as u32,
                    frame_type: FrameType::Data,
                    flags: if done { flags::END_STREAM } else { 0 },
                    stream_id: pending.stream_id,
                },
                payload: FramePayload::Data {
                    data,
                    end_stream: done,
                },
            };
            stream
                .write_all(&frame.encode())
                .map_err(|_| Http2ErrorCode::InternalError)?;
            sent = true;
            if !done {
                self.pending_responses.push_back(pending);
            } else {
                self.send_stream_windows.remove(&pending.stream_id);
                self.mark_closed_stream(pending.stream_id);
            }
        }
        if sent {
            stream.flush().map_err(|_| Http2ErrorCode::InternalError)?;
        }
        Ok(sent)
    }
    fn tracked_stream_count(&self) -> usize {
        // Every accepted stream remains represented here until its response
        // completes or it is reset, including streams waiting on upstream
        // headers and streams queued behind a zero peer send window.
        self.send_stream_windows.len()
    }

    fn can_accept_new_stream(&self) -> bool {
        self.tracked_stream_count() < self.max_concurrent_streams
    }

    fn mark_closed_stream(&mut self, stream_id: u32) {
        if self.closed_streams.contains(&stream_id) {
            return;
        }
        self.closed_streams.push_back(stream_id);
        let limit = self.max_concurrent_streams.saturating_mul(2).max(16);
        while self.closed_streams.len() > limit {
            self.closed_streams.pop_front();
        }
    }

    fn send_goaway(
        &mut self,
        stream: &mut dyn Http2Io,
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

fn accepts_gzip(value: Option<&str>) -> bool {
    let Some(value) = value else { return false };
    value.split(',').any(|entry| {
        let mut parts = entry.trim().split(';');
        let coding = parts.next().unwrap_or("").trim();
        let q = parts
            .find_map(|part| {
                part.trim()
                    .strip_prefix("q=")
                    .and_then(|raw| raw.parse::<f32>().ok())
            })
            .unwrap_or(1.0);
        (coding.eq_ignore_ascii_case("gzip") || coding == "*") && q > 0.0
    })
}

fn dynamic_response_compressible(response: &HttpResponse) -> bool {
    if matches!(
        response.status,
        crate::server::http::StatusCode::NoContent | crate::server::http::StatusCode::NotModified
    ) {
        return false;
    }
    if response.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("Content-Encoding")
            || (name.eq_ignore_ascii_case("Cache-Control")
                && value.to_ascii_lowercase().contains("no-transform"))
    }) {
        return false;
    }
    response
        .headers
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case("Content-Type").then_some(value))
        .is_some_and(|value| {
            let mime = value
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            mime.starts_with("text/")
                || matches!(
                    mime.as_str(),
                    "application/json"
                        | "application/javascript"
                        | "application/xml"
                        | "image/svg+xml"
                )
        })
}

fn remove_header(headers: &mut Vec<(String, String)>, name: &str) {
    headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
}

fn ensure_vary(headers: &mut Vec<(String, String)>) {
    if !headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("Vary")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("Accept-Encoding"))
    }) {
        headers.push(("Vary".to_string(), "Accept-Encoding".to_string()));
    }
}

fn validate_request_headers(h2_stream: &Stream) -> Result<(), Http2ErrorCode> {
    let mut seen_regular = false;
    let mut method = None;
    let mut scheme = None;
    let mut path = None;
    let mut authority = None;

    for (name, value) in &h2_stream.request_headers {
        if name.is_empty()
            || name
                .bytes()
                .any(|b| b.is_ascii_uppercase() || b <= 0x20 || b == 0x7f)
        {
            return Err(Http2ErrorCode::ProtocolError);
        }
        if name.starts_with(':') {
            if seen_regular {
                return Err(Http2ErrorCode::ProtocolError);
            }
            let slot = match name.as_str() {
                ":method" => &mut method,
                ":scheme" => &mut scheme,
                ":path" => &mut path,
                ":authority" => &mut authority,
                _ => return Err(Http2ErrorCode::ProtocolError),
            };
            if slot.replace(value.as_str()).is_some() {
                return Err(Http2ErrorCode::ProtocolError);
            }
        } else {
            seen_regular = true;
            if matches!(
                name.as_str(),
                "connection" | "keep-alive" | "proxy-connection" | "upgrade" | "transfer-encoding"
            ) || (name == "te" && !value.eq_ignore_ascii_case("trailers"))
            {
                return Err(Http2ErrorCode::ProtocolError);
            }
        }
    }

    let method = method.ok_or(Http2ErrorCode::ProtocolError)?;
    if method != "CONNECT" && (scheme.is_none() || path.is_none()) {
        return Err(Http2ErrorCode::ProtocolError);
    }
    Ok(())
}

fn validate_content_length(
    headers: &[(String, String)],
    actual_body_len: usize,
) -> Result<(), Http2ErrorCode> {
    let mut content_length = None;
    for (name, value) in headers {
        if name == "content-length" {
            let parsed = value
                .parse::<usize>()
                .map_err(|_| Http2ErrorCode::ProtocolError)?;
            if content_length.replace(parsed).is_some() {
                return Err(Http2ErrorCode::ProtocolError);
            }
        }
    }
    if content_length.is_some_and(|length| length != actual_body_len) {
        return Err(Http2ErrorCode::ProtocolError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PendingThenData {
        pending: bool,
    }

    impl Read for PendingThenData {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pending {
                self.pending = false;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "not ready",
                ));
            }
            buf[..4].copy_from_slice(b"body");
            Ok(4)
        }
    }

    #[test]
    fn reader_body_preserves_pending_state_and_bounds_reads() {
        let mut body = PendingBody::Reader {
            reader: Box::new(PendingThenData { pending: true }),
            remaining: Some(4),
        };
        assert!(matches!(body.read_chunk(16).unwrap(), BodyRead::Pending));
        match body.read_chunk(16).unwrap() {
            BodyRead::Data(bytes, done) => {
                assert_eq!(bytes, b"body");
                assert!(done);
            }
            _ => panic!("reader did not resume after readiness"),
        }
    }

    #[test]
    fn test_client_preface_constant() {
        assert_eq!(CLIENT_PREFACE.len(), 24);
        assert_eq!(CLIENT_PREFACE, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    }

    #[test]
    fn test_reject_invalid_h2_request_headers() {
        let mut stream = Stream::new(1, 65_535).unwrap();
        stream.request_headers = vec![
            (":method".to_string(), "GET".to_string()),
            ("host".to_string(), "example.test".to_string()),
            (":path".to_string(), "/".to_string()),
            (":scheme".to_string(), "http".to_string()),
        ];
        assert_eq!(
            validate_request_headers(&stream),
            Err(Http2ErrorCode::ProtocolError)
        );

        stream.request_headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "http".to_string()),
            (":path".to_string(), "/".to_string()),
            ("Connection".to_string(), "close".to_string()),
        ];
        assert_eq!(
            validate_request_headers(&stream),
            Err(Http2ErrorCode::ProtocolError)
        );
    }

    #[test]
    fn test_content_length_must_match_h2_data() {
        assert_eq!(
            validate_content_length(&[("content-length".to_string(), "5".to_string())], 4),
            Err(Http2ErrorCode::ProtocolError)
        );
        assert_eq!(
            validate_content_length(
                &[
                    ("content-length".to_string(), "4".to_string()),
                    ("content-length".to_string(), "4".to_string()),
                ],
                4,
            ),
            Err(Http2ErrorCode::ProtocolError)
        );
    }

    #[test]
    fn zero_send_window_cannot_accumulate_unbounded_pending_streams() {
        let config = ServerConfig {
            http2_max_concurrent_streams: 2,
            ..ServerConfig::default()
        };
        let manager = ConfigManager::new();
        let mut connection = Http2Connection::new(&config, &manager);
        connection.peer_connection_window = Window::new(0);

        for stream_id in [1, 3] {
            connection
                .send_stream_windows
                .insert(stream_id, Window::new(65_535));
            connection.pending_responses.push_back(PendingResponse {
                stream_id,
                body: PendingBody::Bytes {
                    data: vec![b'x'; 32],
                    offset: 0,
                },
            });
        }

        assert_eq!(connection.tracked_stream_count(), 2);
        assert!(!connection.can_accept_new_stream());
        assert_eq!(connection.pending_responses.len(), 2);
    }

    #[test]
    fn dynamic_gzip_policy_rejects_no_transform_and_compresses_text() {
        let response = HttpResponse::new(crate::server::http::StatusCode::Ok)
            .with_header("Content-Type", "text/plain")
            .with_header("Content-Length", "4")
            .with_body(b"body".to_vec(), "text/plain");
        assert!(dynamic_response_compressible(&response));
        let blocked = response
            .clone()
            .with_header("Cache-Control", "no-transform");
        assert!(!dynamic_response_compressible(&blocked));
        let mut encoder = GzEncoder::new(
            Box::new(std::io::Cursor::new(b"body".to_vec())) as Box<dyn Read + Send>,
            Compression::default(),
        );
        let mut output = Vec::new();
        encoder.read_to_end(&mut output).unwrap();
        assert_eq!(&output[..2], &[0x1f, 0x8b]);
    }
}
