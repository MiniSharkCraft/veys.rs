use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

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

/// HTTP/2 Connection Driver chính xử lý một kết nối HTTP/2 qua TcpStream
pub struct Http2Connection<'a> {
    config: &'a ServerConfig,
    config_manager: &'a ConfigManager,
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
        }
    }

    /// Khởi tạo và xử lý vòng đời kết nối HTTP/2
    pub fn handle_connection(
        &mut self,
        stream: &mut TcpStream,
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
        loop {
            if let Some(frame) = self.deferred_frames.pop_front() {
                if let Err(err) = self.process_frame(stream, &frame, &handler, peer_addr) {
                    let _ = self.send_goaway(stream, self.last_stream_id, err);
                    break;
                }
                continue;
            }
            while self.read_buffer.len() < FRAME_HEADER_SIZE {
                let mut temp = [0u8; 4096];
                match stream.read(&mut temp) {
                    Ok(0) => return Ok(()),
                    Ok(n) => self.read_buffer.extend_from_slice(&temp[..n]),
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        return Ok(());
                    }
                    Err(e) => return Err(Box::new(e)),
                }
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
            while self.read_buffer.len() < total_frame_len {
                let mut temp = [0u8; 4096];
                match stream.read(&mut temp) {
                    Ok(0) => return Ok(()),
                    Ok(n) => self.read_buffer.extend_from_slice(&temp[..n]),
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        return Ok(());
                    }
                    Err(e) => return Err(Box::new(e)),
                }
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
        stream: &mut TcpStream,
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

                if self.active_streams.len() >= self.max_concurrent_streams {
                    return Err(Http2ErrorCode::RefusedStream);
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
                        self.send_stream_windows.remove(&sid);
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
                            self.send_stream_windows.remove(&sid);
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
                        self.send_stream_windows.remove(&sid);
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
                } else {
                    return Err(Http2ErrorCode::ProtocolError);
                }
            }

            FramePayload::RstStream { .. } => {
                self.active_streams.remove(&sid);
                self.send_stream_windows.remove(&sid);
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
        validate_request_headers(h2_stream)?;
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

        validate_content_length(&headers, h2_stream.request_body.len())?;

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
        if encoded_headers.len() as u32 > self.peer_max_frame_size {
            return Err(Http2ErrorCode::InternalError);
        }

        let has_body = match &resp.body_source {
            BodySource::Bytes(b) => !b.is_empty(),
            BodySource::File(_, size) => *size > 0,
            BodySource::FileRange(_, _, size) => *size > 0,
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
                    self.send_data(stream, stream_id, bytes, true)?;
                }
                BodySource::File(file, size) => {
                    let mut file = file
                        .try_clone()
                        .map_err(|_| Http2ErrorCode::InternalError)?;
                    let mut remaining = *size;
                    let mut buffer = [0u8; 16384];
                    while remaining > 0 {
                        let to_read = remaining.min(buffer.len() as u64) as usize;
                        let n = file
                            .read(&mut buffer[..to_read])
                            .map_err(|_| Http2ErrorCode::InternalError)?;
                        if n == 0 {
                            return Err(Http2ErrorCode::InternalError);
                        }
                        remaining -= n as u64;
                        self.send_data(stream, stream_id, &buffer[..n], remaining == 0)?;
                    }
                }
                BodySource::FileRange(file, offset, length) => {
                    let mut f = file
                        .try_clone()
                        .map_err(|_| Http2ErrorCode::InternalError)?;
                    use std::io::Seek;
                    f.seek(std::io::SeekFrom::Start(*offset))
                        .map_err(|_| Http2ErrorCode::InternalError)?;
                    let mut remaining = *length;
                    let mut buffer = [0u8; 16384];

                    while remaining > 0 {
                        let to_read = (remaining as usize).min(buffer.len());
                        let n = f
                            .read(&mut buffer[..to_read])
                            .map_err(|_| Http2ErrorCode::InternalError)?;
                        if n == 0 {
                            return Err(Http2ErrorCode::InternalError);
                        }
                        remaining -= n as u64;
                        let is_last = remaining == 0;

                        self.send_data(stream, stream_id, &buffer[..n], is_last)?;
                    }
                }
            }
        }

        let _ = stream.flush();
        Ok(())
    }

    fn send_data(
        &mut self,
        stream: &mut TcpStream,
        stream_id: u32,
        data: &[u8],
        end_stream: bool,
    ) -> Result<(), Http2ErrorCode> {
        let mut offset = 0;
        while offset < data.len() {
            while self.peer_connection_window.available() <= 0
                || self
                    .send_stream_windows
                    .get(&stream_id)
                    .ok_or(Http2ErrorCode::StreamClosed)?
                    .available()
                    <= 0
            {
                self.wait_for_window_update(stream, stream_id)?;
            }

            let conn = self.peer_connection_window.available() as usize;
            let stream_window = self.send_stream_windows[&stream_id].available() as usize;
            let amount = (data.len() - offset)
                .min(self.peer_max_frame_size as usize)
                .min(conn)
                .min(stream_window);
            if amount == 0 {
                continue;
            }
            let final_frame = end_stream && offset + amount == data.len();
            self.peer_connection_window.consume(amount as u32)?;
            self.send_stream_windows
                .get_mut(&stream_id)
                .ok_or(Http2ErrorCode::StreamClosed)?
                .consume(amount as u32)?;
            let frame = Frame {
                header: FrameHeader {
                    length: amount as u32,
                    frame_type: FrameType::Data,
                    flags: if final_frame { flags::END_STREAM } else { 0 },
                    stream_id,
                },
                payload: FramePayload::Data {
                    data: data[offset..offset + amount].to_vec(),
                    end_stream: final_frame,
                },
            };
            stream
                .write_all(&frame.encode())
                .map_err(|_| Http2ErrorCode::InternalError)?;
            offset += amount;
        }
        Ok(())
    }

    fn wait_for_window_update(
        &mut self,
        stream: &mut TcpStream,
        stream_id: u32,
    ) -> Result<(), Http2ErrorCode> {
        let mut header_bytes = [0u8; FRAME_HEADER_SIZE];
        self.read_into_buffer(stream, FRAME_HEADER_SIZE)?;
        header_bytes.copy_from_slice(&self.read_buffer[..FRAME_HEADER_SIZE]);
        self.read_buffer.drain(..FRAME_HEADER_SIZE);
        let header = FrameHeader::parse(&header_bytes)?;
        if header.length > self.max_frame_size {
            return Err(Http2ErrorCode::FrameSizeError);
        }
        self.read_into_buffer(stream, header.length as usize)?;
        let payload = self.read_buffer[..header.length as usize].to_vec();
        self.read_buffer.drain(..header.length as usize);
        let frame = Frame::parse(header, &payload)?;
        match frame.payload {
            FramePayload::WindowUpdate {
                window_size_increment,
            } if frame.header.stream_id == 0 => {
                self.peer_connection_window.update(window_size_increment)?;
            }
            FramePayload::WindowUpdate {
                window_size_increment,
            } if frame.header.stream_id != 0 => {
                self.send_stream_windows
                    .get_mut(&frame.header.stream_id)
                    .ok_or(Http2ErrorCode::StreamClosed)?
                    .update(window_size_increment)?;
            }
            FramePayload::Ping {
                opaque_data,
                ack: false,
            } => {
                let ack = Frame {
                    header: FrameHeader {
                        length: 8,
                        frame_type: FrameType::Ping,
                        flags: flags::ACK,
                        stream_id: 0,
                    },
                    payload: FramePayload::Ping {
                        opaque_data,
                        ack: true,
                    },
                };
                stream
                    .write_all(&ack.encode())
                    .map_err(|_| Http2ErrorCode::InternalError)?;
            }
            FramePayload::Settings { ack: true, .. } => {}
            FramePayload::Settings { ack: false, .. } => {
                let ack = Frame {
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
                stream
                    .write_all(&ack.encode())
                    .map_err(|_| Http2ErrorCode::InternalError)?;
            }
            FramePayload::RstStream { .. } if frame.header.stream_id == stream_id => {
                return Err(Http2ErrorCode::StreamClosed);
            }
            ref _other => {
                self.deferred_frames.push_back(frame);
                return Ok(());
            }
        }
        Ok(())
    }

    fn read_into_buffer(
        &mut self,
        stream: &mut TcpStream,
        required: usize,
    ) -> Result<(), Http2ErrorCode> {
        while self.read_buffer.len() < required {
            let mut temp = [0u8; 4096];
            let n = stream
                .read(&mut temp)
                .map_err(|_| Http2ErrorCode::InternalError)?;
            if n == 0 {
                return Err(Http2ErrorCode::InternalError);
            }
            self.read_buffer.extend_from_slice(&temp[..n]);
        }
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
}
