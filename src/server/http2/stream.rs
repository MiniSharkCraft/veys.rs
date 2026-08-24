use crate::server::http2::flow::Window;
use crate::server::http2::frame::Http2ErrorCode;

/// Các trạng thái hợp lệ của HTTP/2 Stream (RFC 9113 Section 5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// Dynamic State & Data Buffer của 1 HTTP/2 Stream
#[derive(Debug, Clone, PartialEq)]
pub struct Stream {
    pub id: u32,
    pub state: StreamState,
    pub window: Window,
    pub send_window: Window,
    pub request_headers: Vec<(String, String)>,
    pub request_body: Vec<u8>,
    pub received_end_stream: bool,
    pub received_end_headers: bool,
}

impl Stream {
    pub fn new(id: u32, initial_window_size: u32) -> Result<Self, Http2ErrorCode> {
        // Stream ID từ client bắt buộc phải là số lẻ (1, 3, 5...)
        if id == 0 || id.is_multiple_of(2) {
            return Err(Http2ErrorCode::ProtocolError);
        }

        Ok(Self {
            id,
            state: StreamState::Idle,
            window: Window::new(initial_window_size),
            send_window: Window::new(65_535),
            request_headers: Vec::new(),
            request_body: Vec::new(),
            received_end_stream: false,
            received_end_headers: false,
        })
    }

    pub fn is_client_initiated(id: u32) -> bool {
        id > 0 && !id.is_multiple_of(2)
    }

    /// Xử lý chuyển đổi trạng thái Stream an toàn
    pub fn transition_to(&mut self, target_state: StreamState) -> Result<(), Http2ErrorCode> {
        match (self.state, target_state) {
            (StreamState::Idle, StreamState::Open) => self.state = StreamState::Open,
            (StreamState::Idle, StreamState::HalfClosedRemote) => {
                self.state = StreamState::HalfClosedRemote
            }
            (StreamState::Open, StreamState::HalfClosedRemote) => {
                self.state = StreamState::HalfClosedRemote
            }
            (StreamState::Open, StreamState::HalfClosedLocal) => {
                self.state = StreamState::HalfClosedLocal
            }
            (StreamState::Open, StreamState::Closed) => self.state = StreamState::Closed,
            (StreamState::HalfClosedRemote, StreamState::Closed) => {
                self.state = StreamState::Closed
            }
            (StreamState::HalfClosedLocal, StreamState::Closed) => self.state = StreamState::Closed,
            (StreamState::Closed, StreamState::Closed) => {}
            _ => return Err(Http2ErrorCode::StreamClosed),
        }
        Ok(())
    }

    pub fn append_request_headers(&mut self, headers: Vec<(String, String)>, end_headers: bool) {
        self.request_headers.extend(headers);
        if end_headers {
            self.received_end_headers = true;
        }
    }

    pub fn append_request_data(
        &mut self,
        data: &[u8],
        end_stream: bool,
    ) -> Result<(), Http2ErrorCode> {
        self.request_body.extend_from_slice(data);
        if end_stream {
            self.received_end_stream = true;
            let _ = self.transition_to(StreamState::HalfClosedRemote);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_client_stream_creation() {
        let stream = Stream::new(1, 65535).unwrap();
        assert_eq!(stream.id, 1);
        assert_eq!(stream.state, StreamState::Idle);
    }

    #[test]
    fn test_reject_even_client_stream_id() {
        let res = Stream::new(2, 65535);
        assert_eq!(res, Err(Http2ErrorCode::ProtocolError));
    }

    #[test]
    fn test_stream_state_transitions() {
        let mut stream = Stream::new(3, 65535).unwrap();
        stream.transition_to(StreamState::Open).unwrap();
        assert_eq!(stream.state, StreamState::Open);

        stream.transition_to(StreamState::HalfClosedRemote).unwrap();
        assert_eq!(stream.state, StreamState::HalfClosedRemote);

        stream.transition_to(StreamState::Closed).unwrap();
        assert_eq!(stream.state, StreamState::Closed);
    }
}
