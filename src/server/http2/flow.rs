use crate::server::http2::frame::Http2ErrorCode;

pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65_535;
pub const MAX_WINDOW_SIZE: u32 = 2_147_483_647; // 2^31 - 1

/// Struct quản lý một Sliding Flow-Control Window (RFC 9113 Section 5.2)
#[derive(Debug, Clone, PartialEq)]
pub struct Window {
    available: i32,
}

#[allow(dead_code)]
impl Window {
    pub fn new(initial_size: u32) -> Self {
        Self {
            available: initial_size as i32,
        }
    }

    pub fn available(&self) -> i32 {
        self.available
    }

    /// Tăng kích thước Cửa sổ nhận được từ WINDOW_UPDATE frame
    pub fn update(&mut self, increment: u32) -> Result<(), Http2ErrorCode> {
        if increment == 0 {
            return Err(Http2ErrorCode::ProtocolError);
        }

        let new_available = (self.available as i64) + (increment as i64);
        if new_available > (MAX_WINDOW_SIZE as i64) {
            return Err(Http2ErrorCode::FlowControlError);
        }

        self.available = new_available as i32;
        Ok(())
    }

    /// Trừ dung lượng cửa sổ khi gửi/nhận DATA frame
    pub fn consume(&mut self, bytes: u32) -> Result<(), Http2ErrorCode> {
        self.available -= bytes as i32;
        Ok(())
    }
}

/// Dynamic Flow Controller cho cả Connection-level và Stream-level
#[derive(Debug, Clone)]
pub struct FlowControl {
    connection_window: Window,
    initial_stream_window_size: u32,
}

#[allow(dead_code)]
impl FlowControl {
    pub fn new(initial_window_size: u32) -> Self {
        Self {
            connection_window: Window::new(initial_window_size),
            initial_stream_window_size: initial_window_size,
        }
    }

    pub fn connection_window(&self) -> &Window {
        &self.connection_window
    }

    pub fn connection_window_mut(&mut self) -> &mut Window {
        &mut self.connection_window
    }

    pub fn initial_stream_window_size(&self) -> u32 {
        self.initial_stream_window_size
    }

    pub fn update_initial_window_size(&mut self, new_size: u32) -> Result<(), Http2ErrorCode> {
        if new_size > MAX_WINDOW_SIZE {
            return Err(Http2ErrorCode::FlowControlError);
        }
        self.initial_stream_window_size = new_size;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_initial_and_update() {
        let mut window = Window::new(65535);
        assert_eq!(window.available(), 65535);

        window.update(1000).unwrap();
        assert_eq!(window.available(), 66535);
    }

    #[test]
    fn test_window_overflow_rejection() {
        let mut window = Window::new(MAX_WINDOW_SIZE);
        let res = window.update(1);
        assert_eq!(res, Err(Http2ErrorCode::FlowControlError));
    }

    #[test]
    fn test_zero_increment_rejection() {
        let mut window = Window::new(65535);
        let res = window.update(0);
        assert_eq!(res, Err(Http2ErrorCode::ProtocolError));
    }

    #[test]
    fn test_window_consume() {
        let mut window = Window::new(65535);
        window.consume(1000).unwrap();
        assert_eq!(window.available(), 64535);
    }
}
