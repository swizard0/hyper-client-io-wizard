use std::{
    time::{
        Duration,
    },
};

use socket2::{
    TcpKeepalive,
};

#[derive(Default, Debug, Clone, Copy)]
pub struct TcpKeepaliveConfig {
    pub time: Option<Duration>,
    pub interval: Option<Duration>,
    pub retries: Option<u32>,
}

impl TcpKeepaliveConfig {
    /// Converts into a `socket2::TcpKeealive` if there is any keep alive configuration.
    fn into_tcpkeepalive(self) -> Option<TcpKeepalive> {
        let mut dirty = false;
        let mut ka = TcpKeepalive::new();
        if let Some(time) = self.time {
            ka = ka.with_time(time);
            dirty = true
        }
        if let Some(interval) = self.interval {
            ka = Self::ka_with_interval(ka, interval, &mut dirty)
        };
        if let Some(retries) = self.retries {
            ka = Self::ka_with_retries(ka, retries, &mut dirty)
        };
        if dirty {
            Some(ka)
        } else {
            None
        }
    }

    #[cfg(not(any(target_os = "openbsd", target_os = "redox", target_os = "solaris")))]
    fn ka_with_interval(ka: TcpKeepalive, interval: Duration, dirty: &mut bool) -> TcpKeepalive {
        *dirty = true;
        ka.with_interval(interval)
    }

    #[cfg(any(target_os = "openbsd", target_os = "redox", target_os = "solaris"))]
    fn ka_with_interval(ka: TcpKeepalive, _: Duration, _: &mut bool) -> TcpKeepalive {
        ka // no-op as keepalive interval is not supported on this platform
    }

    #[cfg(not(any(
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "windows"
    )))]
    fn ka_with_retries(ka: TcpKeepalive, retries: u32, dirty: &mut bool) -> TcpKeepalive {
        *dirty = true;
        ka.with_retries(retries)
    }

    #[cfg(any(
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "windows"
    ))]
    fn ka_with_retries(ka: TcpKeepalive, _: u32, _: &mut bool) -> TcpKeepalive {
        ka // no-op as keepalive retries is not supported on this platform
    }
}
