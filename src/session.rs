use std::{
    borrow::Cow,
    cell::{Ref, RefCell},
    collections::HashMap,
    fmt::Display,
    fs::{self, OpenOptions},
    io::{self, BufRead, BufReader, Bytes, Cursor, ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr},
    os::{
        self,
        fd::{AsFd, AsRawFd, OwnedFd, RawFd},
    },
    process::Output,
    rc::Rc,
    time::Instant,
};

use log::{debug, error, info};
use mio::{event::Event, net::TcpStream, Interest, Registry, Token};
use nix::{
    errno::Errno,
    fcntl::{splice, OFlag, SpliceFFlags},
    unistd::pipe2,
};

use crate::{dns::DNS, err};

pub type SessionRegistry = HashMap<Token, Rc<RefCell<Session>>>;

#[derive(Debug, Clone, Copy)]
pub enum State {
    Piping,
    Head,
}
pub struct Session {
    pub down_sock: TcpStream,
    pub up_sock: Option<TcpStream>,
    pub state: State,
    pub down_sock_id: usize,
    pub up_sock_id: usize,

    pub connect_header_buf: Vec<u8>,
    pub is_https: bool,
    pub host: String,
}

impl Display for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "down_sock_id [{}] up_sock_id [{}] host [{}] state [{:?}] down port {:?} up port {:?}",
            self.down_sock_id,
            self.up_sock_id,
            self.host,
            self.state,
            self.down_sock.peer_addr(),
            self.up_sock.as_ref().map(|x| x.peer_addr())
        ))
    }
}

impl Session {
    pub fn new(down_sock_id: usize, down_sock: TcpStream) -> Self {
        Session {
            host: Default::default(),
            down_sock,
            up_sock: None,
            state: State::Head,
            connect_header_buf: Vec::with_capacity(512),
            down_sock_id,
            up_sock_id: 0,
            is_https: false,
        }
    }

    pub fn down2up(&mut self) -> io::Result<u64> {
        self.up_sock
            .as_mut()
            .map(|up| {
                debug!(
                    "pipe down fd {} to up fd {}",
                    self.down_sock_id, self.up_sock_id
                );
                
                match splice_copy(&mut self.down_sock, up) {
                    Ok(size) => {
                        debug!("piping down to up size {}", size);
                        return Ok(size);
                    }
                    Err(e) => {
                        if e.kind() == ErrorKind::WouldBlock {
                            return Err(io::Error::new(ErrorKind::WouldBlock, ""));
                        }
                        error!("splice error {:?}", e);
                        return Err(io::Error::new(ErrorKind::Other, e.to_string()));
                    }
                }
            })
            .map(|result| match result {
                Ok(u) => {
                    debug!("piping down to up size {}", u);
                    if u == 0 {
                        return Err(io::Error::new(ErrorKind::UnexpectedEof, "eof"));
                    }

                    return Ok(u as u64);
                }
                Err(e) => Err(e),
            })
            .unwrap_or(Err(io::Error::new(io::ErrorKind::Other, "up not ready")))
    }

    pub fn up2down(&mut self) -> io::Result<u64> {
        debug!(
            "pipe up fd {} to down fd {}",
            self.up_sock_id, self.down_sock_id
        );
        match splice_copy(self.up_sock.as_mut().unwrap(), &mut self.down_sock) {
            Ok(size) => {
                debug!("piping up to down size {}", size);
                return Ok(size as u64);
            }
            Err(e) => {
                if e.kind() == ErrorKind::WouldBlock {
                    return Err(io::Error::new(ErrorKind::WouldBlock, ""));
                }
                error!("splice error {:?}", e);
                return Err(io::Error::new(ErrorKind::Other, e.to_string()));
            }
        }
    }

    pub fn parse_header_line(&mut self) -> io::Result<String> {
        let mut reader = &mut self.down_sock;
        let d = b'\n';
        let mut buf = [0u8; 1024];
        let mut headers = [httparse::EMPTY_HEADER; 10];
        loop {
            match reader.read(&mut buf) {
                Ok(s) => {
                    debug!("read header size {}", s);
                    if s == 0 {
                        return Err(io::Error::new(ErrorKind::Other, "eof"));
                    }

                    self.connect_header_buf.write(&buf[0..s])?;

                }
                Err(e) => {
                    if e.kind() == ErrorKind::WouldBlock {
                        let mut idx = 0;
                        for i in 0..self.connect_header_buf.len() {
                            if self.connect_header_buf[i] == d {
                                idx = i;
                                break;
                            }
                        }
                        let r = httparse::parse_headers(
                            &self.connect_header_buf[idx + 1..],
                            &mut headers,
                        );
                        if let Ok(s) = r {
                            if let httparse::Status::Complete(_) = s {
                                if let Some(host) = headers
                                    .iter()
                                    .filter(|h| h.name == "Host")
                                    .map(|h| String::from_utf8_lossy(h.value))
                                    .last()
                                {
                                    return Ok(host.into_owned());
                                }
                            } else {
                                debug!(
                                    "head not complete , buf {}",
                                    String::from_utf8_lossy(&self.connect_header_buf[idx + 1..])
                                );
                            }
                        } else {
                            error!("parse header error {:?}", r.err().unwrap())
                        }
                    }
                    return Err(e);
                }
            }
        }
    }

    fn formatHost(s: Cow<str>) -> Cow<str> {
        if s.starts_with("http") {
            return Cow::Owned(s.replace("https?://", "").replace("/", ""));
        }
        s
    }

    pub fn connect(&mut self, poll: &Registry, dns: &mut DNS) -> io::Result<RawFd> {
        let header_line = self.parse_header_line()?;
        debug!("parsed connect header {}", &header_line);
        let url = header_line.split(" ").take(2).last().unwrap();
        self.is_https = url.ends_with(":443");

        let format_url = Self::formatHost(Cow::Borrowed(url));
        let mut host_port = format_url.split(":");
        let host = host_port.next().unwrap();
        self.host = host.to_owned();
        let st = Instant::now();
        let ips = dns.query(host);
        if ips.is_none() {
            return Err(io::Error::new(
                ErrorKind::NetworkUnreachable,
                "dns qwuery failed",
            ));
        }
        let ip = ips.unwrap();

        info!("connect  {} duration: {:?}", host, st.elapsed());
        let up_addr = SocketAddr::new(ip, host_port.next().unwrap_or("80").parse().unwrap());
        debug!("up addr  {:?}", &up_addr);
        let mut up_sock = TcpStream::connect(up_addr)?;
        let up_sock_fd = &up_sock.as_raw_fd();
        debug!("up sock fd {}", up_sock_fd);
        match poll.register(
            &mut up_sock,
            Token((*up_sock_fd).try_into().unwrap()),
            Interest::READABLE | Interest::WRITABLE,
        ) {
            Ok(_) => {
                //
                self.up_sock = Some(up_sock);
                self.up_sock_id = (*up_sock_fd).try_into().unwrap();

                Ok(*up_sock_fd)
            }
            Err(e) => Err(e),
        }
    }

    pub(crate) fn pipe(&mut self, sock_id: usize) -> io::Result<u64> {
        let mut send = 0;
        if sock_id == self.down_sock_id {
            send += self.down2up()?;
        } else if sock_id == self.up_sock_id {
            send += self.up2down()?;
        }

        debug!("piping {} size {}", self.host, send);
        Ok(send)
    }

    fn handle_up_sock_connected(&mut self, evt: &Event) -> io::Result<()> {
        match self.state {
            State::Head => {
                let up_sock_id = self.up_sock_id;
                if evt.token().0 == up_sock_id {
                    debug!("session connect {} done {}", self.host, up_sock_id);
                    if self.is_https {
                        debug!("respond https");
                        self.down_sock
                            .write_all("HTTP/1.1 200 Connection established\r\n\r\n".as_bytes())?;
                    } else {
                        debug!("respond http");
                        self.up_sock
                            .as_mut()
                            .map(|s| s.write_all(&self.connect_header_buf));
                    }
                    self.state = State::Piping;
                }
            }
            State::Piping => {
                // debug!("piping..");
                // if let Err(e) = session.borrow_mut().pipe(evt.token().0) {
                //     error!("piping error {}", e);
                //     if e.kind() == ErrorKind::WouldBlock {
                //         return Ok(());
                //     }
                //     return Err(e);
                // }
            }
        }
        Ok(())
    }

    pub(crate) fn handle_write(&mut self, evt: &Event) -> io::Result<()> {
        debug!("writeable fd {} session {}", evt.token().0, self);
        let err = self.up_sock.as_mut().map(|sock| {
            if let Err(e) = sock.take_error() {
                if e.kind() == ErrorKind::NotConnected {
                    return Err(io::Error::new(ErrorKind::WouldBlock, "not connected"));
                }
                return Err(e);
            }

            if let Ok(Some(e)) = sock.take_error() {
                if e.kind() == ErrorKind::NotConnected {
                    return Err(io::Error::new(ErrorKind::WouldBlock, "not connected"));
                }
                return Err(e);
            }

            //TcpStream::peer_addr. If it returns libc::EINPROGRESS or ErrorKind::NotConnected
            if let Err(e) = sock.peer_addr() {
                if e.kind() == ErrorKind::NotConnected {
                    return Err(io::Error::new(ErrorKind::WouldBlock, "not connected"));
                }
                return Err(e);
            }

            Ok(())
        });

        if let Some(Err(e)) = err {
            return Err(e);
        }
        return self.handle_up_sock_connected(evt);
    }
}

#[cfg(target_os="linux")]
fn splice_copy(src: &mut TcpStream, dst: &mut TcpStream) -> io::Result<usize> {
    let (read_pipe, write_pipe) = pipe2(OFlag::O_NONBLOCK)?;
    let mut send = 0;
    loop {
        let mut r = splice(
            src.as_fd(),
            None,
            write_pipe.as_fd(),
            None,
            8192,
            SpliceFFlags::SPLICE_F_NONBLOCK | SpliceFFlags::SPLICE_F_MOVE,
        );
        match r {
            Ok(u) => {
                if u == 0 {
                    return Err(io::Error::new(ErrorKind::UnexpectedEof, "eof"));
                }
    
                send = send + u;
            }
            Err(e) => {
                if e == Errno::EAGAIN {
                    return Err(io::Error::new(ErrorKind::WouldBlock, ""));
                }
                error!("splice error {:?}", e);
                return Err(io::Error::new(ErrorKind::Other, e.desc()));
            }
        };

        r = splice(
            read_pipe.as_fd(),
            None,
            dst.as_fd(),
            None,
            8192,
            SpliceFFlags::SPLICE_F_NONBLOCK,
        );
        match r {
            Ok(u) => {
                if u == 0 {
                    return Err(io::Error::new(ErrorKind::UnexpectedEof, "eof"));
                }
    
                send = send + u;
            }
            Err(e) => {
                if e == Errno::EAGAIN {
                    break;
                }
                error!("splice error {:?}", e);
                return Err(io::Error::new(ErrorKind::Other, e.desc()));
            }
        };
    }
    
    Ok(send)
}
