use std::{
    cell::RefCell, error::Error, fs::{self, File}, io::{self, ErrorKind, Write}, os::fd::AsRawFd, rc::Rc, time::Instant
};

use dns::DNS;
use log::{debug, error, info};
use mio::{event::Event, net::TcpListener, Events, Interest, Poll, Registry, Token};
use session::{Session, SessionRegistry};
use rand::prelude::*;

mod dns;
mod err;
mod session;

fn main() -> Result<(), Box<dyn Error>> {
    let mut f = fs::File::options().truncate(false).create(true).write(true).open("/home/dm/t1")?;
    f.write_fmt(format_args!("{}","x"))?;
    env_logger::init();
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    let listen_token = Token(0);
    let mut listen_sock = TcpListener::bind("0.0.0.0:7788".parse()?)?;
    poll.registry()
        .register(&mut listen_sock, listen_token, Interest::READABLE)?;

    let mut session_registry = SessionRegistry::new();
    let mut dns_manager = DNS::new();
    let mut rng = rand::thread_rng();
    loop {
        poll.poll(&mut events, None)?;
        let st = Instant::now();
        
        for evt in events.iter().choose_multiple(&mut rng, events.iter().count()) {
            let st = Instant::now();
            if let Token(0) = evt.token() {
                loop {
                    match accept(&poll.registry(), &mut session_registry, &listen_sock) {
                        Ok(_) => {},
                        Err(e) => {
                            if e.kind() == ErrorKind::WouldBlock {
                                break;
                            }
                        }
                    }
                }
            } else {
                if evt.is_readable() {
                    if let Err(e) = handleRead(
                        poll.registry(),
                        &mut session_registry,
                        &mut dns_manager,
                        evt,
                    ) {
                        if e.kind() != ErrorKind::WouldBlock {
                            error!("handle read error {:?}", e);
                            closeSession(&poll.registry(), &mut session_registry, evt);
                        }
                    }
                }

                if evt.is_writable() {
                    if let Err(e) = handleWrite(poll.registry(), &mut session_registry, evt) {
                        if e.kind() != ErrorKind::WouldBlock {
                            error!("handle write error {:?}", e);
                            closeSession(&poll.registry(), &mut session_registry, evt);
                        }
                    }
                }

                if evt.is_read_closed() {
                    closeSession(&poll.registry(), &mut session_registry, evt);
                }
                if evt.is_error() {
                    closeSession(&poll.registry(), &mut session_registry, evt);
                }
                if evt.is_write_closed() {
                    closeSession(&poll.registry(), &mut session_registry, evt);
                }
            }

            info!("process evt duraion: {:?}", st.elapsed());
        }

        info!("----  session size {}", session_registry.len());
        for k in &session_registry {
            debug!("remaining session key {:?} {}", k.0 .0, k.1.borrow())
        }
        info!("----  session -----------");
        info!("---------   per loop duration {:?} \n\n\n", st.elapsed())
    }
    Ok(())
}

fn accept(
    poll: &Registry,
    session_registry: &mut SessionRegistry,
    listen_sock: &TcpListener,
) -> io::Result<()> {
    match listen_sock.accept() {
        Ok((sock, addr)) => {
            let down_sock_id = sock.as_raw_fd();
            debug!("accpet sock {} fd {}", addr, down_sock_id);
            let sock_id = (down_sock_id).try_into().unwrap();
            let session = Rc::new(RefCell::new(Session::new(sock_id, sock)));
            let r = poll.register(
                &mut session.borrow_mut().down_sock,
                Token(sock_id),
                Interest::READABLE | Interest::WRITABLE,
            );

            match r {
                Ok(_) => {
                    session_registry.insert(Token(sock_id), session);
                    Ok(())
                }
                Err(e) => {
                    error!("register sock errr {:?}", e);
                    Err(e)
                }
            }
        }
        Err(e) => Err(e),
    }
}

fn closeSession(poll: &Registry, session_registry: &mut SessionRegistry, evt: &Event) {
    if let Some(s) = session_registry.remove(&evt.token()) {
        let sock_id = evt.token().0;
        debug!("close session {} fd {}", s.borrow(), sock_id);
        if sock_id == s.borrow().down_sock_id {
            let s = session_registry.remove(&Token(s.borrow().up_sock_id));
            s.iter().for_each(|se| {
                debug!("remove up_sock_fd {}", se.borrow().up_sock_id);
            });
        } else {
            let s = session_registry.remove(&Token(s.borrow().down_sock_id));
            s.iter().for_each(|se| {
                debug!("remove down_sock_fd {}", se.borrow().down_sock_id);
            });
        }

        let rr = poll.deregister(&mut s.borrow_mut().down_sock);
        if let Err(e) = rr {
            error!(
                "deregister fd {} err {:?}",
                &mut s.borrow_mut().down_sock.as_raw_fd(),
                e
            );
        }
        s.borrow_mut().up_sock.iter_mut().for_each(|s| {
            let rr = poll.deregister(s);
            if let Err(e) = rr {
                error!("deregister fd {} err {:?}", s.as_raw_fd(), e);
            }
        });
    }
}

fn handleWrite(
    registry: &Registry,
    session_registry: &mut SessionRegistry,
    evt: &Event,
) -> io::Result<()> {
    if let Some(sess) = session_registry.get(&evt.token()) {
        return sess.borrow_mut().handle_write(evt);
    }

    Ok(())
}

fn handleRead(
    poll: &Registry,
    sessionRegistry: &mut SessionRegistry,
    dns: &mut DNS,
    t: &Event,
) -> io::Result<()> {
    let mut sessionOpt = sessionRegistry.get(&t.token());
    if sessionOpt.is_none() {
        return Ok(());
    }

    let session = sessionOpt.unwrap();
    debug!(
        "readable event fd {} session {}",
        t.token().0,
        session.borrow()
    );
    let state = session.borrow().state;
    let host = session.borrow().host.clone();
    match state {
        session::State::Head => {
            let x = session.borrow_mut().connect(poll, dns);
            if x.is_ok() {
                let fd = x.unwrap();
                sessionRegistry.insert(Token(fd.try_into().unwrap()), Rc::clone(session));
                return Ok(());
            } else {
                let e = x.unwrap_err();
                if e.kind() == ErrorKind::WouldBlock {
                    return Ok(());
                }
                error!("connect error {:?}", e);
                return Err(e);
            }
        }
        session::State::Piping => {
            debug!("piping..");
            if let Err(e) = session.borrow_mut().pipe(t.token().0) {
                if e.kind() == ErrorKind::WouldBlock {
                    return Ok(());
                }
                error!("piping {} error {:?}", host, e);
                return Err(e);
            }
            Ok(())
        }
    }
}
