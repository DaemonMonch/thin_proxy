use std::{cell::RefCell, collections::HashMap, net::IpAddr, rc::Rc};

pub struct DNS {
    cache : HashMap<String,Vec<IpAddr>>
}

impl  DNS {
    pub fn new() -> DNS {
        DNS{cache: HashMap::new()}
    }

    pub fn query(&mut self, host : &str) -> Option<IpAddr> {
        self.cache.entry(host.to_owned()).or_insert_with_key(|h| dns_lookup::lookup_host(h).unwrap_or(Vec::new()));
        match self.cache.get(host) {
            Some(ips) => {
                if ips.is_empty() {
                    self.cache.remove(host);
                    return None;
                }

                ips.first().map(|x| x.to_owned())
            }
            None => None,
        }
    }
}