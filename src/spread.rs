use crate::network::{peer, message};

pub trait Spreading {
    fn spread(&self, peers: &slab::Slab<peer::Context>, peer_index: &Vec<usize>, msg: message::Message);
}

#[derive(Copy, Clone)]
pub enum Spreader {
    Default,
    Trickle,
    Diffusion,
    Dandelion,
    DandelionPlus,
}

struct DefaultSpreader{}

impl Spreading for DefaultSpreader {
    fn spread(&self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: message::Message) {
        for peer_id in peer_list {
            peers[*peer_id].handle.write(msg.clone());
        }
    }
}

struct TrickleSpreader{}

impl Spreading for TrickleSpreader {
    fn spread(&self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: message::Message) {
        // TODO
    }
}

struct DiffusionSpreader{}

impl Spreading for DiffusionSpreader {
    fn spread(&self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: message::Message) {
        // TODO
    }
}

struct DandelionSpreader{}

impl Spreading for DandelionSpreader {
    fn spread(&self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: message::Message) {
        // TODO
    }
}

struct DandelionPlusSpreader{}

impl Spreading for DandelionPlusSpreader {
    fn spread(&self, peers: &slab::Slab<peer::Context>, peer_list: &Vec<usize>, msg: message::Message) {
        // TODO
    }
}

pub fn get_spreader(key: Spreader) -> Box<dyn Spreading + Send + Sync> {
    match key {
        Spreader::Default => Box::new(DefaultSpreader {}),
        Spreader::Trickle => Box::new(TrickleSpreader {}),
        Spreader::Diffusion => Box::new(DiffusionSpreader {}),
        Spreader::Dandelion => Box::new(DandelionSpreader {}),
        Spreader::DandelionPlus => Box::new(DandelionPlusSpreader {}),
    }
}