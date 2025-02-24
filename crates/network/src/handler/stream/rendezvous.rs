use actix::{Message, StreamHandler};

use crate::EventLoop;

#[derive(Message)]
#[rtype(result = "()")]
pub struct FromTick;

impl StreamHandler<FromTick> for EventLoop {
    fn started(&mut self, _ctx: &mut Self::Context) {
        println!("started receiving swarm messages");
    }

    fn handle(&mut self, _tick: FromTick, _ctx: &mut Self::Context) {
        self.broadcast_rendezvous_discoveries();
    }

    fn finished(&mut self, _ctx: &mut Self::Context) {
        println!("finished receiving swarm messages");
    }
}
