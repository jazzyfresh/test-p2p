use libp2p::{
    core::upgrade,
    floodsub::{Floodsub, FloodsubEvent, Topic},
    futures::StreamExt,
    identity,
    mdns::{Mdns, MdnsEvent},
    mplex,
    noise::{Keypair, NoiseConfig, X25519Spec},
    swarm::{NetworkBehaviourEventProcess, Swarm, SwarmBuilder},
    tcp::TokioTcpConfig,
    NetworkBehaviour, PeerId, Transport,
};
use log::{error, info};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::{fs, io::AsyncBufReadExt, sync::mpsc};

const STORAGE_FILE_PATH: &str = "./blogs.json";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;
type Blogs = Vec<Blog>;

static KEYS: Lazy<identity::Keypair> = Lazy::new(|| identity::Keypair::generate_ed25519());
static PEER_ID: Lazy<PeerId> = Lazy::new(|| PeerId::from(KEYS.public()));
static TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("blogs"));

#[derive(Debug, Serialize, Deserialize)]
struct Blog {
    id: usize,
    title: String,
    rant: String,
    date: String,
    public: bool,
}

#[derive(Debug, Serialize, Deserialize)]
enum ListMode {
    ALL,
    One(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct ListRequest {
    mode: ListMode,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListResponse {
    mode: ListMode,
    data: Blogs,
    receiver: String,
}

enum EventType {
    Response(ListResponse),
    Input(String),
}

#[derive(NetworkBehaviour)]
struct BlogBehaviour {
    floodsub: Floodsub,
    mdns: Mdns,
    #[behaviour(ignore)]
    response_sender: mpsc::UnboundedSender<ListResponse>,
}

impl NetworkBehaviourEventProcess<FloodsubEvent> for BlogBehaviour {
    fn inject_event(&mut self, event: FloodsubEvent) {
        match event {
            FloodsubEvent::Message(msg) => {
                if let Ok(resp) = serde_json::from_slice::<ListResponse>(&msg.data) {
                    if resp.receiver == PEER_ID.to_string() {
                        info!("Response from {}:", msg.source);
                        resp.data.iter().for_each(|r| info!("{:?}", r));
                    }
                } else if let Ok(req) = serde_json::from_slice::<ListRequest>(&msg.data) {
                    match req.mode {
                        ListMode::ALL => {
                            info!("Received ALL req: {:?} from {:?}", req, msg.source);
                            respond_with_public_blogs(
                                self.response_sender.clone(),
                                msg.source.to_string(),
                            );
                        }
                        ListMode::One(ref peer_id) => {
                            if peer_id == &PEER_ID.to_string() {
                                info!("Received req: {:?} from {:?}", req, msg.source);
                                respond_with_public_blogs(
                                    self.response_sender.clone(),
                                    msg.source.to_string(),
                                );
                            }
                        }
                    }
                }
            }
            _ => (),
        }
    }
}

fn respond_with_public_blogs(sender: mpsc::UnboundedSender<ListResponse>, receiver: String) {
    tokio::spawn(async move {
        match read_local_blogs().await {
            Ok(blogs) => {
                let resp = ListResponse {
                    mode: ListMode::ALL,
                    receiver,
                    data: blogs.into_iter().filter(|r| r.public).collect(),
                };
                if let Err(e) = sender.send(resp) {
                    error!("error sending response via channel, {}", e);
                }
            }
            Err(e) => error!("error fetching local blogs to answer ALL request, {}", e),
        }
    });
}

impl NetworkBehaviourEventProcess<MdnsEvent> for BlogBehaviour {
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(discovered_list) => {
                for (peer, _addr) in discovered_list {
                    self.floodsub.add_node_to_partial_view(peer);
                }
            }
            MdnsEvent::Expired(expired_list) => {
                for (peer, _addr) in expired_list {
                    if !self.mdns.has_node(&peer) {
                        self.floodsub.remove_node_from_partial_view(&peer);
                    }
                }
            }
        }
    }
}

async fn create_new_blog(title: &str, rant: &str, date: &str) -> Result<()> {
    let mut local_blogs = read_local_blogs().await?;
    let new_id = match local_blogs.iter().max_by_key(|r| r.id) {
        Some(v) => v.id + 1,
        None => 0,
    };
    local_blogs.push(Blog {
        id: new_id,
        title: title.to_owned(),
        rant: rant.to_owned(),
        date: date.to_owned(),
        public: false,
    });
    write_local_blogs(&local_blogs).await?;

    info!("Created blog:");
    info!("title: {}", title);
    info!("rant: {}", rant);
    info!("date:: {}", date);

    Ok(())
}

async fn publish_blog(id: usize) -> Result<()> {
    let mut local_blogs = read_local_blogs().await?;
    local_blogs
        .iter_mut()
        .filter(|r| r.id == id)
        .for_each(|r| r.public = true);
    write_local_blogs(&local_blogs).await?;
    Ok(())
}

async fn read_local_blogs() -> Result<Blogs> {
    let content = fs::read(STORAGE_FILE_PATH).await?;
    let result = serde_json::from_slice(&content)?;
    Ok(result)
}

async fn write_local_blogs(blogs: &Blogs) -> Result<()> {
    let json = serde_json::to_string(&blogs)?;
    fs::write(STORAGE_FILE_PATH, &json).await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    info!("Peer Id: {}", PEER_ID.clone());
    let (response_sender, mut response_rcv) = mpsc::unbounded_channel();

    let auth_keys = Keypair::<X25519Spec>::new()
        .into_authentic(&KEYS)
        .expect("can create auth keys");

    let transp = TokioTcpConfig::new()
        .upgrade(upgrade::Version::V1)
        .authenticate(NoiseConfig::xx(auth_keys).into_authenticated()) // XX Handshake pattern, IX exists as well and IK - only XX currently provides interop with other libp2p impls
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    let mut behaviour = BlogBehaviour {
        floodsub: Floodsub::new(PEER_ID.clone()),
        mdns: Mdns::new(Default::default())
            .await
            .expect("can create mdns"),
        response_sender,
    };

    behaviour.floodsub.subscribe(TOPIC.clone());

    let mut swarm = SwarmBuilder::new(transp, behaviour, PEER_ID.clone())
        .executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
        .build();

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    Swarm::listen_on(
        &mut swarm,
        "/ip4/0.0.0.0/tcp/0"
            .parse()
            .expect("can get a local socket"),
    )
    .expect("swarm can be started");

    loop {
        let evt = {
            tokio::select! {
                line = stdin.next_line() => Some(EventType::Input(line.expect("can get line").expect("can read line from stdin"))),
                response = response_rcv.recv() => Some(EventType::Response(response.expect("response exists"))),
                event = swarm.select_next_some() => {
                    info!("Unhandled Swarm Event: {:?}", event);
                    None
                },
            }
        };

        if let Some(event) = evt {
            match event {
                EventType::Response(resp) => {
                    let json = serde_json::to_string(&resp).expect("can jsonify response");
                    swarm
                        .behaviour_mut()
                        .floodsub
                        .publish(TOPIC.clone(), json.as_bytes());
                }
                EventType::Input(line) => match line.as_str() {
                    "list peers" => handle_list_peers(&mut swarm).await,
                    cmd if cmd.starts_with("list blogs") => {
                        handle_list_blogs(cmd, &mut swarm).await
                    }
                    cmd if cmd.starts_with("create blog") => handle_create_blog(cmd).await,
                    cmd if cmd.starts_with("publish blog") => handle_publish_blog(cmd).await,
                    _ => error!("unknown command"),
                },
            }
        }
    }
}

async fn handle_list_peers(swarm: &mut Swarm<BlogBehaviour>) {
    info!("Discovered Peers:");
    let nodes = swarm.behaviour().mdns.discovered_nodes();
    let mut unique_peers = HashSet::new();
    for peer in nodes {
        unique_peers.insert(peer);
    }
    unique_peers.iter().for_each(|p| info!("{}", p));
}

async fn handle_list_blogs(cmd: &str, swarm: &mut Swarm<BlogBehaviour>) {
    let rest = cmd.strip_prefix("list blogs ");
    match rest {
        Some("all") => {
            let req = ListRequest {
                mode: ListMode::ALL,
            };
            let json = serde_json::to_string(&req).expect("can jsonify request");
            swarm
                .behaviour_mut()
                .floodsub
                .publish(TOPIC.clone(), json.as_bytes());
        }
        Some(blogs_peer_id) => {
            let req = ListRequest {
                mode: ListMode::One(blogs_peer_id.to_owned()),
            };
            let json = serde_json::to_string(&req).expect("can jsonify request");
            swarm
                .behaviour_mut()
                .floodsub
                .publish(TOPIC.clone(), json.as_bytes());
        }
        None => {
            match read_local_blogs().await {
                Ok(v) => {
                    info!("Local Blogs ({})", v.len());
                    v.iter().for_each(|r| info!("{:?}", r));
                }
                Err(e) => error!("error fetching local blogs: {}", e),
            };
        }
    };
}

async fn handle_create_blog(cmd: &str) {
    if let Some(rest) = cmd.strip_prefix("create blog") {
        let elements: Vec<&str> = rest.split("|").collect();
        if elements.len() < 3 {
            info!("too few arguments - Format: title|rant|date");
        } else {
            let title = elements.get(0).expect("title is there");
            let rant = elements.get(1).expect("rant is there");
            let date = elements.get(2).expect("date is there");
            if let Err(e) = create_new_blog(title, rant, date).await {
                error!("error creating blog: {}", e);
            };
        }
    }
}

async fn handle_publish_blog(cmd: &str) {
    if let Some(rest) = cmd.strip_prefix("publish blog") {
        match rest.trim().parse::<usize>() {
            Ok(id) => {
                if let Err(e) = publish_blog(id).await {
                    info!("error publishing blog with id {}, {}", id, e)
                } else {
                    info!("Published Blog with id: {}", id);
                }
            }
            Err(e) => error!("invalid id: {}, {}", rest.trim(), e),
        };
    }
}
