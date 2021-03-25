use std::{
    collections::{BTreeSet, HashMap, HashSet},
    io::BufRead,
    path::PathBuf,
};

use anyhow::{bail, ensure, Context};
use console::style;
use rayon::prelude::*;
use structopt::StructOpt;

const DEFAULT_LOG_LOCATION: &str = "/var/log/**/mail*.log";

#[derive(Debug, structopt::StructOpt)]
#[structopt(author, about = "Parse log files looking for what a mail went through")]
struct Opt {
    /// Message-id to look for in the log files
    message_id: String,

    /// Log files into which to look [default: /var/log/**/mail*.log]
    #[structopt(parse(from_os_str))]
    files: Vec<PathBuf>,
}

#[derive(Clone, PartialEq, Eq)]
enum ParsedLine {
    Postfix {
        id: String,                  // the postfix transaction id
        message_id: Option<String>,  // the message-id, if listed
        previous_id: Option<String>, // the previous postfix transaction id
        next_id: Option<String>,     // the next postfix transaction id
    },

    Unknown,
    Useless,
}

impl ParsedLine {
    fn parse(line: &[u8]) -> ParsedLine {
        use nom::{
            branch::alt,
            bytes::complete::{is_a, tag, take, take_until},
            combinator::{eof, map, opt, rest, value},
            sequence::{delimited, preceded, tuple},
        };
        let res: nom::IResult<&[u8], ParsedLine> = preceded(
            tuple((
                take("Jan 10 00:00:00 ".len()), // skip the date
                take_until(" "),                // skip the hostname
                take(1usize),                   // and the space
            )),
            alt((
                // TODO: clamsmtp and postlicyd don't show the
                // message-id, but maybe we could fiddle with
                // from/to/timestamp to approximate?
                value(ParsedLine::Useless, tag("clamsmtp")),
                value(ParsedLine::Useless, tag("postlicyd")),
                // Postfix log line
                preceded(
                    tuple((
                        tag("postfix"),
                        take_until(" "), // ignore until the beginning of the log line itself
                        take(1usize),    // and the space
                    )),
                    alt((
                        // Log lines with no identifier
                        value(
                            ParsedLine::Useless,
                            alt((
                                tag("Anonymous TLS connection established from "),
                                tag("warning: "),
                                tag("connect from "),
                                tag("lost connection after "),
                                tag("disconnect from "),
                                tag("Untrusted TLS connection established to "),
                                tag("Trusted TLS connection established to "),
                                tag("connect to "),
                                tag("Anonymous TLS connection established to "),
                                tag("statistics: "),
                                tag("NOQUEUE: "),
                                tag("SSL_accept error from "),
                                tag("Trusted TLS connection established from "),
                                tag("Untrusted TLS connection established from "),
                                tag("timeout after "),
                                tag("improper command pipelining after "),
                                tag("Verified TLS connection established to "),
                                tag("too many errors "),
                                tag("mapping DSN status "),
                                tag("SSL_connect error to "),
                            )),
                        ),
                        // Log lines that begin with an identifier
                        map(
                            tuple((
                                map(
                                    is_a("0123456789ABCDEF"),
                                    |s: &[u8]| String::from_utf8_lossy(s).to_string()
                                ),
                                tag(": "),
                                alt((
                                    // Log lines with nothing
                                    value((None, None, None), tuple((tag("removed\n"), eof))),
                                    value(
                                        (None, None, None),
                                        alt((
                                            tag("enabling PIX workarounds: "),
                                            tag("lost connection with "),
                                            tag("discard: "),
                                            tag("reject: "),
                                            tag("filter: "),
                                            tag("Cannot start TLS: "),
                                            tag("conversation with "),
                                        )),
                                    ),
                                    value(
                                        (None, None, None),
                                        tuple((
                                            tag("uid="),
                                            is_a("0123456789"),
                                            tag(" from=<"),
                                            take_until(">"),
                                            tag(">\n"),
                                            eof,
                                        )),
                                    ),
                                    value(
                                        (None, None, None),
                                        tuple((
                                            tag("from=<"),
                                            take_until(">"),
                                            tag(">, size="),
                                            is_a("0123456789"),
                                            tag(", nrcpt="),
                                            is_a("0123456789"),
                                            tag(" (queue active)\n"),
                                            eof,
                                        )),
                                    ),
                                    value(
                                        (None, None, None),
                                        tuple((
                                            tag("from=<"),
                                            take_until(">"),
                                            tag(">, status="),
                                            take_until(","),
                                            tag(", returned to sender"),
                                        )),
                                    ),
                                    value(
                                        (None, None, None),
                                        tuple((
                                            tag("client="),
                                            is_a("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:-[]"),
                                            tag("\n"),
                                            eof,
                                        )),
                                    ),
                                    value(
                                        (None, None, None),
                                        tuple((
                                            tag("client="),
                                            take_until(","),
                                            tag(", sasl_method="),
                                            take_until(","),
                                            tag(", sasl_username="),
                                            is_a("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-@"),
                                            tag("\n"),
                                            eof,
                                        )),
                                    ),
                                    value(
                                        (None, None, None),
                                        tuple((
                                            tag("host "),
                                            take_until(" "),
                                            alt((
                                                tag(" said: "),
                                                tag(" refused to talk to me: "),
                                            )),
                                        )),
                                    ),
                                    // Log lines with message-id's, previous id's and/or next id's
                                    delimited(
                                        tuple((
                                            opt(tag("resent-")), // consider resent-message-id like message-id
                                            tag("message-id="),
                                        )),
                                        map(
                                            take_until("\n"),
                                            |message_id: &[u8]| (Some(String::from_utf8_lossy(message_id).to_string()), None, None),
                                        ),
                                        tuple((tag("\n"), eof)),
                                    ),
                                    delimited(
                                        tag("sender non-delivery notification: "),
                                        map(
                                            is_a("0123456789ABCDEF"),
                                            |next_id: &[u8]| (None, None, Some(String::from_utf8_lossy(next_id).to_string())),
                                        ),
                                        tuple((tag("\n"), eof)),
                                    ),
                                    delimited(
                                        tuple((
                                            tag("client="),
                                            take_until(","),
                                            tag(", orig_queue_id="),
                                        )),
                                        map(
                                            is_a("0123456789ABCDEF"),
                                            |previous_id: &[u8]| (None, Some(String::from_utf8_lossy(previous_id).to_string()), None),
                                        ),
                                        tuple((
                                            tag(", orig_client="),
                                            is_a("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-[]"),
                                            tag("\n"),
                                            eof,
                                        )),
                                    ),
                                    preceded(
                                        tuple((
                                            tag("to=<"),
                                            take_until(">"),
                                            opt(tuple((tag(">, orig_to=<"), take_until(">")))),
                                            tag(">, relay="),
                                            take_until(","),
                                            opt(tuple((tag(", conn_use="), is_a("0123456789")))),
                                            tag(", delay="),
                                            is_a("0123456789."),
                                            tag(", delays="),
                                            is_a("0123456789./"),
                                            tag(", dsn="),
                                            is_a("0123456789."),
                                            tag(", status="),
                                            take_until(" "),
                                            tag(" ("),
                                        )),
                                        alt((
                                            delimited(
                                                alt((
                                                    tag("forwarded as "),
                                                    tag("250 2.0.0 Ok: queued as "),
                                                )),
                                                map(
                                                    is_a("0123456789ABCDEF"),
                                                    |next_id: &[u8]| (None, None, Some(String::from_utf8_lossy(next_id).to_string()))
                                                ),
                                                tuple((tag(")\n"), eof)),
                                            ),
                                            value((None, None, None), rest),
                                        )),
                                    ),
                                )),
                            )),
                            |(id, _, (message_id, previous_id, next_id))| ParsedLine::Postfix {
                                id: id.to_string(),
                                message_id: message_id,
                                previous_id: previous_id,
                                next_id: next_id,
                            },
                        ),
                    )),
                ),
            )),
        )(line);
        match res {
            Ok((_, res)) => res,
            Err(_e) => {
                /*
                match _e {
                    nom::Err::Incomplete(n) => panic!(
                        "parse err in line:\n{:?}\nerror: incomplete (missing {:?})",
                        String::from_utf8_lossy(line).to_string(),
                        n,
                    ),
                    nom::Err::Error(e) | nom::Err::Failure(e) => panic!(
                        "parse err in line:\n{:?}\nerror: {:?} at input:\n{:?}",
                        String::from_utf8_lossy(line).to_string(),
                        e.code,
                        String::from_utf8_lossy(e.input).to_string(),
                    ),
                }
                // */
                ParsedLine::Unknown
            }
        }
    }
}

// all the data associated to one postfix id
#[derive(Clone, Debug)]
struct Block {
    // this block is the creation_idx'th one from the top of the file
    creation_idx: usize,

    // the postfix id of this block
    id: String,

    // the file in which this block was
    file: PathBuf,

    // all the lines in which this postfix-id appears
    lines: Vec<usize>,

    // all the previous id's
    previous_ids: HashSet<String>,

    // all the next id's
    next_ids: HashSet<String>,
}

#[derive(Clone)]
struct State {
    // see Block::creation_idx
    next_block_creation_idx: usize,

    // the file this refers to
    file: PathBuf,

    // all the lines in the log files
    lines: Vec<String>,

    // message-id => all the postfix-id's where it appears
    message_ids: HashMap<String, Vec<String>>,

    // postfix-id => block
    blocks: HashMap<String, Block>,
}

impl State {
    fn new(file: PathBuf) -> State {
        State {
            next_block_creation_idx: 0,
            file,
            lines: Vec::new(),
            message_ids: HashMap::new(),
            blocks: HashMap::new(),
        }
    }

    fn eat(&mut self, line: &[u8]) -> Result<(), ()> {
        let this_line = self.lines.len();
        let parsed = ParsedLine::parse(line);

        let is_useless = match parsed {
            ParsedLine::Postfix {
                id,
                message_id,
                previous_id,
                next_id,
            } => {
                if let Some(mid) = message_id {
                    self.message_ids
                        .entry(mid)
                        .or_insert_with(Vec::new)
                        .push(id.clone());
                }
                let block = {
                    let next_block_creation_idx = &mut self.next_block_creation_idx;
                    let file = &self.file;
                    self.blocks.entry(id.clone()).or_insert_with(|| {
                        let creation_idx = *next_block_creation_idx;
                        *next_block_creation_idx += 1;
                        Block {
                            creation_idx,
                            id,
                            file: file.clone(),
                            lines: Vec::new(),
                            previous_ids: HashSet::new(),
                            next_ids: HashSet::new(),
                        }
                    })
                };
                block.lines.push(this_line);
                if let Some(pid) = previous_id {
                    block.previous_ids.insert(pid);
                }
                if let Some(nid) = next_id {
                    block.next_ids.insert(nid);
                }
                false
            }

            ParsedLine::Useless => true,
            ParsedLine::Unknown => return Err(()),
        };

        if !is_useless {
            // Push the string apart from the trailing \n
            self.lines
                .push(String::from_utf8_lossy(&line[..line.len() - 1]).to_string());
        }
        Ok(())
    }
}

fn run(mut opt: Opt) -> anyhow::Result<()> {
    // Recover the file list
    if opt.files.is_empty() {
        opt.files = glob::glob(DEFAULT_LOG_LOCATION)
            .context("grepping for log files")?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .context("grepping for log files")?;
        ensure!(
            !opt.files.is_empty(),
            "No log file found at {}",
            DEFAULT_LOG_LOCATION
        );
    }

    // Prepare the progress bars
    let bar_style = indicatif::ProgressStyle::default_bar().template(
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes:>8}/{total_bytes:8} ({eta}) {prefix}  {wide_msg}",
    ).progress_chars("=>-");
    let multi_progress = indicatif::MultiProgress::new();
    let max_filename_len = opt
        .files
        .iter()
        .map(|f| format!("{:?}", f).len())
        .max()
        .expect("failed to find max of verified-non-empty list");
    let bars = opt
        .files
        .iter()
        .map(|file| {
            let size = std::fs::metadata(file)
                .with_context(|| format!("retrieving metadata for log file {:?}", file))?
                .len();
            let bar = multi_progress.add(indicatif::ProgressBar::new(
                ((size + 999_999) / 1_000_000) * 1_000_000,
            ));
            bar.set_style(bar_style.clone());
            bar.set_prefix(&format!(
                "loading {name:width$?}",
                name = file,
                width = max_filename_len,
            ));
            Ok(bar)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    std::thread::spawn(move || {
        multi_progress
            .join()
            .expect("failed joining the progress bars");
    });

    // Parse the files
    let states = opt
        .files
        .iter()
        .zip(bars.into_iter())
        .par_bridge()
        .map(|(file, bar)| {
            let f = std::fs::File::open(file)
                .with_context(|| format!("opening log file {:?}", file))?;
            let mut f = std::io::BufReader::new(f);

            let mut accumulated_size = 0u64;
            let mut state = State::new(file.clone());
            let mut showed_message = false;
            let mut lineno = 0;
            let mut l = Vec::new();
            loop {
                // Read the line
                lineno += 1;
                l.truncate(0);
                let read = f
                    .read_until(b'\n', &mut l)
                    .with_context(|| format!("reading file {:?}", file))?;
                if read == 0 {
                    break;
                }
                accumulated_size += read as u64;

                // Parse the line
                if state.eat(&l).is_err() && !showed_message {
                    bar.set_message(&format!(
                        "{}: unable to parse line {}: {}",
                        style("warning").bold().yellow(),
                        lineno,
                        String::from_utf8_lossy(&l),
                    ));
                    showed_message = true;
                }

                // And move the progress bar forward
                if accumulated_size > bar.length() / 2048 {
                    bar.inc(accumulated_size);
                    accumulated_size = 0;
                }
            }
            bar.finish();
            Ok((file.clone(), state))
        })
        .collect::<anyhow::Result<HashMap<PathBuf, State>>>()?;

    if !display(&opt.message_id, states.clone()).context("displaying the result")? {
        eprintln!(
            "{}: found no mail with the requested message-id, trying with ‘<{}>’",
            style("warning").bold().yellow(),
            opt.message_id
        );
        let bracketed_mid = String::from("<") + &opt.message_id + ">";
        if !display(&bracketed_mid, states).context("displaying the result")? {
            bail!("found logs for neither ‘{0}’ nor ‘<{0}>’", opt.message_id);
        }
    }

    Ok(())
}

fn display(message_id: &str, states: HashMap<PathBuf, State>) -> anyhow::Result<bool> {
    // Search the states for the blocks that are relevant to the message-id
    let blocks = states
        .iter()
        .flat_map(|(_, s)| {
            s.message_ids
                .get(message_id)
                .into_iter()
                .flat_map(|ids| {
                    ids.iter()
                        .filter_map(|id| s.blocks.get(id).map(|b| (b.id.clone(), b.clone())))
                })
                .collect::<Vec<(String, Block)>>()
                .into_iter()
        })
        .collect::<HashMap<String, Block>>();

    if blocks.is_empty() {
        return Ok(false);
    }

    // Helper functions to toposort the blocks
    //
    // (we return BTreeSet's because it makes sure things are properly
    // sorted and the display is reproducible)
    let predecessors = |id: &str| {
        // get all the blocks pointed to by previous-id
        states
            .iter()
            .flat_map(move |(_, s)| {
                s.blocks
                    .get(id)
                    .into_iter()
                    .flat_map(|b| b.previous_ids.iter().cloned())
            })
            // and then, get all the blocks that point to this by next-id
            .chain(states.iter().flat_map(move |(_, s)| {
                s.blocks.iter().filter_map(move |(b_id, b)| {
                    if b.next_ids.contains(id) {
                        Some(b_id.clone())
                    } else {
                        None
                    }
                })
            }))
            .collect::<BTreeSet<String>>()
    };
    let successors = |id: &str| {
        // get all the blocks pointed to by next-id
        states
            .iter()
            .flat_map(move |(_, s)| {
                s.blocks
                    .get(id)
                    .into_iter()
                    .flat_map(|b| b.next_ids.iter().cloned())
            })
            // and then, get all the blocks that point to this by previous-id
            .chain(states.iter().flat_map(move |(_, s)| {
                s.blocks.iter().filter_map(move |(b_id, b)| {
                    if b.previous_ids.contains(id) {
                        Some(b_id.clone())
                    } else {
                        None
                    }
                })
            }))
            .collect::<BTreeSet<String>>()
    };

    // Finally, display all the things
    let mut displayed = HashSet::new();
    for (id, _) in blocks.iter() {
        if displayed.contains(&id as &str) {
            // Already displayed this
            continue;
        }

        // Figure out the root of the predecessors
        let root = {
            let initial_id = &id;
            let mut id = id.clone();
            let mut explored = HashSet::new();
            loop {
                explored.insert(id.clone());
                let pred = predecessors(&id);
                if pred.is_empty() {
                    // Found the root
                    break id;
                }
                if pred.len() > 1 {
                    // More than one predecessor… ignoring, we'll pick the min-valued one
                    eprintln!(
                        "{}: {} has more than one predecessor, output may look weird",
                        style("warning").bold().yellow(),
                        id
                    );
                }
                let parent = pred
                    .iter()
                    .next()
                    .expect("getting the min element of a non-empty btree set")
                    .clone();
                ensure!(
                    !explored.contains(&parent),
                    "found a loop involving message {}",
                    id,
                );
                ensure!(
                    !displayed.contains(&parent),
                    "somehow already displayed ancestor {} but not its child {}",
                    parent,
                    initial_id,
                );
                id = parent;
            }
        };

        // Display the root and then all successors
        display_recursively(
            root,
            2,
            &predecessors,
            &successors,
            &|id| {
                for (_, s) in states.iter() {
                    if let Some(b) = s.blocks.get(id) {
                        return Some(b.clone());
                    }
                }
                None
            },
            &|path, line| states[path].lines[line].clone(),
            &mut |id| displayed.insert(id.to_string()),
        );
    }

    Ok(true)
}

fn display_recursively(
    root: String,
    indent: usize,
    predecessors: &dyn Fn(&str) -> BTreeSet<String>,
    successors: &dyn Fn(&str) -> BTreeSet<String>,
    block: &dyn Fn(&str) -> Option<Block>,
    line: &dyn Fn(&PathBuf, usize) -> String,
    visit: &mut dyn FnMut(&str) -> bool, // returns true if it's the first visit
) {
    if !visit(&root) {
        // already visited (probably while displaying this graph)
        return;
    }

    let b = match block(&root) {
        Some(b) => b,
        None => {
            eprintln!(
                "{}: unable to find block ID {} in the provided files",
                style("warning").bold().yellow(),
                root,
            );
            return;
        }
    };

    // display the root
    let lines = b
        .lines
        .iter()
        .map(|&l| line(&b.file, l))
        .collect::<Vec<String>>();
    let width = lines
        .iter()
        .map(|l| l.len())
        .max()
        .expect("block with no lines");

    println!();
    let bonus_header = {
        let pred = predecessors(&root);
        if !pred.is_empty() {
            format!(", coming from {:?}", pred)
        } else {
            String::from("")
        }
    };
    println!(
        "{n:indent$}┌─{title:─<width$}─┐",
        n = "",
        title = format!("[ {}{} ]", style(&root).bold(), bonus_header,),
        indent = indent,
        width = width,
    );
    for l in lines {
        println!(
            "{n:indent$}│ {l: <width$} │",
            n = "",
            indent = indent,
            l = l,
            width = width,
        );
    }
    let bonus_footer = {
        let succ = successors(&root);
        if !succ.is_empty() {
            format!(", flowing into {:?}", succ)
        } else {
            String::from("")
        }
    };
    println!(
        "{n:indent$}└─{title:─<width$}─┘",
        n = "",
        title = format!("[ {}{} ]", style(&root).bold(), bonus_footer),
        indent = indent,
        width = width,
    );

    // and display all successors
    for succ_id in successors(&root) {
        display_recursively(
            succ_id,
            indent + 4,
            predecessors,
            successors,
            block,
            line,
            visit,
        );
    }
}

fn main() {
    match run(Opt::from_args()) {
        Ok(()) => (),
        Err(e) => {
            let mut errs = e.chain().rev();
            eprintln!(
                "{}:  {}",
                style("error").for_stderr().bold().red(),
                style(errs.next().expect("got error chain with zero errors"))
                    .for_stderr()
                    .bold(),
            );
            for e in errs {
                eprintln!("  while {}", style(e).for_stderr().bold());
            }
        }
    }
}
