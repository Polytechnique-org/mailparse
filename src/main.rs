use std::{
    collections::{HashMap, HashSet},
    io::BufRead,
    path::PathBuf,
};

use anyhow::{ensure, Context};
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
    fn parse(line: &str) -> ParsedLine {
        use nom::{
            branch::alt,
            bytes::complete::{is_a, tag, take, take_until},
            combinator::{eof, map, opt, rest, value},
            sequence::{delimited, preceded, tuple},
        };
        let res: nom::IResult<&str, ParsedLine> = preceded(
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
                            )),
                        ),
                        // Log lines that begin with an identifier
                        map(
                            tuple((
                                map(
                                    is_a("0123456789ABCDEF"),
                                    |s: &str| s.to_string()
                                ),
                                tag(": "),
                                alt((
                                    // Log lines with nothing
                                    value((None, None, None), tuple((tag("removed"), eof))),
                                    value(
                                        (None, None, None),
                                        alt((
                                            tag("enabling PIX workarounds: "),
                                            tag("lost connection with "),
                                            tag("discard: "),
                                            tag("reject: "),
                                            tag("filter: "),
                                        )),
                                    ),
                                    value(
                                        (None, None, None),
                                        tuple((
                                            tag("uid="),
                                            is_a("0123456789"),
                                            tag(" from=<"),
                                            take_until(">"),
                                            tag(">"),
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
                                            tag(" (queue active)"),
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
                                            eof
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
                                    preceded(
                                        tuple((
                                            opt(tag("resent-")), // consider resent-message-id like message-id
                                            tag("message-id="),
                                        )),
                                        map(
                                            rest,
                                            |message_id: &str| (Some(message_id.to_string()), None, None),
                                        ),
                                    ),
                                    delimited(
                                        tag("sender non-delivery notification: "),
                                        map(
                                            is_a("0123456789ABCDEF"),
                                            |previous_id: &str| (None, Some(previous_id.to_string()), None),
                                        ),
                                        eof,
                                    ),
                                    delimited(
                                        tuple((
                                            tag("client="),
                                            take_until(","),
                                            tag(", orig_queue_id="),
                                        )),
                                        map(
                                            is_a("0123456789ABCDEF"),
                                            |previous_id: &str| (None, Some(previous_id.to_string()), None),
                                        ),
                                        tuple((
                                            tag(", orig_client="),
                                            is_a("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-[]"),
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
                                                    |next_id: &str| (None, None, Some(next_id.to_string()))
                                                ),
                                                tuple((tag(")"), eof)),
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
                // panic!("parse err in line {:?}:\n{:?}", line, _e);
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

    fn eat(&mut self, line: String) -> Result<(), ()> {
        let this_line = self.lines.len();
        let parsed = ParsedLine::parse(&line);

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
            self.lines.push(line);
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
            let f = std::io::BufReader::new(f);

            let mut accumulated_size = 0u64;
            let mut state = State::new(file.clone());
            let mut showed_message = false;
            for l in f.lines() {
                // Parse the line
                let l = l.with_context(|| format!("reading file {:?}", file))?;
                accumulated_size += (l.len() + 1) as u64;
                if state.eat(l.clone()).is_err() && !showed_message {
                    bar.set_message(&format!(
                        "{}: unable to parse line: {}",
                        style("warning").bold().yellow(),
                        l,
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

    // Search the states for the blocks that are relevant to the message-id
    let blocks = states
        .iter()
        .flat_map(|(_, s)| {
            s.message_ids
                .get(&opt.message_id)
                .into_iter()
                .flat_map(|ids| {
                    ids.iter()
                        .filter_map(|id| s.blocks.get(id).map(|blocks| blocks.clone()))
                })
                .collect::<Vec<Block>>()
                .into_iter()
        })
        .collect::<Vec<Block>>();

    // Toposort the blocks
    // TODO: this currently causes more issues than it solves
    // problems, as the logs are usually ordered and this introduces
    // randomness
    /*
       let successors = |id: &String| {
           // get all the blocks pointed to by next-id
           states
               .iter()
               .flat_map(move |s| {
                   s.blocks
                       .get(id)
                       .into_iter()
                       .flat_map(|b| b.next_ids.iter().cloned())
               })
               // and then, get all the blocks that point to this by previous-id
               .chain(states.iter().flat_map(move |s| {
                   s.blocks.iter().filter_map(move |(b_id, b)| {
                       if b.previous_ids.contains(id) {
                           Some(b_id.clone())
                       } else {
                           None
                       }
                   })
               }))
               .collect::<Vec<String>>()
       };
       let sorted_blocks = pathfinding::directed::topological_sort::topological_sort(
           &blocks.iter().map(|b| b.id.clone()).collect::<Vec<String>>(),
           successors,
       )
       .map_err(|id| {
           anyhow!(
               "Failed to toposort the blocks: a loop was found with id {}",
               id
           )
       })?;
       println!("{:?}", sorted_blocks);
    */

    for b in blocks {
        let s = states
            .get(&b.file)
            .expect("retrieving state for a known-good filename");
        println!(
            "{}",
            style(format!(
                "Queued with id {} in file {:?} around lines {}-{}\n\
                 --------------",
                b.id,
                b.file,
                b.lines.first().expect("block has zero lines"),
                b.lines.last().expect("block has zero lines")
            ))
            .bold(),
        );
        for l in b.lines {
            println!("    {}", s.lines[l]);
        }
        println!();
    }

    Ok(())
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
