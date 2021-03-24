use std::{
    collections::{BTreeSet, HashMap, HashSet},
    io::BufRead,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
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
                                            |next_id: &str| (None, None, Some(next_id.to_string())),
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
    // the postfix id of this block
    id: String,

    // all the lines in which this postfix-id appears (and which file they were in)
    lines: HashMap<&'static Path, BTreeSet<usize>>,

    // all the previous id's
    previous_ids: HashSet<String>,

    // all the next id's
    next_ids: HashSet<String>,
}

#[derive(Clone)]
struct State {
    // all the lines in the log files
    lines: HashMap<&'static Path, HashMap<usize, String>>,

    // message-id => all the postfix-id's where it appears
    message_ids: HashMap<String, Vec<String>>,

    // postfix-id => block
    blocks: HashMap<String, Block>,
}

impl State {
    fn empty() -> State {
        State {
            lines: HashMap::new(),
            message_ids: HashMap::new(),
            blocks: HashMap::new(),
        }
    }

    fn from_line(file: &'static Path, lineno: usize, line: String) -> Result<State, ()> {
        let parsed = ParsedLine::parse(&line);

        match parsed {
            ParsedLine::Postfix {
                id,
                message_id,
                previous_id,
                next_id,
            } => {
                // Prepare the Block
                let block = {
                    let id = id.clone();

                    let lines = {
                        let mut file_lines = BTreeSet::new();
                        file_lines.insert(lineno);

                        let mut lines = HashMap::new();
                        lines.insert(file, file_lines);
                        lines
                    };

                    let mut previous_ids = HashSet::new();
                    if let Some(pid) = previous_id {
                        previous_ids.insert(pid);
                    }

                    let mut next_ids = HashSet::new();
                    if let Some(nid) = next_id {
                        next_ids.insert(nid);
                    }

                    Block {
                        id,
                        lines,
                        previous_ids,
                        next_ids,
                    }
                };

                // Prepare the State
                let lines = {
                    let mut file_lines = HashMap::new();
                    file_lines.insert(lineno, line);

                    let mut lines = HashMap::new();
                    lines.insert(file, file_lines);
                    lines
                };

                let mut message_ids = HashMap::new();
                if let Some(mid) = message_id {
                    message_ids.insert(mid, vec![id.clone()]);
                }

                let mut blocks = HashMap::new();
                blocks.insert(id, block);

                Ok(State {
                    lines,
                    message_ids,
                    blocks,
                })
            }

            ParsedLine::Useless => Ok(State::empty()),
            ParsedLine::Unknown => Err(()),
        }
    }

    fn merge(mut a: State, b: State) -> State {
        for (path, lines) in b.lines {
            let emplace = a.lines.entry(path).or_insert_with(HashMap::new);
            for (lineno, line) in lines {
                emplace.insert(lineno, line);
            }
        }

        for (mid, ids) in b.message_ids {
            a.message_ids
                .entry(mid)
                .or_insert_with(Vec::new)
                .extend(ids);
        }

        for (id, block) in b.blocks {
            match a.blocks.entry(id) {
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(block);
                }
                std::collections::hash_map::Entry::Occupied(mut o) => {
                    let emplace = o.get_mut();
                    for (path, mut lines) in block.lines {
                        emplace
                            .lines
                            .entry(path)
                            .or_insert_with(BTreeSet::new)
                            .append(&mut lines);
                    }
                    for id in block.previous_ids {
                        emplace.previous_ids.insert(id);
                    }
                    for id in block.next_ids {
                        emplace.next_ids.insert(id);
                    }
                }
            }
        }

        a
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
    let state = opt
        .files
        .iter()
        .map(|f| &*Box::leak(f.clone().into_boxed_path()))
        .zip(bars.into_iter())
        .par_bridge()
        .map(|(file, bar)| -> anyhow::Result<State> {
            let f = std::fs::File::open(file)
                .with_context(|| format!("opening log file {:?}", file))?;
            let f = std::io::BufReader::new(f);

            let accumulated_size = AtomicU64::new(0);
            let showed_message = AtomicBool::new(false);
            let res = f
                .lines()
                .enumerate()
                .par_bridge()
                .map(|(lineno, line)| -> anyhow::Result<State> {
                    let line = line.with_context(|| format!("reading file {:?}", file))?;
                    let new_pos =
                        accumulated_size.fetch_add(line.len() as u64 + 1, Ordering::Relaxed);
                    if new_pos % (bar.length() / 2048) < 3 * line.len() as u64 {
                        // this heuristics… appears to work in practice
                        bar.set_position(new_pos);
                    }
                    match State::from_line(file, lineno, line.clone()) {
                        Ok(s) => Ok(s),
                        Err(()) => {
                            if !showed_message.fetch_or(true, Ordering::Relaxed) {
                                bar.set_message(&format!(
                                    "{}: unable to parse line: {}",
                                    style("warning").bold().yellow(),
                                    line
                                ));
                            }
                            Ok(State::empty())
                        }
                    }
                })
                .reduce(|| Ok(State::empty()), |a, b| Ok(State::merge(a?, b?)))?;
            bar.finish();
            Ok(res)
        })
        .reduce(|| Ok(State::empty()), |a, b| Ok(State::merge(a?, b?)))
        .context("parsing the log files")?;

    if !display(&opt.message_id, &state).context("displaying the result")? {
        eprintln!(
            "{}: found no mail with the requested message-id, trying with ‘<{}>’",
            style("warning").bold().yellow(),
            opt.message_id
        );
        let bracketed_mid = String::from("<") + &opt.message_id + ">";
        if !display(&bracketed_mid, &state).context("displaying the result")? {
            bail!("found logs for neither ‘{0}’ nor ‘<{0}>’", opt.message_id);
        }
    }

    Ok(())
}

fn display(message_id: &str, state: &State) -> anyhow::Result<bool> {
    // Search the states for the blocks that are relevant to the message-id
    let blocks = state
        .message_ids
        .get(message_id)
        .iter()
        .flat_map(|ids| {
            ids.iter()
                .filter_map(|id| state.blocks.get(id).map(|b| (b.id.clone(), b.clone())))
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
        state
            .blocks
            .get(id)
            .iter()
            .flat_map(|b| b.previous_ids.iter().cloned())
            // and then, get all the blocks that point to this by next-id
            .chain(state.blocks.iter().filter_map(move |(b_id, b)| {
                if b.next_ids.contains(id) {
                    Some(b_id.clone())
                } else {
                    None
                }
            }))
            .collect::<BTreeSet<String>>()
    };
    let successors = |id: &str| {
        // get all the blocks pointed to by next-id
        state
            .blocks
            .get(id)
            .iter()
            .flat_map(|b| b.next_ids.iter().cloned())
            // and then, get all the blocks that point to this by previous-id
            .chain(state.blocks.iter().filter_map(move |(b_id, b)| {
                if b.previous_ids.contains(id) {
                    Some(b_id.clone())
                } else {
                    None
                }
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
            &|id| state.blocks.get(id).cloned(),
            &|path, line| state.lines[path][&line].clone(),
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
    line: &dyn Fn(&'static Path, usize) -> String,
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
        .flat_map(|(&path, lines)| lines.iter().map(move |&l| line(path, l)))
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
