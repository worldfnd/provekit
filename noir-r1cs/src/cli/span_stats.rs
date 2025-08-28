//! Using `tracing` spans to print performance statistics for the program.
//!
//! NOTE: This module is only included in the bin, not in the lib.
use {
    crate::ALLOC_STATE,
    noir_r1cs::human,
    std::{
        cmp::max,
        fmt::{self, Write as _},
        time::Instant,
    },
    tracing::{
        field::{Field, Visit},
        span::{Attributes, Id},
        Level, Subscriber,
    },
    tracing_subscriber::{self, layer::Context, registry::LookupSpan, Layer},
};

const DIM: &str = "\x1b[2m";
const UNDIM: &str = "\x1b[22m";

// Span extension data
pub struct Data {
    depth:       usize,
    time:        Instant,
    memory:      usize,
    allocations: usize,

    /// `peak_memory` will be updated as it is not monotonic
    peak_memory: usize,
    children:    bool,
    kvs:         Vec<(&'static str, String)>,
}

impl Data {
    pub fn new(attrs: &Attributes<'_>, depth: usize) -> Self {
        let mut span = Self {
            depth,
            time: Instant::now(),
            memory: ALLOC_STATE.current(),
            allocations: ALLOC_STATE.count(),
            peak_memory: ALLOC_STATE.current(),
            children: false,
            kvs: Vec::new(),
        };
        attrs.record(&mut span);
        span
    }
}

impl Visit for Data {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.kvs.push((field.name(), format!("{value:?}")));
    }
}

pub struct FmtEvent<'a>(&'a mut String);

impl Visit for FmtEvent<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        match field.name() {
            "message" => {
                write!(self.0, " {value:?}").unwrap();
            }
            name => {
                write!(self.0, " {name}={value:?}").unwrap();
            }
        }
    }
}

/// Logging layer that keeps track of time and memory consumption of spans.
pub struct SpanStats;

impl<S> Layer<S> for SpanStats
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_new_span(&self, attrs: &Attributes, id: &Id, ctx: Context<S>) {
        let span = ctx.span(id).expect("invalid span in on_new_span");

        // Update parent
        if let Some(parent) = span.parent() {
            if let Some(data) = parent.extensions_mut().get_mut::<Data>() {
                data.children = true;
                data.peak_memory = max(data.peak_memory, ALLOC_STATE.max());
            }
        }
        ALLOC_STATE.reset_max();

        // Add Data if it hasn't already
        if span.extensions().get::<Data>().is_none() {
            let depth = span.parent().map_or(0, |s| {
                s.extensions()
                    .get::<Data>()
                    .expect("parent span has no data")
                    .depth
                    + 1
            });
            let data = Data::new(attrs, depth);
            span.extensions_mut().insert(data);
        }

        // Fetch data
        let ext = span.extensions();
        let data = ext.get::<Data>().expect("span does not have data");

        let mut buffer = String::with_capacity(100);

        // Box draw tree indentation
        if data.depth >= 1 {
            for _ in 0..(data.depth - 1) {
                let _ = write!(&mut buffer, "│ ");
            }
            let _ = write!(&mut buffer, "├─");
        }
        let _ = write!(&mut buffer, "╮ ");

        // Span name
        let _ = write!(
            &mut buffer,
            "{DIM}{}::{UNDIM}{}",
            span.metadata().target(),
            span.metadata().name()
        );

        // KV args
        for (key, val) in &data.kvs {
            let _ = write!(&mut buffer, " {key}={val}");
        }

        eprintln!("{buffer}");
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        let span = ctx.current_span().id().and_then(|id| ctx.span(id));

        let mut buffer = String::with_capacity(100);

        // Span indentation + time in span
        if let Some(span) = &span {
            // Flag child on parent
            if let Some(parent) = span.parent() {
                if let Some(data) = parent.extensions_mut().get_mut::<Data>() {
                    data.children = true;
                }
            }

            if let Some(data) = span.extensions().get::<Data>() {
                // Box draw tree indentation
                for _ in 0..=data.depth {
                    let _ = write!(&mut buffer, "│ ");
                }

                // Time
                let elapsed = data.time.elapsed();
                let _ = write!(
                    &mut buffer,
                    "{DIM}{:6}s {UNDIM}",
                    human(elapsed.as_secs_f64())
                );
            }
        }

        // Log level
        match *event.metadata().level() {
            Level::TRACE => write!(&mut buffer, "TRACE"),
            Level::DEBUG => write!(&mut buffer, "DEBUG"),
            Level::INFO => write!(&mut buffer, "\x1b[1;32mINFO\x1b[0m"),
            Level::WARN => write!(&mut buffer, "\x1b[1;38;5;208mWARN\x1b[0m"),
            Level::ERROR => write!(&mut buffer, "\x1b[1;31mERROR\x1b[0m"),
        }
        .unwrap();

        let mut visitor = FmtEvent(&mut buffer);
        event.record(&mut visitor);

        eprintln!("{buffer}");
    }

    fn on_close(&self, id: Id, ctx: Context<S>) {
        let span = ctx.span(&id).expect("invalid span in on_close");
        let ext = span.extensions();
        let data = ext.get::<Data>().expect("span does not have data");

        let duration = data.time.elapsed();
        let peak_memory: usize = std::cmp::max(ALLOC_STATE.max(), data.peak_memory);
        let allocations = ALLOC_STATE.count() - data.allocations;
        let own = peak_memory - data.memory;

        // Update parent
        if let Some(parent) = span.parent() {
            if let Some(data) = parent.extensions_mut().get_mut::<Data>() {
                data.peak_memory = max(data.peak_memory, peak_memory);
            }
        }

        let mut buffer = String::with_capacity(100);

        // Box draw tree indentation
        if data.depth >= 1 {
            for _ in 0..(data.depth - 1) {
                let _ = write!(&mut buffer, "│ ");
            }
            let _ = write!(&mut buffer, "├─");
        }
        let _ = write!(&mut buffer, "╯ ");

        // Short span name if not childless
        if data.children {
            let _ = write!(&mut buffer, "{DIM}{}: {UNDIM}", span.metadata().name());
        }

        // Print stats
        let _ = write!(
            &mut buffer,
            "{}s{DIM} duration, {UNDIM}{}B{DIM} peak memory, {UNDIM}{}B{DIM} local, \
             {UNDIM}{:#}{DIM} allocations{UNDIM}",
            human(duration.as_secs_f64()),
            human(peak_memory as f64),
            human(own as f64),
            human(allocations as f64)
        );

        eprintln!("{buffer}");
    }
}
