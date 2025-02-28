use std::{
    fmt::{self, Display, Formatter},
    hint::black_box,
    time::{Duration, Instant},
};

/// Measure a function for the given minimum duration.
pub fn measure<A, F: FnMut() -> A>(duration: Duration, mut f: F) -> f64 {
    let total = Instant::now();
    let mut aggregate = f64::INFINITY;
    let mut repeats = 1;
    while total.elapsed() < duration {
        let start = Instant::now();
        for _ in 0..repeats {
            black_box(f());
        }
        let elapsed = start.elapsed().as_secs_f64();
        if elapsed < 1.0e-6 {
            repeats *= 10;
        } else {
            aggregate = aggregate.min(elapsed / repeats as f64);
        }
    }
    aggregate
}

/// Pretty print a float using SI-prefixes.
pub fn human(value: f64) -> impl Display {
    pub struct Human(f64);
    impl Display for Human {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            let log10 = if self.0.is_normal() {
                self.0.abs().log10()
            } else {
                0.0
            };
            let si_power = ((log10 / 3.0).floor() as isize).clamp(-10, 10);
            let value = self.0 * 10_f64.powi((-si_power * 3) as i32);
            let digits = f.precision().unwrap_or(3) - 1 - (log10 - 3.0 * si_power as f64) as usize;
            let separator = if f.alternate() { "" } else { "\u{202F}" };
            write!(f, "{value:.digits$}{separator}")?;
            let suffix = "qryzafpnμm kMGTPEZYRQ"
                .chars()
                .nth((si_power + 10) as usize)
                .unwrap();
            if suffix != ' ' {
                write!(f, "{suffix}")?;
            }
            Ok(())
        }
    }
    Human(value)
}
