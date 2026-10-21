//! Unlock pattern on a 5×5 grid: structure rules, setup policy and canonical encoding.
//!
//! Nodes are numbered row-major: node = y * 5 + x, x/y in 0..5.
//!
//! Structural rules (any pattern that can be tried at unlock):
//! - 1 or 2 strokes, each with 1..=25 nodes, node ids < 25;
//! - no node repeats within a stroke (the second stroke may reuse first-stroke nodes);
//! - a move a→b may only pass over grid nodes already visited in the same stroke
//!   (as on Android: the UI auto-inserts skipped nodes, see [`intermediate_nodes`]).
//!
//! Setup policy (enforced when a pattern is set): ≥ 6 distinct nodes, ≥ 2 direction changes.
//!
//! Canonical encoding (injective, prefix-free):
//! `0x01 (version) || 0x05 (grid size) || stroke_count || for each stroke: len || nodes`.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::secret::SecretVec;

/// Grid side length.
pub const GRID: u8 = 5;
/// Number of nodes on the grid.
pub const NODES: u8 = GRID * GRID;
/// Maximum number of strokes (one optional second stroke).
pub const MAX_STROKES: usize = 2;
/// Minimum distinct nodes at setup.
pub const MIN_NODES: usize = 6;
/// Minimum direction changes at setup.
pub const MIN_DIRECTION_CHANGES: usize = 2;
/// Encoding format version.
pub const ENCODING_VERSION: u8 = 1;

/// Why a pattern was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternError {
    /// Zero or more than [`MAX_STROKES`] strokes.
    StrokeCount,
    /// A stroke is empty.
    EmptyStroke,
    /// Node id ≥ 25.
    NodeOutOfRange,
    /// A node repeats within a stroke.
    RepeatedNode,
    /// A move skips over an unvisited node.
    SkipsNode,
    /// Fewer than [`MIN_NODES`] distinct nodes.
    TooFewNodes,
    /// Fewer than [`MIN_DIRECTION_CHANGES`] direction changes.
    TooFewDirectionChanges,
    /// Encoding is malformed.
    Malformed,
}

/// A (secret) unlock pattern. Zeroized on drop; `Debug` is redacted.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Pattern {
    strokes: Vec<Vec<u8>>,
}

impl fmt::Debug for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pattern([REDACTED])")
    }
}

fn xy(n: u8) -> (i8, i8) {
    ((n % GRID) as i8, (n / GRID) as i8)
}

fn node(x: i8, y: i8) -> u8 {
    debug_assert!((0..GRID as i8).contains(&x) && (0..GRID as i8).contains(&y));
    y as u8 * GRID + x as u8
}

fn gcd(a: i8, b: i8) -> i8 {
    let (mut a, mut b) = (a.abs(), b.abs());
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// Unit direction (dx, dy) / gcd of a move.
pub(crate) fn direction(a: u8, b: u8) -> (i8, i8) {
    let ((ax, ay), (bx, by)) = (xy(a), xy(b));
    let (dx, dy) = (bx - ax, by - ay);
    let g = gcd(dx, dy).max(1);
    (dx / g, dy / g)
}

/// Grid nodes lying strictly between `a` and `b` on the straight segment a→b, in order.
pub fn intermediate_nodes(a: u8, b: u8) -> Vec<u8> {
    let ((ax, ay), (bx, by)) = (xy(a), xy(b));
    let (dx, dy) = (bx - ax, by - ay);
    let g = gcd(dx, dy);
    (1..g.max(1))
        .map(|t| node(ax + dx / g * t, ay + dy / g * t))
        .collect()
}

impl Pattern {
    /// Build a pattern, checking the structural rules.
    pub fn new(strokes: Vec<Vec<u8>>) -> Result<Self, PatternError> {
        let p = Pattern { strokes };
        p.check_structure()?;
        Ok(p)
    }

    /// Build from a stroke list, auto-inserting skipped nodes (what a UI does when the
    /// finger passes over a node). Still checks the structural rules.
    pub fn from_drawn(strokes: Vec<Vec<u8>>) -> Result<Self, PatternError> {
        let mut out = Vec::with_capacity(strokes.len());
        for s in &strokes {
            let mut v: Vec<u8> = Vec::with_capacity(s.len());
            for &n in s {
                if n >= NODES {
                    return Err(PatternError::NodeOutOfRange);
                }
                if let Some(&last) = v.last() {
                    for m in intermediate_nodes(last, n) {
                        if !v.contains(&m) {
                            v.push(m);
                        }
                    }
                }
                v.push(n);
            }
            out.push(v);
        }
        Pattern::new(out)
    }

    /// The strokes.
    pub fn strokes(&self) -> &[Vec<u8>] {
        &self.strokes
    }

    fn check_structure(&self) -> Result<(), PatternError> {
        if self.strokes.is_empty() || self.strokes.len() > MAX_STROKES {
            return Err(PatternError::StrokeCount);
        }
        for s in &self.strokes {
            if s.is_empty() {
                return Err(PatternError::EmptyStroke);
            }
            let mut seen = [false; NODES as usize];
            for (i, &n) in s.iter().enumerate() {
                if n >= NODES {
                    return Err(PatternError::NodeOutOfRange);
                }
                if seen[n as usize] {
                    return Err(PatternError::RepeatedNode);
                }
                if i > 0
                    && intermediate_nodes(s[i - 1], n)
                        .iter()
                        .any(|&m| !seen[m as usize])
                {
                    return Err(PatternError::SkipsNode);
                }
                seen[n as usize] = true;
            }
        }
        Ok(())
    }

    /// Number of distinct nodes across strokes.
    pub fn distinct_nodes(&self) -> usize {
        let mut seen = [false; NODES as usize];
        for &n in self.strokes.iter().flatten() {
            seen[n as usize] = true;
        }
        seen.iter().filter(|&&b| b).count()
    }

    /// Number of direction changes summed over strokes.
    pub fn direction_changes(&self) -> usize {
        self.strokes
            .iter()
            .map(|s| {
                let dirs: Vec<_> = s.windows(2).map(|w| direction(w[0], w[1])).collect();
                dirs.windows(2).filter(|d| d[0] != d[1]).count()
            })
            .sum()
    }

    /// Setup policy: ≥ [`MIN_NODES`] distinct nodes and ≥ [`MIN_DIRECTION_CHANGES`].
    pub fn check_policy(&self) -> Result<(), PatternError> {
        if self.distinct_nodes() < MIN_NODES {
            return Err(PatternError::TooFewNodes);
        }
        if self.direction_changes() < MIN_DIRECTION_CHANGES {
            return Err(PatternError::TooFewDirectionChanges);
        }
        Ok(())
    }

    /// Canonical, injective byte encoding (input to the KDF chain).
    pub fn encode(&self) -> SecretVec {
        let mut v = Vec::with_capacity(3 + self.strokes.len() + 25 * MAX_STROKES);
        v.push(ENCODING_VERSION);
        v.push(GRID);
        v.push(self.strokes.len() as u8);
        for s in &self.strokes {
            v.push(s.len() as u8);
            v.extend_from_slice(s);
        }
        SecretVec::new(v)
    }

    /// Parse a canonical encoding (strict: rejects trailing bytes and invalid structure).
    pub fn decode(bytes: &[u8]) -> Result<Self, PatternError> {
        let mut it = bytes.iter().copied();
        let mut next = || it.next().ok_or(PatternError::Malformed);
        if next()? != ENCODING_VERSION || next()? != GRID {
            return Err(PatternError::Malformed);
        }
        let count = next()? as usize;
        if count == 0 || count > MAX_STROKES {
            return Err(PatternError::StrokeCount);
        }
        let mut strokes = Vec::with_capacity(count);
        for _ in 0..count {
            let len = next()? as usize;
            let mut s = Vec::with_capacity(len);
            for _ in 0..len {
                s.push(next()?);
            }
            strokes.push(s);
        }
        if it.next().is_some() {
            return Err(PatternError::Malformed);
        }
        Pattern::new(strokes)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy producing structurally valid patterns (random walks without skips).
    pub fn arb_pattern() -> impl Strategy<Value = Pattern> {
        let stroke = (0u8..NODES, proptest::collection::vec(0u8..NODES, 0..12));
        proptest::collection::vec(stroke, 1..=2).prop_map(|strokes| {
            let strokes = strokes
                .into_iter()
                .map(|(start, steps)| {
                    let mut s = vec![start];
                    for t in steps {
                        if s.contains(&t) {
                            continue;
                        }
                        let last = *s.last().unwrap();
                        let mut cand = s.clone();
                        for m in intermediate_nodes(last, t) {
                            if !cand.contains(&m) {
                                cand.push(m);
                            }
                        }
                        cand.push(t);
                        s = cand;
                    }
                    s
                })
                .collect();
            Pattern::new(strokes).expect("generated pattern valid")
        })
    }

    #[test]
    fn encoding_vector() {
        let p = Pattern::new(vec![vec![0, 1, 2, 7, 12], vec![24]]).unwrap();
        assert_eq!(&p.encode()[..], &[1, 5, 2, 5, 0, 1, 2, 7, 12, 1, 24]);
    }

    #[test]
    fn structure_rules() {
        assert_eq!(Pattern::new(vec![]), Err(PatternError::StrokeCount));
        assert_eq!(
            Pattern::new(vec![vec![0]; 3]),
            Err(PatternError::StrokeCount)
        );
        assert_eq!(Pattern::new(vec![vec![]]), Err(PatternError::EmptyStroke));
        assert_eq!(
            Pattern::new(vec![vec![25]]),
            Err(PatternError::NodeOutOfRange)
        );
        assert_eq!(
            Pattern::new(vec![vec![0, 1, 0]]),
            Err(PatternError::RepeatedNode)
        );
        // 0 -> 2 passes over 1.
        assert_eq!(Pattern::new(vec![vec![0, 2]]), Err(PatternError::SkipsNode));
        assert!(Pattern::new(vec![vec![1, 0, 2]]).is_ok());
        // 0 -> 24 passes 6, 12, 18; 0 -> 7 (knight-like) passes nothing.
        assert_eq!(
            Pattern::new(vec![vec![0, 24]]),
            Err(PatternError::SkipsNode)
        );
        assert!(Pattern::new(vec![vec![0, 7]]).is_ok());
        // Second stroke may reuse nodes.
        assert!(Pattern::new(vec![vec![0, 1], vec![1, 0]]).is_ok());
        assert_eq!(
            Pattern::from_drawn(vec![vec![0, 24]]).unwrap().strokes(),
            &[vec![0, 6, 12, 18, 24]]
        );
    }

    #[test]
    fn policy() {
        // Straight line: 0 direction changes.
        let line = Pattern::new(vec![vec![0, 1, 2, 3, 4]]).unwrap();
        assert_eq!(line.direction_changes(), 0);
        assert_eq!(line.check_policy(), Err(PatternError::TooFewNodes));
        let l = Pattern::new(vec![vec![0, 1, 2, 3, 4, 9, 14]]).unwrap();
        assert_eq!(l.check_policy(), Err(PatternError::TooFewDirectionChanges));
        let ok = Pattern::new(vec![vec![0, 1, 2, 7, 12, 13]]).unwrap();
        assert_eq!(ok.direction_changes(), 2);
        assert_eq!(ok.check_policy(), Ok(()));
    }

    #[test]
    fn decode_rejects_malformed() {
        assert_eq!(Pattern::decode(&[]), Err(PatternError::Malformed));
        assert_eq!(
            Pattern::decode(&[2, 5, 1, 1, 0]),
            Err(PatternError::Malformed)
        );
        assert_eq!(
            Pattern::decode(&[1, 4, 1, 1, 0]),
            Err(PatternError::Malformed)
        );
        assert_eq!(
            Pattern::decode(&[1, 5, 1, 1, 0, 0]),
            Err(PatternError::Malformed)
        );
        assert_eq!(
            Pattern::decode(&[1, 5, 1, 2, 0]),
            Err(PatternError::Malformed)
        );
        assert_eq!(Pattern::decode(&[1, 5, 3]), Err(PatternError::StrokeCount));
    }

    proptest! {
        #[test]
        fn encode_decode_roundtrip(p in arb_pattern()) {
            let e = p.encode();
            prop_assert_eq!(Pattern::decode(&e).unwrap(), p);
        }

        #[test]
        fn encoding_injective(a in arb_pattern(), b in arb_pattern()) {
            prop_assert_eq!(a == b, a.encode()[..] == b.encode()[..]);
        }

        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            if let Ok(p) = Pattern::decode(&bytes) {
                prop_assert_eq!(&p.encode()[..], &bytes[..]);
            }
        }
    }
}
