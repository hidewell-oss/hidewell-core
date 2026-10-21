//! Pattern strength: a programmatically generated blocklist of common shapes and a
//! simple guess-rank meter.
//!
//! # Blocklist
//! Generated once from shape families, each expanded to node sequences (skipped nodes
//! auto-inserted) and closed under the 8 grid symmetries (rotations/reflections) and
//! stroke reversal:
//! - straight lines (all segments of ≥ 3 nodes), L shapes (all arm lengths/positions);
//! - rectangle borders (perimeter minus the closing edge, every start corner and
//!   direction) and U/C shapes (three sides);
//! - Z/N shapes over every rectangle;
//! - letter/digit templates (C, L, U, V, M, W, S, 2, 7, J, G, Z, N) at full size and at
//!   half size in every position;
//! - spirals and snakes (boustrophedon) from every corner, all prefixes ≥ 6 nodes;
//! - two-stroke shapes: X, +, T, =, || (all positions/sizes on the 5×5 and 3×3 scale).
//!
//! # Meter (guess-rank model)
//! Models an attacker who tries likelier patterns first. The estimated guess rank is
//! `2^bits`, where `bits = -log2 P(pattern)` under this model:
//! - start node: corners 40 % (10 % each), other border nodes 40 % (shared), inner 20 %;
//! - each next node: classes "continue straight" 50 %, "adjacent turn" (Chebyshev
//!   distance 1) 40 %, "far move" 10 % (renormalised over classes with ≥ 1 legal
//!   candidate); uniform within a class;
//! - a second stroke costs 1 extra bit plus its own path cost.
//!
//! Blocklisted patterns get rank ≈ their index in the (small) blocklist, i.e. a few
//! thousand guesses at most. The model is intentionally simple, deterministic and
//! documented; it is a UX meter, not a security proof.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::pattern::{GRID, NODES, Pattern, direction, intermediate_nodes};

/// Coarse strength rating.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    /// Blocklisted or < 14 bits.
    Weak,
    /// 14..20 bits.
    Fair,
    /// 20..26 bits.
    Good,
    /// ≥ 26 bits.
    Strong,
}

/// Stable identifier of a blocklisted shape family, for app copy such as
/// "Too common: U shape". Apps map identifiers to localised strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockedShape {
    /// Straight line.
    Line,
    /// L shape (two sides of a rectangle).
    LShape,
    /// U / C shape (three sides of a rectangle).
    UShape,
    /// Square or rectangle border.
    Square,
    /// Z shape.
    ZShape,
    /// N shape (reserved: N is a rotation of Z, so patterns report `ZShape`).
    NShape,
    /// Letter C (reserved: C is a rotation of U, so patterns report `UShape`).
    CShape,
    /// Letter V.
    VShape,
    /// Letter M.
    MShape,
    /// Letter W.
    WShape,
    /// Letter S (and its mirror, the digit 2).
    SShape,
    /// Digit 2 (reserved: 2 is a mirror of S, so patterns report `SShape`).
    Digit2,
    /// Digit 7.
    Digit7,
    /// Letter J.
    JShape,
    /// Letter G.
    GShape,
    /// Spiral.
    Spiral,
    /// Snake (row-by-row zigzag).
    Snake,
    /// Two diagonals (X).
    Cross,
    /// Plus sign.
    Plus,
    /// Letter T (two strokes).
    TShape,
    /// Two parallel horizontal lines (=).
    Equals,
    /// Two parallel vertical lines (||).
    Bars,
}

/// Result of a strength check.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StrengthReport {
    /// Pattern matches a blocklisted shape.
    pub blocklisted: bool,
    /// Which shape family, if blocklisted.
    pub blocked_shape: Option<BlockedShape>,
    /// log2 of the estimated guess rank.
    pub guess_rank_log2: f64,
    /// Rating derived from `guess_rank_log2`.
    pub strength: Strength,
}

/// Evaluate a pattern.
pub fn evaluate(p: &Pattern) -> StrengthReport {
    let bl = blocklist();
    let blocked_shape = bl.get(p.strokes()).copied();
    let blocklisted = blocked_shape.is_some();
    let bits = if blocklisted {
        (bl.len() as f64).log2()
    } else {
        model_bits(p)
    };
    let strength = match bits {
        _ if blocklisted => Strength::Weak,
        b if b < 14.0 => Strength::Weak,
        b if b < 20.0 => Strength::Fair,
        b if b < 26.0 => Strength::Good,
        _ => Strength::Strong,
    };
    StrengthReport {
        blocklisted,
        blocked_shape,
        guess_rank_log2: bits,
        strength,
    }
}

/// True if the pattern is a blocklisted common shape.
pub fn is_blocklisted(p: &Pattern) -> bool {
    blocklist().contains_key(p.strokes())
}

/// The blocklisted shape family the pattern matches, if any.
pub fn blocked_shape(p: &Pattern) -> Option<BlockedShape> {
    blocklist().get(p.strokes()).copied()
}

fn xy(n: u8) -> (i8, i8) {
    ((n % GRID) as i8, (n / GRID) as i8)
}

fn is_border(n: u8) -> bool {
    let (x, y) = xy(n);
    x == 0 || y == 0 || x == GRID as i8 - 1 || y == GRID as i8 - 1
}

fn is_corner(n: u8) -> bool {
    let (x, y) = xy(n);
    (x == 0 || x == GRID as i8 - 1) && (y == 0 || y == GRID as i8 - 1)
}

fn start_prob(n: u8) -> f64 {
    if is_corner(n) {
        0.1
    } else if is_border(n) {
        0.4 / 12.0
    } else {
        0.2 / 9.0
    }
}

fn stroke_bits(s: &[u8]) -> f64 {
    let mut bits = -start_prob(s[0]).log2();
    let mut visited = [false; NODES as usize];
    visited[s[0] as usize] = true;
    for i in 1..s.len() {
        let cur = s[i - 1];
        let prev_dir = (i >= 2).then(|| direction(s[i - 2], cur));
        let (cx, cy) = xy(cur);
        let class = |n: u8| -> u8 {
            let (nx, ny) = xy(n);
            if prev_dir == Some(direction(cur, n)) {
                0
            } else if (nx - cx).abs() <= 1 && (ny - cy).abs() <= 1 {
                1
            } else {
                2
            }
        };
        let mut counts = [0usize; 3];
        for n in 0..NODES {
            let legal = !visited[n as usize]
                && intermediate_nodes(cur, n)
                    .iter()
                    .all(|&m| visited[m as usize]);
            if legal {
                counts[class(n) as usize] += 1;
            }
        }
        let weights = [0.5, 0.4, 0.1];
        let total: f64 = (0..3).filter(|&c| counts[c] > 0).map(|c| weights[c]).sum();
        let c = class(s[i]) as usize;
        debug_assert!(counts[c] > 0, "move must be legal");
        let p = weights[c] / total / counts[c] as f64;
        bits -= p.log2();
        visited[s[i] as usize] = true;
    }
    bits
}

fn model_bits(p: &Pattern) -> f64 {
    let extra = if p.strokes().len() > 1 { 1.0 } else { 0.0 };
    extra + p.strokes().iter().map(|s| stroke_bits(s)).sum::<f64>()
}

// ---------------------------------------------------------------------------
// Blocklist generation
// ---------------------------------------------------------------------------

type Pt = (i8, i8);

/// The 8 symmetries of the square grid.
fn symmetries(p: Pt) -> [Pt; 8] {
    let m = GRID as i8 - 1;
    let (x, y) = p;
    [
        (x, y),
        (m - y, x),
        (m - x, m - y),
        (y, m - x),
        (m - x, y),
        (x, m - y),
        (y, x),
        (m - y, m - x),
    ]
}

fn in_grid(p: Pt) -> bool {
    (0..GRID as i8).contains(&p.0) && (0..GRID as i8).contains(&p.1)
}

/// Expand a polyline (vertices) into a node sequence with skipped nodes inserted.
/// Returns None if out of grid or self-intersecting at a node.
fn polyline_nodes(vs: &[Pt]) -> Option<Vec<u8>> {
    if !vs.iter().all(|&p| in_grid(p)) {
        return None;
    }
    let nodes: Vec<u8> = vs.iter().map(|&(x, y)| y as u8 * GRID + x as u8).collect();
    let mut out: Vec<u8> = vec![nodes[0]];
    for w in nodes.windows(2) {
        if w[0] == w[1] {
            continue;
        }
        for m in intermediate_nodes(w[0], w[1]) {
            if out.contains(&m) {
                return None;
            }
            out.push(m);
        }
        if out.contains(&w[1]) {
            return None;
        }
        out.push(w[1]);
    }
    Some(out)
}

struct Builder {
    /// Pattern → shape family; the first family that generates a pattern names it.
    set: HashMap<Vec<Vec<u8>>, BlockedShape>,
    shape: BlockedShape,
}

impl Builder {
    /// Insert a shape given as polylines (one per stroke) under all symmetries and
    /// stroke reversals.
    fn add(&mut self, strokes: &[Vec<Pt>]) {
        for sym in 0..8 {
            let t: Vec<Vec<Pt>> = strokes
                .iter()
                .map(|s| s.iter().map(|&p| symmetries(p)[sym]).collect())
                .collect();
            let Some(nodes) = t
                .iter()
                .map(|s| polyline_nodes(s))
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            // Every combination of stroke reversals and both stroke orders.
            let n = nodes.len();
            for rev_mask in 0..(1u8 << n) {
                let v: Vec<Vec<u8>> = nodes
                    .iter()
                    .enumerate()
                    .map(|(i, s)| {
                        let mut s = s.clone();
                        if rev_mask & (1 << i) != 0 {
                            s.reverse();
                        }
                        s
                    })
                    .collect();
                if n == 2 {
                    self.insert(vec![v[1].clone(), v[0].clone()]);
                }
                self.insert(v);
            }
        }
    }

    fn insert(&mut self, strokes: Vec<Vec<u8>>) {
        if Pattern::new(strokes.clone()).is_ok() {
            self.set.entry(strokes).or_insert(self.shape);
        }
    }

    fn add_as(&mut self, shape: BlockedShape, strokes: &[Vec<Pt>]) {
        self.shape = shape;
        self.add(strokes);
    }
}

/// Letter/digit templates on a 0..=4 box.
const TEMPLATES: &[(BlockedShape, &[Pt])] = &[
    (BlockedShape::CShape, &[(4, 0), (0, 0), (0, 4), (4, 4)]),
    (BlockedShape::LShape, &[(0, 0), (0, 4), (4, 4)]),
    (BlockedShape::UShape, &[(0, 0), (0, 4), (4, 4), (4, 0)]),
    (BlockedShape::VShape, &[(0, 0), (2, 4), (4, 0)]),
    (
        BlockedShape::MShape,
        &[(0, 4), (0, 0), (2, 2), (4, 0), (4, 4)],
    ),
    (
        BlockedShape::WShape,
        &[(0, 0), (1, 4), (2, 2), (3, 4), (4, 0)],
    ),
    (
        BlockedShape::WShape,
        &[(0, 0), (1, 4), (2, 0), (3, 4), (4, 0)],
    ),
    (
        BlockedShape::SShape,
        &[(4, 0), (0, 0), (0, 2), (4, 2), (4, 4), (0, 4)],
    ),
    (
        BlockedShape::Digit2,
        &[(0, 0), (4, 0), (4, 2), (0, 2), (0, 4), (4, 4)],
    ),
    (BlockedShape::Digit7, &[(0, 0), (4, 0), (0, 4)]),
    (BlockedShape::JShape, &[(4, 0), (4, 4), (0, 4), (0, 2)]),
    (
        BlockedShape::GShape,
        &[(4, 0), (0, 0), (0, 4), (4, 4), (4, 2), (2, 2)],
    ),
    (BlockedShape::ZShape, &[(0, 0), (4, 0), (0, 4), (4, 4)]),
    (BlockedShape::NShape, &[(0, 4), (0, 0), (4, 4), (4, 0)]),
    (
        BlockedShape::Spiral,
        &[(0, 0), (4, 0), (4, 4), (0, 4), (0, 1), (3, 1), (3, 3)],
    ),
];

fn build_blocklist() -> HashMap<Vec<Vec<u8>>, BlockedShape> {
    let mut b = Builder {
        set: HashMap::new(),
        shape: BlockedShape::Line,
    };
    let g = GRID as i8;

    // Straight lines: every segment with ≥ 3 nodes in the 8 lattice directions.
    for x0 in 0..g {
        for y0 in 0..g {
            for (dx, dy) in [(1, 0), (0, 1), (1, 1), (1, -1)] {
                for len in 2..g {
                    let end = (x0 + dx * len, y0 + dy * len);
                    b.add_as(BlockedShape::Line, &[vec![(x0, y0), end]]);
                }
            }
        }
    }

    // Rectangles: L shapes, U shapes, borders, Z/N.
    for x0 in 0..g {
        for y0 in 0..g {
            for x1 in x0 + 1..g {
                for y1 in y0 + 1..g {
                    let (a, bb, c, d) = ((x0, y0), (x1, y0), (x1, y1), (x0, y1));
                    b.add_as(BlockedShape::LShape, &[vec![a, bb, c]]);
                    b.add_as(BlockedShape::UShape, &[vec![a, bb, c, d]]);
                    // Border: perimeter minus closing edge, ending one node before start.
                    let ring_pts = ring(a, bb, c, d);
                    for start in 0..ring_pts.len() {
                        let mut v = ring_pts.clone();
                        v.rotate_left(start);
                        b.add_as(BlockedShape::Square, &[v]);
                    }
                    b.add_as(BlockedShape::ZShape, &[vec![a, bb, d, c]]);
                    b.add_as(BlockedShape::NShape, &[vec![d, a, c, bb]]);
                }
            }
        }
    }

    // Templates at full size and at half size in every position.
    for &(shape, t) in TEMPLATES {
        b.add_as(shape, &[t.to_vec()]);
        if t.iter().all(|&(x, y)| x % 2 == 0 && y % 2 == 0) {
            for ox in 0..3 {
                for oy in 0..3 {
                    b.add(&[t.iter().map(|&(x, y)| (x / 2 + ox, y / 2 + oy)).collect()]);
                }
            }
        }
    }

    // Spirals and snakes from every corner (symmetries cover corners/directions);
    // all prefixes with ≥ 6 nodes.
    for (shape, walk) in [
        (BlockedShape::Spiral, spiral_walk()),
        (BlockedShape::Snake, snake_walk()),
    ] {
        for len in 6..=walk.len() {
            b.add_as(shape, &[walk[..len].to_vec()]);
        }
    }

    // Two-stroke shapes at full and half scale, every position.
    for s in [4i8, 2] {
        for ox in 0..=(g - 1 - s) {
            for oy in 0..=(g - 1 - s) {
                let h = s / 2;
                let shapes: [(BlockedShape, [Vec<Pt>; 2]); 5] = [
                    (
                        BlockedShape::Cross,
                        [
                            vec![(ox, oy), (ox + s, oy + s)],
                            vec![(ox + s, oy), (ox, oy + s)],
                        ],
                    ),
                    (
                        BlockedShape::Plus,
                        [
                            vec![(ox + h, oy), (ox + h, oy + s)],
                            vec![(ox, oy + h), (ox + s, oy + h)],
                        ],
                    ),
                    (
                        BlockedShape::TShape,
                        [
                            vec![(ox, oy), (ox + s, oy)],
                            vec![(ox + h, oy), (ox + h, oy + s)],
                        ],
                    ),
                    (
                        BlockedShape::Equals,
                        [
                            vec![(ox, oy), (ox + s, oy)],
                            vec![(ox, oy + s), (ox + s, oy + s)],
                        ],
                    ),
                    (
                        BlockedShape::Bars,
                        [
                            vec![(ox, oy), (ox, oy + s)],
                            vec![(ox + s, oy), (ox + s, oy + s)],
                        ],
                    ),
                ];
                for (shape, sh) in shapes {
                    b.add_as(shape, &sh);
                }
            }
        }
    }
    b.set
}

/// Perimeter of the rectangle a-b-c-d (all nodes, each once, starting at `a`).
fn ring(a: Pt, b: Pt, c: Pt, d: Pt) -> Vec<Pt> {
    let mut v = polyline_nodes(&[a, b, c, d]).expect("rectangle sides are simple");
    let to = |p: Pt| p.1 as u8 * GRID + p.0 as u8;
    v.extend(intermediate_nodes(to(d), to(a)));
    v.into_iter().map(xy).collect()
}

/// Clockwise inward spiral from (0,0) covering the grid.
fn spiral_walk() -> Vec<Pt> {
    let g = GRID as i8;
    let (mut x0, mut y0, mut x1, mut y1) = (0, 0, g - 1, g - 1);
    let mut v = Vec::new();
    while x0 <= x1 && y0 <= y1 {
        for x in x0..=x1 {
            v.push((x, y0));
        }
        for y in y0 + 1..=y1 {
            v.push((x1, y));
        }
        if y1 > y0 {
            for x in (x0..x1).rev() {
                v.push((x, y1));
            }
        }
        if x1 > x0 {
            for y in (y0 + 1..y1).rev() {
                v.push((x0, y));
            }
        }
        (x0, y0, x1, y1) = (x0 + 1, y0 + 1, x1 - 1, y1 - 1);
    }
    v
}

/// Row-wise snake from (0,0).
fn snake_walk() -> Vec<Pt> {
    let g = GRID as i8;
    let mut v = Vec::new();
    for y in 0..g {
        if y % 2 == 0 {
            v.extend((0..g).map(|x| (x, y)));
        } else {
            v.extend((0..g).rev().map(|x| (x, y)));
        }
    }
    v
}

fn blocklist() -> &'static HashMap<Vec<Vec<u8>>, BlockedShape> {
    static BL: OnceLock<HashMap<Vec<Vec<u8>>, BlockedShape>> = OnceLock::new();
    BL.get_or_init(build_blocklist)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::tests::arb_pattern;
    use proptest::prelude::*;

    fn pat(s: &[&[u8]]) -> Pattern {
        Pattern::new(s.iter().map(|x| x.to_vec()).collect()).unwrap()
    }

    #[test]
    fn blocklist_contents() {
        let bl = blocklist();
        assert!(bl.len() > 1000, "blocklist unexpectedly small");
        // Z over the whole grid: top row, anti-diagonal, bottom row.
        let z = Pattern::from_drawn(vec![vec![0, 4, 20, 24]]).unwrap();
        assert!(is_blocklisted(&z));
        // Reversed Z.
        let zr = Pattern::from_drawn(vec![vec![24, 20, 4, 0]]).unwrap();
        assert!(is_blocklisted(&zr));
        // Rotated C (U opening up).
        let u = Pattern::from_drawn(vec![vec![0, 20, 24, 4]]).unwrap();
        assert!(is_blocklisted(&u));
        // Border of the full grid minus the closing edge.
        let border = Pattern::from_drawn(vec![vec![0, 4, 24, 20, 5]]).unwrap();
        assert!(is_blocklisted(&border));
        // Small L, half-size Z at an offset.
        assert!(is_blocklisted(&pat(&[&[6, 11, 16, 17, 18]])));
        let small_z = Pattern::from_drawn(vec![vec![6, 8, 16, 18]]).unwrap();
        assert!(is_blocklisted(&small_z));
        // Spiral prefix.
        assert!(is_blocklisted(&pat(&[&[0, 1, 2, 3, 4, 9, 14]])));
        // Two-stroke X.
        let x = Pattern::from_drawn(vec![vec![0, 24], vec![4, 20]]).unwrap();
        assert!(is_blocklisted(&x));
        // Every blocklist entry is structurally valid.
        for s in bl.keys() {
            assert!(Pattern::new(s.clone()).is_ok());
        }
    }

    #[test]
    fn blocked_shapes_are_named() {
        let named = |strokes: Vec<Vec<u8>>| blocked_shape(&Pattern::from_drawn(strokes).unwrap());
        assert_eq!(named(vec![vec![0, 4, 20, 24]]), Some(BlockedShape::ZShape));
        // N is a rotation of Z: same family, named ZShape.
        assert_eq!(named(vec![vec![20, 0, 24, 4]]), Some(BlockedShape::ZShape));
        assert_eq!(named(vec![vec![0, 20, 24, 4]]), Some(BlockedShape::UShape));
        assert_eq!(
            named(vec![vec![0, 4, 24, 20, 5]]),
            Some(BlockedShape::Square)
        );
        assert_eq!(named(vec![vec![6, 16, 18]]), Some(BlockedShape::LShape));
        assert_eq!(named(vec![vec![0, 4]]), Some(BlockedShape::Line));
        assert_eq!(
            named(vec![vec![
                0, 1, 2, 3, 4, 9, 14, 19, 24, 23, 22, 21, 20, 15, 10, 5, 6
            ]]),
            Some(BlockedShape::Spiral)
        );
        assert_eq!(
            named(vec![vec![0, 24], vec![4, 20]]),
            Some(BlockedShape::Cross)
        );
        assert_eq!(named(vec![vec![7, 0, 11, 22, 13, 4, 8, 15, 21]]), None);
        let r = evaluate(&Pattern::from_drawn(vec![vec![0, 4, 20, 24]]).unwrap());
        assert!(r.blocklisted && r.blocked_shape == Some(BlockedShape::ZShape));
    }

    #[test]
    fn meter_orders_sensibly() {
        let z = Pattern::from_drawn(vec![vec![0, 4, 20, 24]]).unwrap();
        let rz = evaluate(&z);
        assert!(rz.blocklisted);
        assert_eq!(rz.strength, Strength::Weak);
        // An irregular pattern with knight moves.
        let irregular = pat(&[&[7, 0, 11, 22, 13, 4, 8, 15, 21]]);
        let ri = evaluate(&irregular);
        assert!(!ri.blocklisted);
        assert!(ri.guess_rank_log2 > 26.0, "bits {}", ri.guess_rank_log2);
        assert_eq!(ri.strength, Strength::Strong);
        // A short adjacent walk is weaker than the irregular one.
        let simple = pat(&[&[12, 13, 8, 7, 6, 11]]);
        assert!(evaluate(&simple).guess_rank_log2 < ri.guess_rank_log2);
    }

    proptest! {
        #[test]
        fn meter_is_finite_and_positive(p in arb_pattern()) {
            let r = evaluate(&p);
            prop_assert!(r.guess_rank_log2.is_finite() && r.guess_rank_log2 > 0.0);
        }
    }
}
