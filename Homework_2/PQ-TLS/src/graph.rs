use std::collections::HashMap;
use image::{Rgb, RgbImage};
use imageproc::drawing::{draw_line_segment_mut, draw_text_mut};
use ab_glyph::{FontArc, PxScale};

#[derive(Clone, Copy)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

const FONT_DATA: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/Roboto-Italic-VariableFont_wdth,wght.ttf"));

pub struct Graph {
    pub positions: HashMap<u64, Point>,
    pub names: HashMap<u64, String>,
    pub arrows: Vec<(u64, u64, String)>,
}

impl Graph {
    pub fn new() -> Self {
        Self {
            positions: HashMap::new(),
            names: HashMap::new(),
            arrows: Vec::new(),
        }
    }

    pub fn add_arrow(&mut self, from: u64, to: u64, title: String) {
        self.arrows.push((from, to, title));
    }
}

pub fn render_graph(graph: &Graph, path: &str) {
    let mut img = RgbImage::new(800, 600);
    for p in img.pixels_mut() {
        *p = Rgb([255, 255, 255]);
    }

    let font = FontArc::try_from_slice(FONT_DATA).expect("Font not found");
    let scale = PxScale::from(14.0);

    for (from, to, title) in &graph.arrows {
        let a = graph.positions[from];
        let b = graph.positions[to];

        draw_line_segment_mut(
            &mut img,
            (a.x as f32, a.y as f32),
            (b.x as f32, b.y as f32),
            Rgb([0, 0, 0]),
        );

        let mid_x = ((a.x + b.x) / 2) as i32;
        let mid_y = ((a.y + b.y) / 2) as i32;
        draw_text_mut(&mut img, Rgb([0, 0, 255]), mid_x, mid_y, scale, &font, title);
    }

    for (id, pos) in &graph.positions {
        if let Some(name) = graph.names.get(id) {
            draw_text_mut(&mut img, Rgb([255, 0, 0]), pos.x - 10, pos.y - 20, scale, &font, name);
        }
    }

    img.save(path).unwrap();
}