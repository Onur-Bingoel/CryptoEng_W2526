use std::collections::HashMap;
use image::{Rgb, RgbImage};
use imageproc::drawing::{draw_line_segment_mut, draw_text_mut};
use ab_glyph::{Font, FontArc, PxScale, ScaleFont};

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
    let scaled = font.as_scaled(scale);

    for (idx, (from, to, title)) in graph.arrows.iter().enumerate() {
        let a = graph.positions[from];
        let b = graph.positions[to];
        let offset = (idx as i32) * 20;

        let ay = a.y + offset;
        let by = b.y + offset;

        draw_line_segment_mut(&mut img, (a.x as f32, ay as f32), (b.x as f32, by as f32), Rgb([0, 0, 0]));

        let dx = (b.x - a.x) as f32;
        let dy = (by - ay) as f32;
        let len = (dx * dx + dy * dy).sqrt().max(1.0);
        let ux = dx / len;
        let uy = dy / len;
        let head_len = 12.0;
        let head_w = 6.0;

        let tip = (b.x as f32, by as f32);
        let base = (b.x as f32 - ux * head_len, by as f32 - uy * head_len);
        let left = (base.0 - uy * head_w, base.1 + ux * head_w);
        let right = (base.0 + uy * head_w, base.1 - ux * head_w);
        draw_line_segment_mut(&mut img, tip, left, Rgb([0, 0, 0]));
        draw_line_segment_mut(&mut img, tip, right, Rgb([0, 0, 0]));

        // Text mittig auf der Linie platzieren
        let text_width: f32 = title.chars().map(|c| {
            let gid = scaled.glyph_id(c);
            scaled.h_advance(gid)
        }).sum();
        let mid_x = ((a.x + b.x) as f32 / 2.0 - text_width / 2.0) as i32;
        let mid_y = ((ay + by) / 2) as i32;
        draw_text_mut(&mut img, Rgb([0, 0, 255]), mid_x, mid_y, scale, &font, title);
    }

    for (id, pos) in &graph.positions {
        if let Some(name) = graph.names.get(id) {
            draw_text_mut(&mut img, Rgb([255, 0, 0]), pos.x - 10, pos.y - 20, scale, &font, name);
        }
    }

    img.save(path).unwrap();
}