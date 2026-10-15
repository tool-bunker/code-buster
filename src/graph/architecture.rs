use std::collections::{BTreeMap, BTreeSet};

use crate::dependency_graph::DependencyGraph;

pub fn layer_for<'a>(source: &str, layers: &'a [String]) -> Option<&'a str> {
    let normalized = source.replace('\\', "/");
    let segments = normalized.split('/').collect::<Vec<_>>();
    for layer in layers {
        let pattern = layer.split('/').collect::<Vec<_>>();
        if pattern.len() == 1 && segments.contains(&pattern[0]) {
            return Some(layer);
        }
        if pattern.len() <= segments.len()
            && segments.windows(pattern.len()).any(|window| {
                window
                    .iter()
                    .zip(&pattern)
                    .all(|(segment, expected)| *expected == "*" || segment == expected)
            })
        {
            return Some(layer);
        }
    }
    None
}

pub fn layer_edges(
    graph: &DependencyGraph,
    layers: &[String],
) -> BTreeMap<String, BTreeSet<String>> {
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for source in graph.nodes() {
        let Some(source_layer) = layer_for(source, layers) else {
            continue;
        };
        for target in graph.dependencies(source) {
            if let Some(target_layer) = layer_for(target, layers)
                && target_layer != source_layer
            {
                edges
                    .entry(source_layer.to_owned())
                    .or_default()
                    .insert(target_layer.to_owned());
            }
        }
    }
    edges
}
