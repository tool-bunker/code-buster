
#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::analyze;

    fn codes(sources: BTreeMap<String, String>) -> BTreeSet<String> {
        analyze(&sources)
            .into_iter()
            .map(|finding| finding.code)
            .collect()
    }

    #[test]
    fn reports_core_style_runtime_and_project_contracts() {
        let findings = codes(BTreeMap::from([(
            "src/risky.nim".to_owned(),
            r#"import os
proc risky*(a, b, c, d, e, f: int) =
  var value = 1
  try:
    discard
  except:
    discard
  let pointer = cast[pointer](value)
  return value"#
                .to_owned(),
        )]));
        for code in [
            "nim-no-test-suite",
            "nim-missing-test-for-module",
            "nim-std-import",
            "nim-missing-raises",
            "nim-missing-doc",
            "nim-too-many-parameters",
            "nim-prefer-let",
            "nim-broad-except",
            "nim-cast-usage",
            "nim-return-instead-of-result",
        ] {
            assert!(findings.contains(code), "missing {code}");
        }
    }

    #[test]
    fn preserves_advanced_rule_order_and_object_state() {
        let findings = analyze(&BTreeMap::from([(
            "advanced.nim".to_owned(),
            r#"type
  Public* = ref object
    items*: seq[int]
proc broadHook*[T](value: seq[T]): T = discard
if websocketConnection.contains("upgrade"): discard
template withState*(body: untyped) =
  config.value = true
  body"#
                .to_owned(),
        )]));
        let advanced_codes = [
            "nim-public-mutable-container-field",
            "nim-hook-too-generic",
            "nim-generic-hook-same-signature",
            "nim-generic-hook-missing-doc",
            "nim-http-header-contains",
            "nim-websocket-upgrade-fragile",
            "nim-exported-template-missing-doc",
            "nim-template-body-state-mutation",
            "nim-state-restore-without-finally",
        ];

        assert_eq!(
            findings
                .iter()
                .filter(|finding| advanced_codes.contains(&finding.code.as_str()))
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("nim-public-mutable-container-field", 3),
                ("nim-hook-too-generic", 4),
                ("nim-generic-hook-same-signature", 4),
                ("nim-generic-hook-missing-doc", 4),
                ("nim-http-header-contains", 5),
                ("nim-websocket-upgrade-fragile", 5),
                ("nim-exported-template-missing-doc", 6),
                ("nim-template-body-state-mutation", 6),
                ("nim-state-restore-without-finally", 6),
            ]
        );
    }

    #[test]
    fn preserves_simple_rule_order() {
        let findings = analyze(&BTreeMap::from([(
            "simple.nim".to_owned(),
            r#"import os
proc risky*(a, b, c, d, e, f: int) =
  try:
    discard
  except CatchableError:
    discard
  let pointer = cast[pointer](value)"#
                .to_owned(),
        )]));
        let simple_codes = [
            "nim-std-import",
            "nim-too-many-parameters",
            "nim-missing-raises",
            "nim-missing-doc",
            "nim-broad-except",
            "nim-empty-except-body",
            "nim-cast-usage",
        ];

        assert_eq!(
            findings
                .iter()
                .filter(|finding| simple_codes.contains(&finding.code.as_str()))
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("nim-std-import", 1),
                ("nim-too-many-parameters", 2),
                ("nim-missing-raises", 2),
                ("nim-missing-doc", 2),
                ("nim-broad-except", 5),
                ("nim-empty-except-body", 5),
                ("nim-cast-usage", 7),
            ]
        );
    }

    #[test]
    fn reports_simulation_and_render_state_contracts() {
        let findings = codes(BTreeMap::from([(
            "game.nim".to_owned(),
            r#"proc update(position: Vec2) =
  if position.x == 0.0: discard
  if distance(position, target) == 0: discard
  let value = rand(10)
  let clock = getTime()
  playSound(hit)
  saveState(game)
  for entity in entities:
    entities.remove(entity)
proc draw() =
  beginScissor()
  if keyPressed(Escape): discard
  drawText($"score")"#
                .to_owned(),
        )]));
        for code in [
            "nim-float-equality-physics",
            "nim-input-in-draw",
            "nim-missing-epsilon-distance",
            "nim-mutate-while-iterating",
            "nim-per-frame-string-format",
            "nim-random-in-simulation",
            "nim-render-state-not-restored",
            "nim-save-in-update",
            "nim-sound-every-frame",
            "nim-wall-clock-in-update",
        ] {
            assert!(findings.contains(code), "missing {code}");
        }
    }

    #[test]
    fn excludes_comments_and_safe_markup_output() {
        let findings = analyze(&BTreeMap::from([(
            "tests/test_safe.nim".to_owned(),
            r#"# execCmd("tool " & input)
let text = "ordinary text"
echo "<user>", xmltree.escape(userName), "</user>"
echo "<user>", userName, "</user>""#
                .to_owned(),
        )]));
        let markup = findings
            .iter()
            .filter(|finding| finding.code == "nim-xml-output-unescaped")
            .collect::<Vec<_>>();
        assert_eq!(markup.len(), 1);
        assert_eq!(markup[0].line, 4);
        assert!(
            !findings
                .iter()
                .any(|finding| finding.code == "nim-exec-dynamic-command")
        );
    }
    #[test]
    fn reports_only_ungrouped_large_numeric_literals() {
        let findings = analyze(&BTreeMap::from([(
            "numbers.nim".to_owned(),
            "let unsafe = 10000000\n\
             let grouped = 10_000_000\n\
             let text = \"10000000\"\n\
             let decimal = 10000000.5\n\
             let identifier10000000 = 1"
                .to_owned(),
        )]));

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "nim-large-number-ungrouped")
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[test]
    fn preserves_runtime_and_aggregate_finding_order() {
        let findings = analyze(&BTreeMap::from([(
            "tests/helpers.nim".to_owned(),
            r#"proc average*(values: openArray[float]): float =
  discard
proc update(dt: float) =
  discard
proc renderTensor*(input: Tensor): Tensor =
  discard"#
                .to_owned(),
        )]));
        let selected = [
            "nim-average-openarray-risk",
            "nim-float-tests-missing-edge-cases",
            "nim-dt-not-used",
            "nim-layout-assumption-undocumented",
            "nim-test-naming",
        ];

        assert_eq!(
            findings
                .iter()
                .filter(|finding| selected.contains(&finding.code.as_str()))
                .map(|finding| (finding.code.as_str(), finding.line))
                .collect::<Vec<_>>(),
            vec![
                ("nim-average-openarray-risk", 1),
                ("nim-float-tests-missing-edge-cases", 1),
                ("nim-dt-not-used", 3),
                ("nim-layout-assumption-undocumented", 5),
                ("nim-test-naming", 1),
            ]
        );
    }

    #[test]
    fn reports_runtime_loop_and_lifecycle_risks_after_dispatch() {
        let findings = codes(BTreeMap::from([(
            "game.nim".to_owned(),
            r#"proc saveGame(path: string) =
  writeFile(path, "state")
proc updateWorld() =
  for entity in entities:
    for other in entities:
      let hits = newSeq[int]()
      if collide(entity, other): discard
  let component = getComponent(entity)
  entity.dead = true
  echo entity.position
  discard readFile("state.json")
  entities.add(spawn())"#
                .to_owned(),
        )]));

        for code in [
            "nim-save-missing-version",
            "nim-hot-loop-allocation",
            "nim-game-loop-allocation",
            "nim-o-n-squared-collision",
            "nim-nil-component-access",
            "nim-entity-access-after-destroy",
            "nim-update-blocking-io",
            "nim-unbounded-entity-growth",
        ] {
            assert!(findings.contains(code), "missing {code}");
        }
    }

}
