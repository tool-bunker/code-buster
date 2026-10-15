fn analyze_runtime(
    context: &LineContext<'_>,
    file_lower: &str,
    state: &mut ScanState,
    findings: &mut Vec<Finding>,
) {
    analyze_security(context, state, findings);
    update_runtime_scopes(context, state);

    let proc_declaration = is_proc_declaration(context.line);
    if proc_declaration {
        analyze_runtime_proc(context, file_lower, state, findings);
    }
    if proc_declaration && HOT_PROC.is_match(context.lower) {
        analyze_hot_proc(context, state, findings);
    }

    analyze_runtime_loops(context, state, findings);
    analyze_runtime_lifecycle(context, proc_declaration, state, findings);
    analyze_runtime_rendering(context, state, findings);
    analyze_runtime_simulation(context, proc_declaration, state, findings);
    analyze_runtime_tail(context, proc_declaration, state, findings);
}

fn update_runtime_scopes(context: &LineContext<'_>, state: &mut ScanState) {
    pop_scopes(context.indent, &mut state.loop_indents);
    pop_scopes(context.indent, &mut state.hot_proc_indents);
    pop_scopes(context.indent, &mut state.draw_proc_indents);
    while state
        .loop_collections
        .last()
        .is_some_and(|(_, indent)| context.indent <= *indent)
    {
        state.loop_collections.pop();
    }
}

fn is_proc_declaration(line: &str) -> bool {
    line.starts_with("proc ") || line.starts_with("func ")
}

fn analyze_runtime_proc(
    context: &LineContext<'_>,
    file_lower: &str,
    state: &mut ScanState,
    findings: &mut Vec<Finding>,
) {
    let proc_body = indented_body(context.lines, context.index, context.indent)
        .join("\n")
        .to_ascii_lowercase();
    analyze_average_risk(context, findings);
    analyze_unused_delta_time(context, &proc_body, findings);
    analyze_float_edge_coverage(context, file_lower, state, findings);
}

fn analyze_average_risk(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    if context.lower.contains("average") && context.lower.contains("openarray") {
        add_line(
            findings,
            context,
            "nim-average-openarray-risk",
            "average-like openArray API needs edge-case handling",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_unused_delta_time(
    context: &LineContext<'_>,
    proc_body: &str,
    findings: &mut Vec<Finding>,
) {
    let has_dt = (context.lower.contains("dt:") || context.lower.contains("delta"))
        && !context.lower.contains("_dt:")
        && !context.lower.contains("_delta");
    if has_dt && UPDATE_WORD.is_match(context.lower) && !DT_USE.is_match(proc_body) {
        add_line(
            findings,
            context,
            "nim-dt-not-used",
            "update-like proc accepts dt but does not appear to use it",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_float_edge_coverage(
    context: &LineContext<'_>,
    file_lower: &str,
    state: &mut ScanState,
    findings: &mut Vec<Finding>,
) {
    if state.float_edge_finding_added
        || !context.line.contains('*')
        || !FLOAT_API.is_match(context.lower)
        || FLOAT_EDGE.is_match(file_lower)
    {
        return;
    }
    push_str(
        findings,
        "nim-float-tests-missing-edge-cases",
        context.path,
        1,
        "exported floating-point API has no obvious edge-case coverage nearby",
        "low",
        Some(Severity::Info),
    );
    state.float_edge_finding_added = true;
}

fn analyze_hot_proc(
    context: &LineContext<'_>,
    state: &mut ScanState,
    findings: &mut Vec<Finding>,
) {
    state.hot_proc_indents.push(context.indent);
    if context.lower.contains("draw") || context.lower.contains("render") {
        state.draw_proc_indents.push(context.indent);
        state.render_begin_count = 0;
        state.render_end_count = 0;
        state.render_proc_line = context.index + 1;
    }
    analyze_layout_documentation(context, findings);
}

fn analyze_layout_documentation(context: &LineContext<'_>, findings: &mut Vec<Finding>) {
    let layout_sensitive = LAYOUT_TYPE.is_match(context.lower)
        || (LAYOUT_WORD.is_match(context.lower) && context.lower.contains("shape")
            || LAYOUT_WORD.is_match(context.lower) && context.lower.contains("dims"));
    let previous = context
        .index
        .checked_sub(1)
        .map_or("", |index| context.lines[index].trim());
    if layout_sensitive
        && !LAYOUT_DOC.is_match(&previous.to_ascii_lowercase())
        && !context.line.contains("##")
    {
        add_line(
            findings,
            context,
            "nim-layout-assumption-undocumented",
            "layout-sensitive public API lacks obvious shape/layout docs",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_security(context: &LineContext<'_>, state: &mut ScanState, findings: &mut Vec<Finding>) {
    pop_scopes(context.indent, &mut state.capture_indents);
    if CAPTURE_START.is_match(context.line) {
        if !state.capture_indents.is_empty() {
            add_line(
                findings,
                context,
                "nim-nested-stdout-capture",
                "nested stdout/stderr capture detected",
                "low",
                Some(Severity::Info),
            );
        }
        state.capture_indents.push(context.indent);
    }
    if let Some(captures) = TAINTED_ASSIGNMENT.captures(context.line) {
        state.tainted_values.insert(captures[1].to_owned());
    }
    if let Some(captures) = TABLE_DECLARATION.captures(context.line)
        && !context.line.contains("initOrderedTable[")
    {
        state.unordered_tables.insert(captures[1].to_owned());
    }
    if EXEC_CALL.is_match(context.line)
        && (context.line.contains('&') || context.line.contains('$'))
        && state
            .tainted_values
            .iter()
            .any(|value| context.line.contains(value))
    {
        add_line(
            findings,
            context,
            "nim-tainted-exec",
            "user/input-derived value flows into process command",
            "low",
            Some(Severity::Warn),
        );
    }
    if context.line.starts_with("for ")
        && state
            .unordered_tables
            .iter()
            .any(|table| context.line.contains(&format!(" in {table}:")))
        && context.lines[context.index + 1..]
            .iter()
            .take(8)
            .any(|body| {
                let body = body.trim();
                body.starts_with("echo ")
                    || body.contains("result.add")
                    || body.contains("rows.add")
            })
    {
        add_line(
            findings,
            context,
            "nim-unordered-table-output",
            "unordered Table iteration contributes directly to ordered output",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_runtime_loops(
    context: &LineContext<'_>,
    state: &mut ScanState,
    findings: &mut Vec<Finding>,
) {
    record_runtime_loop(context, state);
    analyze_loop_file_concat(context, state, findings);
    analyze_hot_loop_allocation(context, state, findings);
    analyze_game_loop_allocation(context, state, findings);
    analyze_hot_loop_blocking_io(context, state, findings);
    analyze_entity_growth(context, state, findings);
    analyze_draw_asset_load(context, state, findings);
    analyze_render_randomness(context, state, findings);
}

fn record_runtime_loop(context: &LineContext<'_>, state: &mut ScanState) {
    if !context.line.starts_with("for ") && !context.line.starts_with("while ") {
        return;
    }
    state.loop_indents.push(context.indent);
    if let Some(captures) = LOOP_COLLECTION.captures(context.line) {
        state
            .loop_collections
            .push((captures[1].to_owned(), context.indent));
    }
}

fn analyze_loop_file_concat(
    context: &LineContext<'_>,
    state: &ScanState,
    findings: &mut Vec<Finding>,
) {
    if !state.loop_indents.is_empty()
        && context.lower.contains("result")
        && (context.lower.contains("&= readfile")
            || context.lower.contains("= result &") && context.lower.contains("readfile"))
    {
        add_line(
            findings,
            context,
            "nim-readfile-concat-temp",
            "readFile result is concatenated in a loop",
            "medium",
            Some(Severity::Info),
        );
    }
}

fn analyze_hot_loop_allocation(
    context: &LineContext<'_>,
    state: &ScanState,
    findings: &mut Vec<Finding>,
) {
    if !state.loop_indents.is_empty()
        && !state.hot_proc_indents.is_empty()
        && HOT_ALLOCATION.is_match(context.lower)
    {
        add_line(
            findings,
            context,
            "nim-hot-loop-allocation",
            "allocation-like operation inside loop",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_game_loop_allocation(
    context: &LineContext<'_>,
    state: &ScanState,
    findings: &mut Vec<Finding>,
) {
    if !state.hot_proc_indents.is_empty() && GAME_ALLOCATION.is_match(context.lower) {
        add_line(
            findings,
            context,
            "nim-game-loop-allocation",
            "allocation-like operation inside update/render loop",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_hot_loop_blocking_io(
    context: &LineContext<'_>,
    state: &ScanState,
    findings: &mut Vec<Finding>,
) {
    if !state.hot_proc_indents.is_empty() && BLOCKING_IO.is_match(context.lower) {
        add_line(
            findings,
            context,
            "nim-update-blocking-io",
            "blocking IO appears inside update/render loop",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_entity_growth(
    context: &LineContext<'_>,
    state: &ScanState,
    findings: &mut Vec<Finding>,
) {
    if state.hot_proc_indents.is_empty()
        || !ENTITY_WORD.is_match(context.lower)
        || !(context.lower.contains(".add(") || context.lower.contains(".add "))
    {
        return;
    }
    let nearby = nearby_lines(context.lines, context.index, 5, 5).to_ascii_lowercase();
    if !GROWTH_LIMIT.is_match(&nearby) {
        add_line(
            findings,
            context,
            "nim-unbounded-entity-growth",
            "entity-like collection grows in hot loop without obvious cap/removal",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_draw_asset_load(
    context: &LineContext<'_>,
    state: &ScanState,
    findings: &mut Vec<Finding>,
) {
    if !state.draw_proc_indents.is_empty() && ASSET_LOAD_CALL.is_match(context.lower) {
        add_line(
            findings,
            context,
            "nim-draw-loads-asset",
            "asset loading appears inside draw/render proc",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_render_randomness(
    context: &LineContext<'_>,
    state: &ScanState,
    findings: &mut Vec<Finding>,
) {
    if !state.draw_proc_indents.is_empty() && RANDOM_CALL.is_match(context.lower) {
        add_line(
            findings,
            context,
            "nim-random-in-render",
            "random call appears inside draw/render proc",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_runtime_lifecycle(
    context: &LineContext<'_>,
    proc_declaration: bool,
    state: &mut ScanState,
    findings: &mut Vec<Finding>,
) {
    let in_update = !state.hot_proc_indents.is_empty() && state.draw_proc_indents.is_empty();
    analyze_save_version(context, proc_declaration, findings);
    analyze_destroyed_entity_access(context, in_update, state, findings);
    analyze_component_nil_check(context, in_update, findings);
    analyze_nested_collision(context, in_update, state, findings);
}

fn analyze_save_version(
    context: &LineContext<'_>,
    proc_declaration: bool,
    findings: &mut Vec<Finding>,
) {
    if !proc_declaration || !SAVE_PROC.is_match(context.lower) {
        return;
    }
    let body = indented_body(context.lines, context.index, context.indent)
        .join("\n")
        .to_ascii_lowercase();
    if SAVE_WRITE.is_match(&body) && !body.contains("version") {
        push_str(
            findings,
            "nim-save-missing-version",
            context.path,
            1,
            "save proc writes data but has no version field",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_destroyed_entity_access(
    context: &LineContext<'_>,
    in_update: bool,
    state: &mut ScanState,
    findings: &mut Vec<Finding>,
) {
    if !in_update {
        return;
    }
    if ENTITY_LIFECYCLE.is_match(context.lower) {
        record_destroyed_entity(context, state);
        return;
    }
    for entity in &state.destroyed_entities {
        if has_member(context.lower, entity, &[])
            && !has_member(context.lower, entity, &["alive", "dead", "destroyed"])
        {
            add_line(
                findings,
                context,
                "nim-entity-access-after-destroy",
                "entity field accessed after being marked dead/destroyed",
                "low",
                Some(Severity::Warn),
            );
            break;
        }
    }
}

fn record_destroyed_entity(context: &LineContext<'_>, state: &mut ScanState) {
    let Some(captures) = ENTITY_RECEIVER.captures(context.line) else {
        return;
    };
    let entity = captures[1].to_ascii_lowercase();
    if entity.len() > 2 {
        state.destroyed_entities.insert(entity);
    }
}

fn analyze_component_nil_check(
    context: &LineContext<'_>,
    in_update: bool,
    findings: &mut Vec<Finding>,
) {
    if !in_update || !COMPONENT_LOOKUP.is_match(context.lower) {
        return;
    }
    let Some(captures) = ASSIGNED_VALUE.captures(context.line) else {
        return;
    };
    let name = captures[1].to_ascii_lowercase();
    let nearby = context.lines[context.index + 1..]
        .iter()
        .take(5)
        .copied()
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    if has_nil_check(&nearby, &name) {
        return;
    }
    add_line(
        findings,
        context,
        "nim-nil-component-access",
        "component obtained but not checked for nil before use",
        "low",
        Some(Severity::Info),
    );
}

fn has_nil_check(source: &str, name: &str) -> bool {
    source.contains(&format!("{name} != nil"))
        || source.contains(&format!("{name} == nil"))
        || source.contains(&format!("{name}.isnil"))
        || source.contains(&format!("isnil({name}"))
}

fn analyze_nested_collision(
    context: &LineContext<'_>,
    in_update: bool,
    state: &ScanState,
    findings: &mut Vec<Finding>,
) {
    if !in_update || state.loop_indents.len() < 2 || !COLLISION_CALL.is_match(context.lower) {
        return;
    }
    let nearby = context.lines[context.index.saturating_sub(10)..=context.index]
        .join("\n")
        .to_ascii_lowercase();
    if !BROAD_PHASE.is_match(&nearby) {
        add_line(
            findings,
            context,
            "nim-o-n-squared-collision",
            "nested-loop collision check without broad-phase hint",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_runtime_rendering(
    context: &LineContext<'_>,
    state: &mut ScanState,
    findings: &mut Vec<Finding>,
) {
    let in_draw = !state.draw_proc_indents.is_empty();
    if in_draw && CAMERA_MUTATION.is_match(context.lower) {
        state.camera_modified = true;
        state.camera_proc_line = state.render_proc_line;
    }
    if in_draw && CAMERA_RESTORE.is_match(context.lower) {
        state.camera_restored = true;
    }
    let asset_load = context.lower.contains("load") && ASSET_WORD.is_match(context.lower);
    let asset_free = ASSET_FREE.is_match(context.lower) && ASSET_FREE_WORD.is_match(context.lower);
    state.asset_load_count += usize::from(asset_load);
    state.asset_free_count += usize::from(asset_free);
    if in_draw
        && DRAW_PRIMITIVE.is_match(context.lower)
        && DEBUG_WORD.is_match(&context.raw.to_ascii_lowercase())
    {
        let nearby = context.lines[context.index.saturating_sub(5)..=context.index]
            .join("\n")
            .to_ascii_lowercase();
        if !nearby.contains("if debug") {
            add_line(
                findings,
                context,
                "nim-debug-draw-not-gated",
                "debug-looking draw call not gated by a debug flag",
                "low",
                Some(Severity::Info),
            );
        }
    }
}

fn analyze_runtime_simulation(
    context: &LineContext<'_>,
    proc_declaration: bool,
    state: &ScanState,
    findings: &mut Vec<Finding>,
) {
    let in_update = !state.hot_proc_indents.is_empty() && state.draw_proc_indents.is_empty();
    let in_draw = !state.draw_proc_indents.is_empty();
    analyze_simulation_configuration(context, in_update, in_draw, findings);
    analyze_update_rendering(context, proc_declaration, in_update, findings);
    analyze_simulation_comparisons(context, in_update, in_draw, findings);
    analyze_simulation_determinism(context, in_update, findings);
    analyze_per_frame_formatting(context, proc_declaration, in_update, in_draw, findings);
    analyze_input_polling(context, proc_declaration, in_draw, findings);
    analyze_sound_playback(context, in_update, in_draw, findings);
    analyze_hot_loop_saves(context, in_update, in_draw, findings);
}

fn analyze_simulation_configuration(
    context: &LineContext<'_>,
    in_update: bool,
    in_draw: bool,
    findings: &mut Vec<Finding>,
) {
    if (in_update || in_draw)
        && SCREEN_DIMENSION.is_match(context.lower)
        && SCREEN_NUMBER.is_match(context.lower)
        && !CONFIG_WORD.is_match(context.lower)
    {
        add_line(
            findings,
            context,
            "nim-hardcoded-screen-size",
            "screen dimension appears hardcoded instead of using config",
            "low",
            Some(Severity::Info),
        );
    }
    if in_update && context.lower.contains("* dt") && PHYSICS_WORD.is_match(context.lower) {
        let nearby = nearby_lines(context.lines, context.index, 10, 10).to_ascii_lowercase();
        if !nearby.contains("fixed") {
            add_line(
                findings,
                context,
                "nim-physics-variable-timestep",
                "physics integration uses variable dt without fixed timestep",
                "low",
                Some(Severity::Info),
            );
        }
    }
}

fn analyze_update_rendering(
    context: &LineContext<'_>,
    proc_declaration: bool,
    in_update: bool,
    findings: &mut Vec<Finding>,
) {
    if in_update
        && !proc_declaration
        && DRAW_IN_UPDATE.is_match(context.lower)
        && !context.lower.contains("debug")
    {
        add_line(
            findings,
            context,
            "nim-draw-call-in-update",
            "draw/render call appears inside update proc",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_simulation_comparisons(
    context: &LineContext<'_>,
    in_update: bool,
    in_draw: bool,
    findings: &mut Vec<Finding>,
) {
    if in_update && context.line.contains(" == ") && PHYSICS_FLOAT.is_match(context.lower) {
        add_line(
            findings,
            context,
            "nim-float-equality-physics",
            "floating-point equality comparison in update/sim code",
            "low",
            Some(Severity::Info),
        );
    }
    if (in_update || in_draw)
        && DISTANCE_CALL.is_match(context.lower)
        && context.lower.contains(" == 0")
    {
        add_line(
            findings,
            context,
            "nim-missing-epsilon-distance",
            "distance compared exactly to zero",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_simulation_determinism(
    context: &LineContext<'_>,
    in_update: bool,
    findings: &mut Vec<Finding>,
) {
    if in_update
        && RAND_SIMULATION.is_match(context.lower)
        && !context.lower.contains("rng")
        && !context.lower.contains("seed")
    {
        add_line(
            findings,
            context,
            "nim-random-in-simulation",
            "unseeded random call in update/sim proc",
            "low",
            Some(Severity::Info),
        );
    }
    if in_update && WALL_CLOCK.is_match(context.lower) {
        add_line(
            findings,
            context,
            "nim-wall-clock-in-update",
            "wall-clock time used inside update/sim proc",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_per_frame_formatting(
    context: &LineContext<'_>,
    proc_declaration: bool,
    in_update: bool,
    in_draw: bool,
    findings: &mut Vec<Finding>,
) {
    if (in_update || in_draw)
        && !proc_declaration
        && (context.raw.contains("$\"")
            || context.raw.contains("$(")
            || context.lower.contains(".format(")
            || context.lower.contains("formatstring"))
    {
        add_line(
            findings,
            context,
            "nim-per-frame-string-format",
            "string formatting appears inside update/draw loop",
            "low",
            Some(Severity::Info),
        );
    }
}

fn analyze_input_polling(
    context: &LineContext<'_>,
    proc_declaration: bool,
    in_draw: bool,
    findings: &mut Vec<Finding>,
) {
    if in_draw && !proc_declaration && INPUT_CALL.is_match(context.lower) {
        add_line(
            findings,
            context,
            "nim-input-in-draw",
            "input polling appears inside draw/render proc",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_sound_playback(
    context: &LineContext<'_>,
    in_update: bool,
    in_draw: bool,
    findings: &mut Vec<Finding>,
) {
    if !(in_update || in_draw) || !SOUND_CALL.is_match(context.lower) {
        return;
    }
    let nearby = context.lines[context.index.saturating_sub(3)..=context.index]
        .join("\n")
        .to_ascii_lowercase();
    if !nearby.contains("pressed") {
        add_line(
            findings,
            context,
            "nim-sound-every-frame",
            "sound played in hot loop without an edge/trigger guard",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_hot_loop_saves(
    context: &LineContext<'_>,
    in_update: bool,
    in_draw: bool,
    findings: &mut Vec<Finding>,
) {
    if (in_update || in_draw) && SAVE_CALL.is_match(context.lower) {
        add_line(
            findings,
            context,
            "nim-save-in-update",
            "save/write appears inside update/draw loop",
            "medium",
            Some(Severity::Warn),
        );
    }
}

fn analyze_runtime_tail(
    context: &LineContext<'_>,
    proc_declaration: bool,
    state: &mut ScanState,
    findings: &mut Vec<Finding>,
) {
    if !state.draw_proc_indents.is_empty() {
        if RENDER_BEGIN.is_match(context.lower) {
            state.render_begin_count += 1;
        }
        if RENDER_END.is_match(context.lower) {
            state.render_end_count += 1;
        }
    }
    if !state.loop_collections.is_empty() && !context.line.starts_with("for ") {
        for (collection, _) in &state.loop_collections {
            if has_member_call(
                context.lower,
                collection,
                &["add", "delete", "del", "remove", "pop"],
            ) {
                add_line(
                    findings,
                    context,
                    "nim-mutate-while-iterating",
                    "collection appears to be mutated while being iterated",
                    "medium",
                    Some(Severity::Warn),
                );
                break;
            }
        }
    }
    if proc_declaration
        && let (Some(open), Some(close)) = (context.line.find('('), context.line.rfind(')'))
        && close > open
    {
        let names = context.line[open + 1..close]
            .split(',')
            .filter_map(|segment| segment.split(':').next())
            .map(str::trim)
            .filter(|candidate| IDENTIFIER.is_match(candidate))
            .map(str::to_ascii_lowercase)
            .collect::<BTreeSet<_>>();
        state.proc_parameters.push((context.index + 1, names));
    }
}
