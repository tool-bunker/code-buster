
fn data_clumps(project: &Project) -> Vec<Finding> {
    let mut groups = BTreeMap::<String, Vec<(String, usize)>>::new();
    for (path, method) in all_methods(project) {
        let Some(parameters) = &method.parameters else {
            continue;
        };
        if parameters.len() < 3 {
            continue;
        }
        let mut values = parameters
            .iter()
            .map(|parameter| format!("{} {}", parameter.type_name, parameter.name))
            .collect::<Vec<_>>();
        values.sort();
        let names = values
            .iter()
            .filter_map(|parameter| parameter.split_whitespace().next_back())
            .collect::<BTreeSet<_>>();
        if names.contains("id")
            && names.contains("severity")
            && (names.contains("message") || names.contains("group"))
        {
            continue;
        }
        groups
            .entry(values.join("|"))
            .or_default()
            .push((path.to_owned(), method.line));
    }
    let mut findings = Vec::new();
    for (key, mut occurrences) in groups {
        let paths = occurrences
            .iter()
            .map(|(path, _)| path.clone())
            .collect::<BTreeSet<_>>();
        if !is_distributed_repetition(occurrences.len(), paths.len()) {
            continue;
        }
        occurrences.sort();
        let first = &occurrences[0];
        findings.push(finding(
            "oop-data-clump",
            &first.0,
            first.1,
            format!(
                "Parameters {} recur together in {} declarations across {} files",
                key.split('|')
                    .filter_map(|parameter| parameter.split_whitespace().next_back())
                    .collect::<Vec<_>>()
                    .join(", "),
                occurrences.len(),
                paths.len()
            ),
            "high",
            paths.into_iter().filter(|path| path != &first.0).collect(),
        ));
    }
    findings
}

fn strategy_dispatch(project: &Project) -> Vec<Finding> {
    let mut groups = BTreeMap::<String, Vec<(String, usize)>>::new();
    for (path, source) in &project.sources {
        let code = dart_source_with_interpolations(source, &mask_strings(source));
        for switch in switch_blocks(&code) {
            let cases = switch_cases(&switch.body);
            if cases.len() < 3 {
                continue;
            }
            let call_sets = cases
                .iter()
                .map(|(_, body)| call_names(body).into_iter().collect::<BTreeSet<_>>())
                .collect::<Vec<_>>();
            if call_sets.iter().any(BTreeSet::is_empty) || !has_distinct_calls(&call_sets) {
                continue;
            }
            let mut labels = cases
                .into_iter()
                .map(|(label, _)| label)
                .collect::<Vec<_>>();
            labels.sort();
            groups
                .entry(labels.join("|"))
                .or_default()
                .push((path.to_owned(), line_at(&code, switch.start)));
        }
    }
    grouped_occurrence_findings(
        groups,
        "oop-repeated-strategy-dispatch",
        "medium",
        |key, count, paths| {
            format!(
                "{count} switches repeat dispatch for {} across {paths} files",
                key.split('|').collect::<Vec<_>>().join(", ")
            )
        },
    )
}

fn has_distinct_calls(call_sets: &[BTreeSet<String>]) -> bool {
    fn assign(
        index: usize,
        sets: &[BTreeSet<String>],
        owners: &mut BTreeMap<String, usize>,
        visited: &mut BTreeSet<String>,
    ) -> bool {
        for call in &sets[index] {
            if !visited.insert(call.clone()) {
                continue;
            }
            if owners
                .get(call)
                .copied()
                .is_none_or(|owner| assign(owner, sets, owners, visited))
            {
                owners.insert(call.clone(), index);
                return true;
            }
        }
        false
    }
    let mut owners = BTreeMap::new();
    (0..call_sets.len()).all(|index| assign(index, call_sets, &mut owners, &mut BTreeSet::new()))
}

fn interface_pressure(project: &Project) -> Vec<Finding> {
    let mut findings = Vec::new();
    for contract in project.classes.iter().filter(|class| {
        class
            .methods
            .iter()
            .filter(|method| method.is_empty)
            .count()
            >= 4
    }) {
        let contract_methods = contract
            .methods
            .iter()
            .filter(|method| method.is_empty)
            .map(|method| method.name.clone())
            .collect::<BTreeSet<_>>();
        let rejecting = project
            .classes
            .iter()
            .filter(|class| class.interfaces.contains(&contract.name))
            .filter_map(|class| {
                let methods = class
                    .methods
                    .iter()
                    .filter(|method| {
                        contract_methods.contains(&method.name)
                            && throws_unsupported(&direct_body(&method.body))
                    })
                    .map(|method| method.name.clone())
                    .collect::<BTreeSet<_>>();
                (!methods.is_empty()).then_some((class, methods))
            })
            .collect::<Vec<_>>();
        let rejected_count = rejecting
            .iter()
            .map(|(_, methods)| methods.len())
            .sum::<usize>();
        let rejected_methods = rejecting
            .iter()
            .flat_map(|(_, methods)| methods.iter().cloned())
            .collect::<BTreeSet<_>>();
        if rejecting.len() < 2 || rejected_count < 3 || rejected_methods.len() < 2 {
            continue;
        }
        let related = rejecting
            .iter()
            .map(|(class, _)| class.path.clone())
            .filter(|path| path != &contract.path)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        findings.push(finding(
            "oop-interface-segregation-pressure",
            &contract.path,
            contract.line,
            format!(
                "{} has {} operations; {} implementors contain {} rejected implementations across {} operations",
                contract.name,
                contract_methods.len(),
                rejecting.len(),
                rejected_count,
                rejected_methods.len()
            ),
            "high",
            related,
        ));
    }
    findings
}

fn state_behavior(project: &Project) -> Vec<Finding> {
    project
        .classes
        .iter()
        .filter_map(state_behavior_finding)
        .collect()
}

fn state_behavior_finding(class: &Class) -> Option<Finding> {
    for field in class.fields.iter().filter(|field| {
        !field.is_static
            && !field.is_final
            && !field.is_const
            && ["State", "Status", "Phase"]
                .iter()
                .any(|suffix| field.type_name.ends_with(suffix))
    }) {
        if !state_field_is_assigned(class, field) {
            continue;
        }
        let Some((cases, methods)) = repeated_state_cases(class, field) else {
            continue;
        };
        return Some(finding(
            "oop-state-behavior-candidate",
            &class.path,
            class.line,
            format!(
                "{} switches on mutable {} across {} methods for {}",
                class.name,
                field.name,
                methods.len(),
                cases.split('|').collect::<Vec<_>>().join(", ")
            ),
            "medium",
            Vec::new(),
        ));
    }
    None
}

fn state_field_is_assigned(class: &Class, field: &Field) -> bool {
    let assignment =
        Regex::new(&format!(r"\b(?:this\.)?{}\s*=", regex::escape(&field.name))).unwrap();
    class
        .methods
        .iter()
        .any(|method| assignment.is_match(&direct_body(&method.body)))
}

fn repeated_state_cases(class: &Class, field: &Field) -> Option<(String, BTreeSet<String>)> {
    let mut methods_by_cases = BTreeMap::<String, BTreeSet<String>>::new();
    for method in &class.methods {
        for switch in switch_blocks(&method.body) {
            let Some(case_key) =
                qualifying_state_case_key(&switch.expression, &switch.body, &field.name)
            else {
                continue;
            };
            methods_by_cases
                .entry(case_key)
                .or_default()
                .insert(method.name.clone());
        }
    }
    methods_by_cases
        .into_iter()
        .find(|(_, methods)| methods.len() >= 3)
}

fn qualifying_state_case_key(
    expression: &str,
    switch_body: &str,
    field_name: &str,
) -> Option<String> {
    if !switches_on_state_field(expression, field_name) {
        return None;
    }
    let mut labels = switch_cases(switch_body)
        .into_iter()
        .map(|(label, _)| label)
        .collect::<Vec<_>>();
    if labels.len() < 3 {
        return None;
    }
    labels.sort();
    Some(labels.join("|"))
}

fn switches_on_state_field(expression: &str, field_name: &str) -> bool {
    let expression = expression.trim();
    expression == field_name || expression.strip_prefix("this.") == Some(field_name)
}

struct SingleUseCandidate<'a> {
    contract: &'a Class,
    implementation: &'a Class,
}

struct SingleUseUsage<'a> {
    candidate: SingleUseCandidate<'a>,
    references: usize,
    constructions: usize,
}

fn single_use_abstractions(project: &Project) -> Vec<Finding> {
    let project_source = project
        .sources
        .values()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    aggregate_single_use_usage(discover_single_use_candidates(project), &project_source)
        .into_iter()
        .filter(single_use_abstraction_qualifies)
        .map(single_use_abstraction_finding)
        .collect()
}

fn discover_single_use_candidates(project: &Project) -> Vec<SingleUseCandidate<'_>> {
    project
        .classes
        .iter()
        .filter(|class| {
            class.methods.len() == 1 && class.methods[0].is_empty && class.fields.is_empty()
        })
        .filter_map(|contract| {
            unique_single_use_implementor(project, contract).map(|implementation| {
                SingleUseCandidate {
                    contract,
                    implementation,
                }
            })
        })
        .collect()
}

fn unique_single_use_implementor<'a>(
    project: &'a Project,
    contract: &Class,
) -> Option<&'a Class> {
    let mut implementors = project.classes.iter().filter(|class| {
        class.interfaces.len() == 1
            && class.interfaces[0] == contract.name
            && class.parent.is_none()
            && !class.has_mixin
    });
    let implementation = implementors.next()?;
    implementors.next().is_none().then_some(implementation)
}

fn aggregate_single_use_usage<'a>(
    candidates: Vec<SingleUseCandidate<'a>>,
    project_source: &str,
) -> Vec<SingleUseUsage<'a>> {
    candidates
        .into_iter()
        .filter_map(|candidate| {
            let construction_pattern = Regex::new(&format!(
                r"\b{}\s*\(",
                regex::escape(&candidate.implementation.name)
            ))
            .ok()?;
            Some(SingleUseUsage {
                references: identifier_pattern(&candidate.contract.name)
                    .find_iter(project_source)
                    .count(),
                constructions: construction_pattern.find_iter(project_source).count(),
                candidate,
            })
        })
        .collect()
}

fn single_use_abstraction_qualifies(usage: &SingleUseUsage<'_>) -> bool {
    let mut methods = usage
        .candidate
        .implementation
        .methods
        .iter()
        .filter(|method| !method.is_static && !method.is_constructor);
    let Some(method) = methods.next() else {
        return false;
    };
    methods.next().is_none()
        && method.name == usage.candidate.contract.methods[0].name
        && usage.candidate.implementation.fields.is_empty()
        && is_small_behavior(&method.body)
        && usage.references <= 2
        && usage.constructions == 1
}

fn single_use_abstraction_finding(usage: SingleUseUsage<'_>) -> Finding {
    crate::oop_rules::single_use_abstraction_finding(
        "oop-single-use-abstraction",
        &usage.candidate.contract.name,
        &usage.candidate.implementation.name,
        &usage.candidate.contract.path,
        usage.candidate.contract.line,
        &usage.candidate.implementation.path,
    )
}

fn refused_bequests(project: &Project) -> Vec<Finding> {
    let mut findings = Vec::new();
    for base in project.classes.iter().filter(|class| {
        class
            .methods
            .iter()
            .filter(|method| !method.is_static && !method.is_constructor)
            .map(|method| &method.name)
            .collect::<BTreeSet<_>>()
            .len()
            >= 4
    }) {
        let methods = base
            .methods
            .iter()
            .filter(|method| !method.is_static && !method.is_constructor)
            .map(|method| method.name.clone())
            .collect::<BTreeSet<_>>();
        let rejecting = project
            .classes
            .iter()
            .filter(|class| class.parent.as_deref() == Some(base.name.as_str()))
            .filter_map(|class| {
                let rejected = class
                    .methods
                    .iter()
                    .filter(|method| {
                        method.is_override
                            && methods.contains(&method.name)
                            && throws_unsupported(&direct_body(&method.body))
                    })
                    .map(|method| method.name.clone())
                    .collect::<BTreeSet<_>>();
                (rejected.len() >= 2).then_some((class, rejected))
            })
            .collect::<Vec<_>>();
        let rejected = rejecting
            .iter()
            .flat_map(|(_, methods)| methods.iter().cloned())
            .collect::<BTreeSet<_>>();
        if rejecting.len() < 2 || rejected.len() < 3 {
            continue;
        }
        findings.push(finding(
            "oop-refused-bequest",
            &base.path,
            base.line,
            format!(
                "{} has {} inherited operations rejected by {} direct subclasses",
                base.name,
                rejected.len(),
                rejecting.len()
            ),
            "high",
            rejecting
                .iter()
                .map(|(class, _)| class.path.clone())
                .filter(|path| path != &base.path)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        ));
    }
    findings
}

struct MiddleManUsage<'a> {
    class: &'a Class,
    field: String,
    forwarding_count: usize,
    method_count: usize,
}

fn middle_men(project: &Project) -> Vec<Finding> {
    middle_man_candidates(project)
        .filter_map(aggregate_middle_man_usage)
        .filter(middle_man_qualifies)
        .map(middle_man_finding)
        .collect()
}

fn middle_man_candidates(project: &Project) -> impl Iterator<Item = &Class> {
    project
        .classes
        .iter()
        .filter(|class| class.parent.is_none() && class.interfaces.is_empty() && !class.has_mixin)
}

fn aggregate_middle_man_usage(class: &Class) -> Option<MiddleManUsage<'_>> {
    let private_fields = class
        .fields
        .iter()
        .filter(|field| !field.is_static && field.name.starts_with('_'))
        .map(|field| field.name.clone())
        .collect::<BTreeSet<_>>();
    if private_fields.is_empty() {
        return None;
    }
    let methods = class
        .methods
        .iter()
        .filter(|method| {
            !method.is_static && !method.is_constructor && !method.name.starts_with('_')
        })
        .collect::<Vec<_>>();
    if methods.len() < 5 {
        return None;
    }
    let mut forwarding = BTreeMap::<String, usize>::new();
    for method in &methods {
        if let Some(field) = direct_forward(method, &private_fields) {
            *forwarding.entry(field).or_default() += 1;
        }
    }
    let (field, forwarding_count) = forwarding
        .into_iter()
        .max_by(|left, right| left.1.cmp(&right.1).then_with(|| right.0.cmp(&left.0)))?;
    Some(MiddleManUsage {
        class,
        field,
        forwarding_count,
        method_count: methods.len(),
    })
}

fn middle_man_qualifies(usage: &MiddleManUsage<'_>) -> bool {
    usage.forwarding_count >= 4 && usage.forwarding_count * 5 >= usage.method_count * 4
}

fn middle_man_finding(usage: MiddleManUsage<'_>) -> Finding {
    finding(
        "oop-middle-man-delegation",
        &usage.class.path,
        usage.class.line,
        format!(
            "{} forwards {} of {} public methods unchanged to {}",
            usage.class.name, usage.forwarding_count, usage.method_count, usage.field
        ),
        "high",
        Vec::new(),
    )
}

fn direct_forward(method: &Method, fields: &BTreeSet<String>) -> Option<String> {
    let body = method.body.trim();
    let body = body.strip_prefix("return ").unwrap_or(body).trim();
    let body = body.strip_suffix(';').unwrap_or(body).trim();
    let capture = DIRECT_CALL.captures(body)?;
    if capture[2] != method.name || !fields.contains(&capture[1]) {
        return None;
    }
    let arguments = quote_aware_split_top_level_with_angles(&capture[3], b',')
        .into_iter()
        .filter(|argument| !argument.trim().is_empty())
        .map(|argument| argument.trim().to_owned())
        .collect::<Vec<_>>();
    let parameters = method
        .parameters
        .as_ref()?
        .iter()
        .map(|parameter| parameter.name.clone())
        .collect::<Vec<_>>();
    (arguments == parameters).then(|| capture[1].to_owned())
}

struct ObserverNotificationCandidate<'a> {
    class: &'a Class,
    field: String,
}

struct ObserverNotificationUsage<'a> {
    candidate: ObserverNotificationCandidate<'a>,
    callbacks: BTreeMap<String, BTreeSet<String>>,
}

fn observer_notifications(project: &Project) -> Vec<Finding> {
    let mut findings = Vec::new();
    for candidate in observer_notification_candidates(project).filter(observer_registration_complete)
    {
        emit_observer_notifications(
            aggregate_observer_notification_usage(candidate),
            &mut findings,
        );
    }
    findings
}

fn observer_notification_candidates(
    project: &Project,
) -> impl Iterator<Item = ObserverNotificationCandidate<'_>> {
    project
        .classes
        .iter()
        .filter(|class| !excluded_analysis_class(class))
        .flat_map(|class| {
            observer_fields(class)
                .into_iter()
                .map(move |field| ObserverNotificationCandidate { class, field })
        })
}

fn observer_fields(class: &Class) -> BTreeSet<String> {
    class
        .fields
        .iter()
        .filter(|field| {
            (field.type_name.starts_with("List<") || field.type_name.starts_with("Set<"))
                && matches!(
                    field.name.replace('_', "").to_ascii_lowercase().as_str(),
                    "listeners" | "observers"
                )
        })
        .map(|field| field.name.clone())
        .collect()
}

fn observer_registration_complete(candidate: &ObserverNotificationCandidate<'_>) -> bool {
    let Ok(add) = Regex::new(&format!(
        r"\b{}\s*\.\s*add\s*\(",
        regex::escape(&candidate.field)
    )) else {
        return false;
    };
    let Ok(remove) = Regex::new(&format!(
        r"\b{}\s*\.\s*remove\s*\(",
        regex::escape(&candidate.field)
    )) else {
        return false;
    };
    candidate
        .class
        .methods
        .iter()
        .any(|method| add.is_match(&direct_body(&method.body)))
        && candidate
            .class
            .methods
            .iter()
            .any(|method| remove.is_match(&direct_body(&method.body)))
}

fn aggregate_observer_notification_usage<'a>(
    candidate: ObserverNotificationCandidate<'a>,
) -> ObserverNotificationUsage<'a> {
    let mut callbacks = BTreeMap::<String, BTreeSet<String>>::new();
    for method in &candidate.class.methods {
        for callback in notification_callbacks(&direct_body(&method.body), &candidate.field) {
            callbacks
                .entry(callback)
                .or_default()
                .insert(method.name.clone());
        }
    }
    ObserverNotificationUsage {
        candidate,
        callbacks,
    }
}

fn qualified_observer_callbacks(
    callbacks: BTreeMap<String, BTreeSet<String>>,
) -> impl Iterator<Item = (String, BTreeSet<String>)> {
    callbacks
        .into_iter()
        .filter(|(_, methods)| methods.len() >= 3)
}

fn emit_observer_notifications(
    usage: ObserverNotificationUsage<'_>,
    findings: &mut Vec<Finding>,
) {
    for (callback, methods) in qualified_observer_callbacks(usage.callbacks) {
        findings.push(finding(
            "oop-repeated-observer-notification",
            &usage.candidate.class.path,
            usage.candidate.class.line,
            format!(
                "{} repeats {} traversal calling {} from {} methods",
                usage.candidate.class.name,
                usage.candidate.field,
                callback,
                methods.len()
            ),
            "high",
            Vec::new(),
        ));
    }
}

fn notification_callbacks(body: &str, field: &str) -> Vec<String> {
    let pattern = Regex::new(&format!(
        r"\bfor\s*\(\s*(?:final|var|[A-Za-z_$][\w$<>?]*)\s+([A-Za-z_$][\w$]*)\s+in\s+{}\s*\)",
        regex::escape(field)
    ))
    .unwrap();
    let mut callbacks = Vec::new();
    for capture in pattern.captures_iter(body) {
        let whole = capture.get(0).unwrap();
        let after = next_non_whitespace(body, whole.end());
        let loop_body = if body.as_bytes().get(after) == Some(&b'{') {
            matching_delimiter(body, after, b'{', b'}')
                .map(|close| &body[after + 1..close])
                .unwrap_or("")
        } else {
            let end = body[after..]
                .find(';')
                .map_or(body.len(), |offset| after + offset + 1);
            &body[after..end]
        };
        let calls = CALL_WITH_TARGET
            .captures_iter(loop_body)
            .collect::<Vec<_>>();
        if calls.len() == 1 && calls[0][1] == capture[1] {
            callbacks.push(calls[0][2].to_owned());
        }
    }
    callbacks
}

fn message_chains(project: &Project) -> Vec<Finding> {
    let mut findings = Vec::new();
    for class in project
        .classes
        .iter()
        .filter(|class| !excluded_analysis_class(class))
    {
        let mut count = 0;
        let mut methods = 0;
        let mut maximum = 0;
        for method in class.methods.iter().filter(|method| !method.is_constructor) {
            let direct = direct_body(&method.body);
            let depths = chain_depths(&direct);
            if depths.is_empty() {
                continue;
            }
            methods += 1;
            count += depths.len();
            maximum = maximum.max(depths.into_iter().max().unwrap_or(0));
        }
        if count >= 3 && methods >= 2 {
            findings.push(finding(
                "oop-message-chain",
                &class.path,
                class.line,
                format!(
                    "{} contains {} collaboration chains of at least four hops across {} methods (maximum {})",
                    class.name, count, methods, maximum
                ),
                "high",
                Vec::new(),
            ));
        }
    }
    findings
}

fn chain_depths(body: &str) -> Vec<usize> {
    let direct = direct_body(body);
    let source = dart_source_with_interpolations(&direct, &mask_strings(&direct));
    collect_chain_depths(&source)
}

fn collect_chain_depths(source: &str) -> Vec<usize> {
    let bytes = source.as_bytes();
    let mut depths = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if !(bytes[index].is_ascii_alphabetic() || matches!(bytes[index], b'_' | b'$')) {
            index += 1;
            continue;
        }
        let Some(depth) = chain_root_depth(source, index) else {
            index += 1;
            continue;
        };
        let cursor = chain_identifier_end(bytes, index);
        let cursor = skip_chain_call(source, cursor, &mut depths);
        index = traverse_chain(source, cursor, depth, &mut depths).max(index + 1);
    }
    depths
}

enum ChainTransition {
    Assertion,
    Index(usize),
    Member(usize),
    Stop,
}

fn traverse_chain(
    source: &str,
    mut cursor: usize,
    mut depth: usize,
    depths: &mut Vec<usize>,
) -> usize {
    let mut recordable = true;
    loop {
        cursor = next_non_whitespace(source, cursor);
        match chain_transition(source, cursor, depths) {
            ChainTransition::Assertion => {
                record_chain_depth(depth, recordable, depths);
                depth = 0;
                recordable = false;
                cursor += 1;
            }
            ChainTransition::Index(close) => {
                depths.extend(chain_depths(&source[cursor + 1..close]));
                depth += 1;
                recordable = false;
                cursor = close + 1;
            }
            ChainTransition::Member(next) => {
                depth += 1;
                recordable = true;
                cursor = next;
            }
            ChainTransition::Stop => break,
        }
    }
    record_chain_depth(depth, recordable, depths);
    cursor
}

fn chain_transition(source: &str, cursor: usize, depths: &mut Vec<usize>) -> ChainTransition {
    let bytes = source.as_bytes();
    match bytes.get(cursor) {
        Some(b'!') => ChainTransition::Assertion,
        Some(b'[') => matching_delimiter(source, cursor, b'[', b']')
            .map_or(ChainTransition::Stop, ChainTransition::Index),
        _ => next_chain_member(source, cursor, depths)
            .map_or(ChainTransition::Stop, ChainTransition::Member),
    }
}

fn next_chain_member(source: &str, cursor: usize, depths: &mut Vec<usize>) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut cursor = match (bytes.get(cursor), bytes.get(cursor + 1)) {
        (Some(b'?'), Some(b'.')) => cursor + 2,
        (Some(b'.'), next) if next != Some(&b'.') => cursor + 1,
        _ => return None,
    };
    cursor = next_non_whitespace(source, cursor);
    if !bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(*byte, b'_' | b'$'))
    {
        return None;
    }
    cursor = chain_identifier_end(bytes, cursor);
    Some(skip_chain_call(source, cursor, depths))
}

fn record_chain_depth(depth: usize, recordable: bool, depths: &mut Vec<usize>) {
    if recordable && depth >= 4 {
        depths.push(depth);
    }
}

fn chain_identifier_end(bytes: &[u8], mut cursor: usize) -> usize {
    cursor += 1;
    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'$'))
    {
        cursor += 1;
    }
    cursor
}

enum ChainRootCandidate {
    Independent,
    Member { dot: usize },
}

fn chain_root_depth(source: &str, index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    qualify_chain_root(bytes, parse_chain_root_candidate(bytes, index)?)
}

fn parse_chain_root_candidate(bytes: &[u8], index: usize) -> Option<ChainRootCandidate> {
    if index == 0 {
        return Some(ChainRootCandidate::Independent);
    }
    let previous = previous_non_whitespace_byte(bytes, index);
    if previous == 0 || (previous < index && bytes[previous - 1] != b'.') {
        return Some(ChainRootCandidate::Independent);
    }
    match bytes[previous - 1] {
        byte if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$') => None,
        b'.' => Some(ChainRootCandidate::Member { dot: previous - 1 }),
        _ => Some(ChainRootCandidate::Independent),
    }
}

fn qualify_chain_root(bytes: &[u8], candidate: ChainRootCandidate) -> Option<usize> {
    match candidate {
        ChainRootCandidate::Independent => Some(0),
        ChainRootCandidate::Member { dot } => {
            let receiver = member_receiver_end(bytes, dot);
            bytes
                .get(receiver.checked_sub(1)?)
                .is_some_and(|byte| matches!(*byte, b')' | b'!'))
                .then_some(1)
        }
    }
}

fn skip_chain_call(source: &str, offset: usize, depths: &mut Vec<usize>) -> usize {
    let mut open = next_non_whitespace(source, offset);
    if source.as_bytes().get(open) == Some(&b'<') {
        let Some(close) = matching_delimiter(source, open, b'<', b'>') else {
            return offset;
        };
        open = next_non_whitespace(source, close + 1);
    }
    if source.as_bytes().get(open) != Some(&b'(') {
        return offset;
    }
    matching_delimiter(source, open, b'(', b')').map_or(offset, |close| {
        depths.extend(chain_depths(&source[open + 1..close]));
        close + 1
    })
}

struct FeatureEnvyCandidate<'a> {
    class: &'a Class,
    method: &'a Method,
    parameters: Vec<&'a Parameter>,
}

struct FeatureEnvyMatch<'a> {
    class: &'a Class,
    method: &'a Method,
    parameter: &'a Parameter,
    access_count: usize,
    distinct_members: usize,
}

#[derive(Default)]
struct ParameterAccessSummary {
    count: usize,
    members: BTreeSet<String>,
}

fn feature_envy(project: &Project) -> Vec<Finding> {
    collect_feature_envy_candidates(project)
        .into_iter()
        .filter_map(|candidate| qualify_feature_envy(project, candidate))
        .map(feature_envy_finding)
        .collect()
}

fn collect_feature_envy_candidates(project: &Project) -> Vec<FeatureEnvyCandidate<'_>> {
    let mut candidates = Vec::new();
    for class in project
        .classes
        .iter()
        .filter(|class| !excluded_analysis_class(class))
    {
        for method in class.methods.iter().filter(|method| !method.is_static) {
            let Some(parameters) = &method.parameters else {
                continue;
            };
            let parameters = parameters
                .iter()
                .filter(|parameter| {
                    base_type(&parameter.type_name) != class.name && parameter.type_name != "String"
                })
                .collect::<Vec<_>>();
            if parameters.is_empty() || excluded_feature_envy_projection(method) {
                continue;
            }
            candidates.push(FeatureEnvyCandidate {
                class,
                method,
                parameters,
            });
        }
    }
    candidates
}

fn excluded_feature_envy_projection(method: &Method) -> bool {
    method.return_type.as_deref().is_some_and(|return_type| {
        return_type == "Map" || return_type.starts_with("Map<")
    }) || returns_constructed_projection(method)
}

fn qualify_feature_envy<'a>(
    project: &Project,
    candidate: FeatureEnvyCandidate<'a>,
) -> Option<FeatureEnvyMatch<'a>> {
    let unmasked = direct_body(&candidate.method.body);
    let direct = dart_source_with_interpolations(&unmasked, &mask_strings(&unmasked));
    let received = received_access_count(&direct);
    let access = aggregate_parameter_accesses(&direct, &candidate.parameters)?;
    let mut best: Option<FeatureEnvyMatch<'a>> = None;
    for parameter in candidate.parameters {
        let Some(summary) = access.get(parameter.name.as_str()) else {
            continue;
        };
        if qualifies_feature_envy(summary, received)
            && best
                .as_ref()
                .is_none_or(|best| summary.count > best.access_count)
        {
            best = Some(FeatureEnvyMatch {
                class: candidate.class,
                method: candidate.method,
                parameter,
                access_count: summary.count,
                distinct_members: summary.members.len(),
            });
        }
    }
    best.filter(|best| {
        !flutter_widget_composition(
            project,
            best.class,
            best.method,
            best.parameter,
            best.access_count,
        )
    })
}

fn qualifies_feature_envy(summary: &ParameterAccessSummary, received: usize) -> bool {
    summary.count >= 5
        && summary.members.len() >= 3
        && summary.count * 5 >= received * 3
}

fn feature_envy_finding(envy: FeatureEnvyMatch<'_>) -> Finding {
    finding(
        "oop-feature-envy",
        &envy.class.path,
        envy.method.line,
        format!(
            "{}.{} accesses {} parameter {} {} times across {} members",
            envy.class.name,
            envy.method.name,
            envy.parameter.type_name,
            envy.parameter.name,
            envy.access_count,
            envy.distinct_members
        ),
        "high",
        Vec::new(),
    )
}

fn aggregate_parameter_accesses<'a>(
    source: &str,
    parameters: &[&'a Parameter],
) -> Option<BTreeMap<&'a str, ParameterAccessSummary>> {
    let names = parameters
        .iter()
        .map(|parameter| regex::escape(&parameter.name))
        .collect::<Vec<_>>()
        .join("|");
    let direct = Regex::new(&format!(
        r"\b({names})\s*(?:\?\s*\.|\.)\s*([A-Za-z_$][\w$]*)"
    ))
    .ok()?;
    let cascade = Regex::new(&format!(
        r"\b({names})\s*(?:\?\s*\.\s*\.|\.\s*\.)"
    ))
    .ok()?;
    let mut summaries = parameters
        .iter()
        .map(|parameter| (parameter.name.as_str(), ParameterAccessSummary::default()))
        .collect::<BTreeMap<_, _>>();

    for capture in direct.captures_iter(source) {
        let Some(parameter) = capture.get(1) else {
            continue;
        };
        let Some(member) = capture.get(2) else {
            continue;
        };
        if let Some(summary) = summaries.get_mut(parameter.as_str()) {
            summary.count += 1;
            summary.members.insert(member.as_str().to_owned());
        }
    }
    for capture in cascade.captures_iter(source) {
        let Some(whole) = capture.get(0) else {
            continue;
        };
        let Some(parameter) = capture.get(1) else {
            continue;
        };
        let end = source[whole.start()..]
            .find(';')
            .map_or(source.len(), |offset| whole.start() + offset + 1);
        let Some(summary) = summaries.get_mut(parameter.as_str()) else {
            continue;
        };
        for member in CASCADE_MEMBER_ACCESS.captures_iter(&source[whole.start()..end]) {
            let Some(member) = member.get(1) else {
                continue;
            };
            summary.count += 1;
            summary.members.insert(member.as_str().to_owned());
        }
    }
    Some(summaries)
}

static CASCADE_MEMBER_ACCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\?\s*\.\s*\.|\.\s*\.)\s*([A-Za-z_$][\w$]*)").unwrap()
});

fn received_access_count(source: &str) -> usize {
    let bytes = source.as_bytes();
    (1..bytes.len().saturating_sub(1))
        .filter(|index| is_received_member_access(bytes, *index))
        .count()
}

fn is_received_member_access(bytes: &[u8], index: usize) -> bool {
    if bytes[index] != b'.'
        || is_decimal_separator(bytes, index)
        || bytes[index - 1] == b'.'
        || bytes[index + 1] == b'.'
    {
        return false;
    }
    let before = member_receiver_end(bytes, index);
    let after = next_non_whitespace_byte(bytes, index + 1);
    before > 0
        && is_member_receiver_byte(bytes[before - 1])
        && bytes
            .get(after)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(*byte, b'_' | b'$'))
}

fn is_decimal_separator(bytes: &[u8], index: usize) -> bool {
    bytes[index - 1].is_ascii_digit() && bytes[index + 1].is_ascii_digit()
}

fn member_receiver_end(bytes: &[u8], dot: usize) -> usize {
    let mut before = previous_non_whitespace_byte(bytes, dot);
    if before > 0 && bytes[before - 1] == b'?' {
        before = previous_non_whitespace_byte(bytes, before - 1);
    }
    before
}

fn previous_non_whitespace_byte(bytes: &[u8], mut end: usize) -> usize {
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    end
}

fn next_non_whitespace_byte(bytes: &[u8], mut start: usize) -> usize {
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    start
}

fn is_member_receiver_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b')' | b']')
}

fn returns_constructed_projection(method: &Method) -> bool {
    let Some(return_type) = method.return_type.as_deref() else {
        return false;
    };
    let target = base_type(return_type);
    let body = method.body.trim();
    !body.contains(';')
        && Regex::new(&format!(r"^{}\s*\(", regex::escape(&target)))
            .unwrap()
            .is_match(body)
}

fn flutter_widget_composition(
    project: &Project,
    class: &Class,
    method: &Method,
    parameter: &Parameter,
    count: usize,
) -> bool {
    if method.return_type.as_deref() != Some("Widget")
        || !project
            .sources
            .get(&class.path)
            .is_some_and(|source| source.contains("import 'package:flutter/"))
    {
        return false;
    }
    let returned = if !method.body.contains(';') {
        method.body.as_str()
    } else if let Some(index) = method.body.rfind("return ") {
        &method.body[index + 7..]
    } else {
        ""
    };
    Regex::new(&format!(
        r"\b{}\s*\.\s*[A-Za-z_$][\w$]*",
        regex::escape(&parameter.name)
    ))
    .unwrap()
    .find_iter(returned)
    .count()
        == count
}

type ServiceLocatorGroups<'a> = BTreeMap<String, Vec<(&'a Class, BTreeSet<String>)>>;

struct QualifiedServiceLocator<'a> {
    locator: String,
    first: &'a Class,
    service_count: usize,
    class_count: usize,
    paths: BTreeSet<String>,
}

fn service_locators(project: &Project) -> Vec<Finding> {
    collect_service_locator_groups(project)
        .into_iter()
        .filter_map(|(locator, uses)| qualify_service_locator(locator, uses))
        .map(service_locator_finding)
        .collect()
}

fn collect_service_locator_groups(project: &Project) -> ServiceLocatorGroups<'_> {
    let mut groups = ServiceLocatorGroups::new();
    for class in project
        .classes
        .iter()
        .filter(|class| !excluded_analysis_class(class))
    {
        for (locator, services) in class_service_locator_uses(class) {
            groups.entry(locator).or_default().push((class, services));
        }
    }
    groups
}

fn class_service_locator_uses(class: &Class) -> BTreeMap<String, BTreeSet<String>> {
    let mut services = BTreeMap::<String, BTreeSet<String>>::new();
    for method in &class.methods {
        let body = direct_body(&method.body);
        for capture in DART_LOCATOR.captures_iter(&body) {
            let Some(locator) = capture.get(1).or_else(|| capture.get(2)) else {
                continue;
            };
            let Some(service) = capture.get(3) else {
                continue;
            };
            if is_locator_name(locator.as_str()) {
                services
                    .entry(locator.as_str().to_owned())
                    .or_default()
                    .insert(service.as_str().to_owned());
            }
        }
    }
    services
}

fn qualify_service_locator<'a>(
    locator: String,
    mut uses: Vec<(&'a Class, BTreeSet<String>)>,
) -> Option<QualifiedServiceLocator<'a>> {
    let classes = uses
        .iter()
        .map(|(class, _)| format!("{}:{}", class.path, class.name))
        .collect::<BTreeSet<_>>();
    let paths = uses
        .iter()
        .map(|(class, _)| class.path.clone())
        .collect::<BTreeSet<_>>();
    let services = uses
        .iter()
        .flat_map(|(_, services)| services.iter().cloned())
        .collect::<BTreeSet<_>>();
    if classes.len() < 3 || paths.len() < 2 || services.len() < 3 {
        return None;
    }
    uses.sort_by(|left, right| {
        left.0
            .path
            .cmp(&right.0.path)
            .then_with(|| left.0.line.cmp(&right.0.line))
    });
    let first = uses.first().map(|(class, _)| *class)?;
    Some(QualifiedServiceLocator {
        locator,
        first,
        service_count: services.len(),
        class_count: classes.len(),
        paths,
    })
}

fn service_locator_finding(usage: QualifiedServiceLocator<'_>) -> Finding {
    finding(
        "oop-service-locator-dependency",
        &usage.first.path,
        usage.first.line,
        format!(
            "{} resolves {} service types from {} classes across {} files",
            usage.locator,
            usage.service_count,
            usage.class_count,
            usage.paths.len()
        ),
        "high",
        usage
            .paths
            .into_iter()
            .filter(|path| path != &usage.first.path)
            .collect(),
    )
}

#[derive(Clone, Copy)]
struct BoundaryPolicy {
    role: &'static str,
    suffix: &'static str,
    rule: &'static str,
    minimum_covered: usize,
    minimum_direct: usize,
}

const BOUNDARY_POLICIES: [BoundaryPolicy; 4] = [
    BoundaryPolicy {
        role: "factory",
        suffix: "Factory",
        rule: "oop-factory-bypass",
        minimum_covered: 1,
        minimum_direct: 1,
    },
    BoundaryPolicy {
        role: "facade",
        suffix: "Facade",
        rule: "oop-facade-bypass",
        minimum_covered: 3,
        minimum_direct: 2,
    },
    BoundaryPolicy {
        role: "repository",
        suffix: "Repository",
        rule: "oop-repository-bypass",
        minimum_covered: 1,
        minimum_direct: 1,
    },
    BoundaryPolicy {
        role: "proxy",
        suffix: "Proxy",
        rule: "oop-proxy-bypass",
        minimum_covered: 1,
        minimum_direct: 1,
    },
];

struct BoundaryCandidate<'a> {
    abstraction: &'a Class,
    policy: BoundaryPolicy,
    covered: BTreeSet<String>,
}

struct BoundaryBypass {
    path: String,
    offset: usize,
    direct_types: Vec<String>,
}

struct BoundaryUsage {
    use_count: usize,
    bypasses: Vec<BoundaryBypass>,
}

fn boundary_bypasses(project: &Project) -> Vec<Finding> {
    let candidates = collect_boundary_candidates(project);
    if candidates.is_empty() {
        return Vec::new();
    }
    let masked_sources = project
        .sources
        .iter()
        .map(|(path, source)| (path.as_str(), mask_strings(source)))
        .collect::<Vec<_>>();
    let mut findings = Vec::new();
    for candidate in candidates {
        let Some(usage) = aggregate_boundary_usage(&candidate, &masked_sources)
            .and_then(qualify_boundary_usage)
        else {
            continue;
        };
        findings.extend(boundary_bypass_findings(project, &candidate, usage));
    }
    findings
}

fn collect_boundary_candidates(project: &Project) -> Vec<BoundaryCandidate<'_>> {
    let mut candidates = Vec::new();
    for policy in BOUNDARY_POLICIES {
        for abstraction in project
            .classes
            .iter()
            .filter(|class| class.name.ends_with(policy.suffix))
        {
            let covered = covered_types(abstraction, policy.role);
            if covered.len() >= policy.minimum_covered {
                candidates.push(BoundaryCandidate {
                    abstraction,
                    policy,
                    covered,
                });
            }
        }
    }
    candidates
}

fn aggregate_boundary_usage(
    candidate: &BoundaryCandidate<'_>,
    sources: &[(&str, String)],
) -> Option<BoundaryUsage> {
    let boundary_pattern = identifier_pattern(&candidate.abstraction.name);
    let direct_patterns = candidate
        .covered
        .iter()
        .map(|type_name| {
            boundary_direct_pattern(type_name, candidate.policy.role)
                .map(|pattern| (type_name, pattern))
        })
        .collect::<Option<Vec<_>>>()?;
    let mut use_count = 0;
    let mut bypasses = Vec::new();
    for (path, code) in sources {
        if *path == candidate.abstraction.path {
            continue;
        }
        use_count += usize::from(boundary_pattern.is_match(code));
        let direct = collect_direct_boundary_accesses(code, &direct_patterns);
        if direct.len() >= candidate.policy.minimum_direct {
            bypasses.push(BoundaryBypass {
                path: (*path).to_owned(),
                offset: direct[0].1,
                direct_types: direct
                    .into_iter()
                    .map(|(type_name, _)| type_name.to_owned())
                    .collect(),
            });
        }
    }
    Some(BoundaryUsage {
        use_count,
        bypasses,
    })
}

fn boundary_direct_pattern(type_name: &str, role: &str) -> Option<Regex> {
    if role == "factory" {
        Regex::new(&format!(r"\b{}\s*\(", regex::escape(type_name))).ok()
    } else {
        Some(identifier_pattern(type_name))
    }
}

fn collect_direct_boundary_accesses<'a>(
    source: &str,
    patterns: &[(&'a String, Regex)],
) -> Vec<(&'a str, usize)> {
    let mut direct = patterns
        .iter()
        .filter_map(|(type_name, pattern)| {
            pattern
                .find(source)
                .map(|matched| (type_name.as_str(), matched.start()))
        })
        .collect::<Vec<_>>();
    direct.sort_by_key(|(_, offset)| *offset);
    direct
}

fn qualify_boundary_usage(usage: BoundaryUsage) -> Option<BoundaryUsage> {
    (usage.use_count >= 3 && usage.use_count > usage.bypasses.len()).then_some(usage)
}

fn boundary_bypass_findings(
    project: &Project,
    candidate: &BoundaryCandidate<'_>,
    usage: BoundaryUsage,
) -> Vec<Finding> {
    let use_count = usage.use_count;
    usage
        .bypasses
        .into_iter()
        .map(|mut bypass| {
            bypass.direct_types.sort();
            let line = project
                .sources
                .get(&bypass.path)
                .map_or(1, |source| line_at(source, bypass.offset));
            finding(
                candidate.policy.rule,
                &bypass.path,
                line,
                format!(
                    "{} accesses {} directly although {} is used by {} external files and is the dominant {} boundary",
                    bypass.path,
                    bypass.direct_types.join(", "),
                    candidate.abstraction.name,
                    use_count,
                    candidate.policy.role
                ),
                "high",
                Vec::new(),
            )
        })
        .collect()
}

fn covered_types(class: &Class, role: &str) -> BTreeSet<String> {
    if role == "factory" {
        let mut types = BTreeSet::new();
        for method in &class.methods {
            let body = direct_body(&method.body);
            types.extend(
                TYPE_CALL
                    .captures_iter(&body)
                    .map(|capture| base_type(&capture[1]))
                    .filter(|type_name| type_name != &class.name)
                    .filter(|type_name| {
                        !type_name.ends_with("Error") && !type_name.ends_with("Exception")
                    }),
            );
        }
        return types;
    }
    class
        .fields
        .iter()
        .filter(|field| !field.is_static)
        .map(|field| base_type(&field.type_name))
        .filter(|type_name| !IGNORED_TYPES.contains(&type_name.as_str()))
        .filter(|type_name| {
            role != "repository"
                || ["Client", "Dao", "Database", "DataSource", "Store"]
                    .iter()
                    .any(|suffix| type_name.ends_with(suffix))
        })
        .collect()
}

fn repeated_adapter_mappings(project: &Project) -> Vec<Finding> {
    let mut groups = BTreeMap::<String, Vec<(String, usize)>>::new();
    for (path, method) in all_methods(project) {
        let Some(parameters) = &method.parameters else {
            continue;
        };
        let Some(return_type) = method.return_type.as_deref() else {
            continue;
        };
        if parameters.len() != 1 {
            continue;
        }
        let parameter = &parameters[0];
        let target = base_type(return_type);
        let body = direct_body(&method.body);
        let matches = constructor_mappings(&body, &target, &parameter.name);
        if matches.len() != 1 || matches[0].len() < 3 {
            continue;
        }
        let mut fields = matches[0].clone();
        fields.sort();
        groups
            .entry(
                std::iter::once(base_type(&parameter.type_name))
                    .chain(std::iter::once(target))
                    .chain(fields)
                    .collect::<Vec<_>>()
                    .join("|"),
            )
            .or_default()
            .push((path.to_owned(), method.line));
    }
    let mut findings = Vec::new();
    for (key, mut occurrences) in groups {
        let paths = occurrences
            .iter()
            .map(|(path, _)| path.clone())
            .collect::<BTreeSet<_>>();
        if !is_distributed_repetition(occurrences.len(), paths.len()) {
            continue;
        }
        occurrences.sort();
        let first = &occurrences[0];
        let parts = key.split('|').collect::<Vec<_>>();
        findings.push(finding(
            "oop-repeated-adapter-mapping",
            &first.0,
            first.1,
            format!(
                "{} to {} mapping is repeated in {} functions across {} files",
                parts[0],
                parts[1],
                occurrences.len(),
                paths.len()
            ),
            "high",
            paths.into_iter().filter(|path| path != &first.0).collect(),
        ));
    }
    findings
}

fn constructor_mappings(body: &str, target: &str, source: &str) -> Vec<Vec<String>> {
    let pattern = Regex::new(&format!(r"\b{}\s*\(", regex::escape(target))).unwrap();
    let mut matches = Vec::new();
    for call in pattern.find_iter(body) {
        let open = call.end() - 1;
        let Some(close) = matching_delimiter(body, open, b'(', b')') else {
            continue;
        };
        let mut fields = Vec::new();
        let mut valid = true;
        for argument in quote_aware_split_top_level_with_angles(&body[open + 1..close], b',') {
            if argument.trim().is_empty() {
                continue;
            }
            let regex = Regex::new(&format!(
                r"^\s*([A-Za-z_$][\w$]*)\s*:\s*{}\.([A-Za-z_$][\w$]*)\s*$",
                regex::escape(source)
            ))
            .unwrap();
            if let Some(capture) = regex.captures(argument) {
                fields.push(format!("{}={}", &capture[1], &capture[2]));
            } else {
                valid = false;
                break;
            }
        }
        if valid && !fields.is_empty() {
            matches.push(fields);
        }
    }
    matches
}

struct Workflow<'a> {
    class: &'a Class,
    method: &'a Method,
    calls: Vec<String>,
}

struct TemplateWorkflowMatch<'workflow, 'project> {
    left: &'workflow Workflow<'project>,
    right: &'workflow Workflow<'project>,
    varying_call: usize,
}

fn template_workflows(project: &Project) -> Vec<Finding> {
    let workflows = collect_template_workflow_candidates(project);
    aggregate_template_workflow_matches(&workflows)
        .into_iter()
        .filter_map(template_workflow_finding)
        .collect()
}

fn collect_template_workflow_candidates(project: &Project) -> Vec<Workflow<'_>> {
    let mut workflows = Vec::new();
    for class in project
        .classes
        .iter()
        .filter(|class| class.parent.is_some())
    {
        for method in class.methods.iter().filter(|method| {
            method.is_override && method.name != "analyze" && !method.name.starts_with("visit")
        }) {
            let calls = call_names(&direct_body(&method.body));
            if (4..=10).contains(&calls.len()) {
                workflows.push(Workflow {
                    class,
                    method,
                    calls,
                });
            }
        }
    }
    workflows.sort_by(|left, right| {
        left.class
            .path
            .cmp(&right.class.path)
            .then_with(|| left.method.line.cmp(&right.method.line))
    });
    workflows
}

fn aggregate_template_workflow_matches<'workflow, 'project>(
    workflows: &'workflow [Workflow<'project>],
) -> Vec<TemplateWorkflowMatch<'workflow, 'project>> {
    let mut matches = Vec::new();
    let mut reported = BTreeSet::new();
    for (left_index, left) in workflows.iter().enumerate() {
        for right in &workflows[left_index + 1..] {
            let Some(varying_call) = workflow_variation(left, right) else {
                continue;
            };
            if reported.insert(workflow_pair_key(left, right)) {
                matches.push(TemplateWorkflowMatch {
                    left,
                    right,
                    varying_call,
                });
            }
        }
    }
    matches
}

fn workflow_variation(left: &Workflow<'_>, right: &Workflow<'_>) -> Option<usize> {
    if left.class.path == right.class.path
        || left.class.parent != right.class.parent
        || left.method.name != right.method.name
        || left.calls.len() != right.calls.len()
    {
        return None;
    }
    let mut varying = None;
    for (index, (left_call, right_call)) in left.calls.iter().zip(&right.calls).enumerate() {
        if left_call == right_call {
            continue;
        }
        if varying.replace(index).is_some() {
            return None;
        }
    }
    varying
}

fn workflow_pair_key(left: &Workflow<'_>, right: &Workflow<'_>) -> String {
    let (first, second) = if left.class.name <= right.class.name {
        (&left.class.name, &right.class.name)
    } else {
        (&right.class.name, &left.class.name)
    };
    format!("{first}|{second}")
}

fn template_workflow_finding(workflow: TemplateWorkflowMatch<'_, '_>) -> Option<Finding> {
    let left_varying = workflow.left.calls.get(workflow.varying_call)?;
    let right_varying = workflow.right.calls.get(workflow.varying_call)?;
    Some(finding(
        "oop-template-workflow-candidate",
        &workflow.left.class.path,
        workflow.left.method.line,
        format!(
            "{}.{} and {}.{} repeat {} calls and vary only {} versus {}",
            workflow.left.class.name,
            workflow.left.method.name,
            workflow.right.class.name,
            workflow.right.method.name,
            workflow.left.calls.len() - 1,
            left_varying,
            right_varying
        ),
        "high",
        vec![workflow.right.class.path.clone()],
    ))
}

fn all_methods(project: &Project) -> Vec<(&str, &Method)> {
    project
        .functions
        .iter()
        .map(|(path, method)| (path.as_str(), method))
        .chain(project.classes.iter().flat_map(|class| {
            class
                .methods
                .iter()
                .map(|method| (class.path.as_str(), method))
        }))
        .collect()
}

struct SwitchBlock {
    expression: String,
    body: String,
    start: usize,
}

fn switch_blocks(body: &str) -> Vec<SwitchBlock> {
    let mut result = Vec::new();
    for matched in SWITCH_START.find_iter(body) {
        let Some(round_open) = body[matched.start()..matched.end()]
            .find('(')
            .map(|offset| matched.start() + offset)
        else {
            continue;
        };
        let Some(round_close) = matching_delimiter(body, round_open, b'(', b')') else {
            continue;
        };
        let curly_open = next_non_whitespace(body, round_close + 1);
        if body.as_bytes().get(curly_open) != Some(&b'{') {
            continue;
        }
        let Some(curly_close) = matching_delimiter(body, curly_open, b'{', b'}') else {
            continue;
        };
        result.push(SwitchBlock {
            expression: body[round_open + 1..round_close].to_owned(),
            body: body[curly_open + 1..curly_close].to_owned(),
            start: matched.start(),
        });
    }
    result
}

fn switch_cases(body: &str) -> Vec<(String, String)> {
    let labels = CASE_LABEL
        .captures_iter(body)
        .filter_map(|capture| {
            let whole = capture.get(0)?;
            let label = capture.get(1)?;
            Some((
                whole.start(),
                whole.end(),
                WHITESPACE.replace_all(label.as_str().trim(), " ").into_owned(),
            ))
        })
        .collect::<Vec<_>>();
    let mut cases = Vec::with_capacity(labels.len());
    let mut labels = labels.into_iter().peekable();
    while let Some((_, start, label)) = labels.next() {
        let end = labels
            .peek()
            .map_or(body.len(), |(next_start, _, _)| *next_start);
        if let Some(case_body) = body.get(start..end) {
            cases.push((label, case_body.to_owned()));
        }
    }
    cases
}

fn is_distributed_repetition(occurrences: usize, paths: usize) -> bool {
    occurrences >= 3 && paths >= 2
}

fn grouped_occurrence_findings(
    groups: BTreeMap<String, Vec<(String, usize)>>,
    code: &str,
    confidence: &str,
    message: impl Fn(&str, usize, usize) -> String,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (key, mut occurrences) in groups {
        let paths = occurrences
            .iter()
            .map(|(path, _)| path.clone())
            .collect::<BTreeSet<_>>();
        if !is_distributed_repetition(occurrences.len(), paths.len()) {
            continue;
        }
        occurrences.sort();
        let first = &occurrences[0];
        findings.push(finding(
            code,
            &first.0,
            first.1,
            message(&key, occurrences.len(), paths.len()),
            confidence,
            paths.into_iter().filter(|path| path != &first.0).collect(),
        ));
    }
    findings
}

fn call_names(body: &str) -> Vec<String> {
    CALL_NAME
        .captures_iter(body)
        .filter_map(|capture| {
            let whole = capture.get(0).unwrap();
            let previous = body[..whole.start()]
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .rfind(|word| !word.is_empty());
            let name = capture[1].to_owned();
            (!CONTROL_WORDS.contains(&name.as_str()) && !matches!(previous, Some("const" | "new")))
                .then_some(name)
        })
        .collect()
}

fn throws_unsupported(body: &str) -> bool {
    UNSUPPORTED_THROW.is_match(body)
}

fn is_small_behavior(body: &str) -> bool {
    let body = body.trim();
    !body.is_empty()
        && body.len() <= 180
        && !COMPLEX_BEHAVIOR.is_match(body)
        && !TYPE_CALL.is_match(body)
}

fn excluded_analysis_class(class: &Class) -> bool {
    class
        .parent
        .as_deref()
        .is_some_and(|parent| parent.ends_with("AstVisitor"))
        || class.name.ends_with("Analysis")
        || class.name.ends_with("RulePack")
}

#[cfg(test)]
mod panic_hardening_tests {
    use std::collections::BTreeMap;

    use super::{analyze, call_names, switch_blocks, switch_cases};

    #[test]
    fn skips_incomplete_switches_without_changing_complete_case_parsing() {
        let blocks = switch_blocks(
            "switch (unfinished\n\
             switch (kind) {\n\
               case Kind.alpha: runAlpha();\n\
               case Kind.beta when enabled: runBeta();\n\
               case Kind.gamma: runGamma();\n\
             }",
        );

        assert_eq!(blocks.len(), 1);
        let cases = switch_cases(&blocks[0].body);
        assert_eq!(
            cases
                .iter()
                .map(|(label, _)| label.as_str())
                .collect::<Vec<_>>(),
            ["Kind.alpha", "Kind.beta", "Kind.gamma"]
        );
        assert_eq!(
            cases
                .iter()
                .flat_map(|(_, body)| call_names(body))
                .collect::<Vec<_>>(),
            ["runAlpha", "runBeta", "runGamma"]
        );
        assert!(switch_cases("case Kind.unfinished").is_empty());
    }

    #[test]
    fn malformed_locator_calls_do_not_change_the_valid_finding() {
        let sources = BTreeMap::from([
            (
                "lib/first.dart".to_owned(),
                "class First {\n\
                   void load() { locator<Foo>(); locator<; }\n\
                 }\n\
                 class Second {\n\
                   void load() { locator<Bar>(); locator.get<; }\n\
                 }\n"
                .to_owned(),
            ),
            (
                "lib/second.dart".to_owned(),
                "class Third {\n\
                   void load() { locator<Baz>(); }\n\
                 }\n"
                .to_owned(),
            ),
        ]);

        let findings = analyze(&sources)
            .into_iter()
            .filter(|finding| finding.code == "oop-service-locator-dependency")
            .collect::<Vec<_>>();

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].message,
            "locator resolves 3 service types from 3 classes across 2 files"
        );
    }
}
