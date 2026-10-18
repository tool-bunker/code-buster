fn data_clumps(project: &Project) -> Vec<Finding> {
    collect_data_clump_groups(project)
        .into_values()
        .filter_map(data_clump_finding)
        .collect()
}

fn collect_data_clump_groups(project: &Project) -> BTreeMap<String, ParameterGroup> {
    let mut groups = BTreeMap::new();
    for owner in project
        .classes
        .iter()
        .filter(|owner| !is_typescript(&owner.path))
    {
        for method in &owner.methods {
            add_parameter_group(
                &mut groups,
                &owner.path,
                owner.line,
                &method.name,
                &method.parameters,
            );
        }
    }
    for (path, source) in project
        .sources
        .iter()
        .filter(|(path, _)| is_typescript(path))
    {
        add_typescript_parameter_groups(&mut groups, path, source);
    }
    groups
}

fn add_typescript_parameter_groups(
    groups: &mut BTreeMap<String, ParameterGroup>,
    path: &str,
    source: &str,
) {
    let mut line = 1;
    let mut start = 0;
    loop {
        let end = source[start..]
            .find('\n')
            .map_or(source.len(), |relative| start + relative);
        if let Some((name, function_parameters)) =
            typescript_callable_parameters(&source[start..], end - start)
        {
            add_parameter_group(groups, path, line, name, &function_parameters);
        }
        if end == source.len() {
            break;
        }
        start = end + 1;
        line += 1;
    }
}

fn typescript_callable_parameters(
    source: &str,
    line_end: usize,
) -> Option<(&str, Vec<Parameter>)> {
    if !source[..line_end].contains('(') {
        return None;
    }
    let declaration = TS_CLUMP_CALLABLE.captures(source)?;
    if declaration.get(0)?.start() != 0 {
        return None;
    }
    let name = declaration.get(1)?.as_str();
    if matches!(name, "return" | "if" | "for" | "while" | "switch" | "catch") {
        return None;
    }
    Some((name, parameters(declaration.get(2)?.as_str(), true)?))
}

fn data_clump_finding(mut group: ParameterGroup) -> Option<Finding> {
    let paths = group
        .declarations
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<BTreeSet<_>>();
    let mut declaration_name_counts = BTreeMap::<&str, usize>::new();
    for name in &group.declaration_names {
        *declaration_name_counts.entry(name).or_default() += 1;
    }
    let mirrored_operation_family = declaration_name_counts
        .values()
        .all(|declarations| *declarations >= 2);
    if group.declarations.len() < 3
        || paths.len() < 2
        || declaration_name_counts.len() < 2
        || mirrored_operation_family
    {
        return None;
    }
    group.declarations.sort();
    let (first_path, first_line) = &group.declarations[0];
    Some(finding(
        "oop-data-clump",
        first_path,
        *first_line,
        format!(
            "Parameters {} recur together in {} declarations across {} files",
            group.names.join(", "),
            group.declarations.len(),
            paths.len()
        ),
        "high",
        paths
            .into_iter()
            .filter(|path| path != first_path)
            .collect(),
    ))
}

fn add_parameter_group(
    groups: &mut BTreeMap<String, ParameterGroup>,
    path: &str,
    line: usize,
    declaration_name: &str,
    parameters: &[Parameter],
) {
    if parameters.len() < 3 {
        return;
    }
    let key = parameters
        .iter()
        .map(|parameter| format!("{}:{}", parameter.type_name, parameter.name))
        .collect::<Vec<_>>()
        .join(",");
    let names = parameters
        .iter()
        .map(|parameter| parameter.name.clone())
        .collect::<Vec<_>>();
    let group = groups.entry(key).or_insert_with(|| ParameterGroup {
        names,
        declaration_names: Vec::new(),
        declarations: Vec::new(),
    });
    group.declaration_names.push(declaration_name.to_owned());
    group.declarations.push((path.to_owned(), line));
}

fn interface_pressure(project: &Project) -> Vec<Finding> {
    let mut findings = Vec::new();
    for contract in project
        .classes
        .iter()
        .filter(|class| class.is_interface && class.methods.len() >= 4)
    {
        let contract_methods = contract
            .methods
            .iter()
            .map(|method| method.name.clone())
            .collect::<BTreeSet<_>>();
        let mut rejecting = Vec::<(&OopClass, BTreeSet<String>)>::new();
        for owner in project
            .classes
            .iter()
            .filter(|class| class.interfaces.contains(&contract.name))
        {
            let rejected = owner
                .methods
                .iter()
                .filter(|method| contract_methods.contains(&method.name) && rejects(&method.body))
                .map(|method| method.name.clone())
                .collect::<BTreeSet<_>>();
            if !rejected.is_empty() {
                rejecting.push((owner, rejected));
            }
        }
        let rejected_methods = rejecting
            .iter()
            .flat_map(|(_, methods)| methods.iter().cloned())
            .collect::<BTreeSet<_>>();
        let rejected_count = rejecting
            .iter()
            .map(|(_, methods)| methods.len())
            .sum::<usize>();
        if rejecting.len() < 2 || rejected_count < 3 || rejected_methods.len() < 2 {
            continue;
        }
        let related = rejecting
            .iter()
            .map(|(owner, _)| owner.path.clone())
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
                contract.methods.len(),
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

struct RefusedBequestCandidate<'a> {
    base: &'a OopClass,
    rejecting_subclasses: Vec<&'a OopClass>,
    rejected_methods: BTreeSet<&'a str>,
}

fn refused_bequests(project: &Project) -> Vec<Finding> {
    let subclasses = index_direct_subclasses(project);
    let candidates = collect_refused_bequest_candidates(project, &subclasses);
    emit_refused_bequest_findings(candidates)
}

fn index_direct_subclasses(project: &Project) -> BTreeMap<&str, Vec<&OopClass>> {
    let mut subclasses = BTreeMap::<&str, Vec<&OopClass>>::new();
    for class in &project.classes {
        if let Some(parent) = class.parent.as_deref() {
            subclasses.entry(parent).or_default().push(class);
        }
    }
    subclasses
}

fn collect_refused_bequest_candidates<'a>(
    project: &'a Project,
    subclasses: &BTreeMap<&str, Vec<&'a OopClass>>,
) -> Vec<RefusedBequestCandidate<'a>> {
    project
        .classes
        .iter()
        .filter(|base| {
            !base.is_interface
                && base
                    .methods
                    .iter()
                    .filter(|method| !method.is_static)
                    .count()
                    >= 4
        })
        .map(|base| aggregate_refused_bequest_candidate(base, subclasses))
        .collect()
}

fn aggregate_refused_bequest_candidate<'a>(
    base: &'a OopClass,
    subclasses: &BTreeMap<&str, Vec<&'a OopClass>>,
) -> RefusedBequestCandidate<'a> {
    let inherited = base
        .methods
        .iter()
        .map(|method| method.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut rejecting_subclasses = Vec::new();
    let mut rejected_methods = BTreeSet::new();
    for owner in subclasses
        .get(base.name.as_str())
        .into_iter()
        .flat_map(|owners| owners.iter().copied())
    {
        let implicit_override = is_implicit_override_language(&owner.path);
        let rejected = owner
            .methods
            .iter()
            .filter(|method| {
                (method.is_override || implicit_override)
                    && inherited.contains(method.name.as_str())
                    && rejects(&method.body)
            })
            .map(|method| method.name.as_str())
            .collect::<BTreeSet<_>>();
        if rejected.len() >= 2 {
            rejecting_subclasses.push(owner);
            rejected_methods.extend(rejected);
        }
    }
    RefusedBequestCandidate {
        base,
        rejecting_subclasses,
        rejected_methods,
    }
}

fn qualifies_as_refused_bequest(candidate: &RefusedBequestCandidate<'_>) -> bool {
    candidate.rejecting_subclasses.len() >= 2 && candidate.rejected_methods.len() >= 3
}

fn emit_refused_bequest_findings(
    candidates: Vec<RefusedBequestCandidate<'_>>,
) -> Vec<Finding> {
    candidates
        .into_iter()
        .filter(qualifies_as_refused_bequest)
        .map(|candidate| {
            let related = candidate
                .rejecting_subclasses
                .iter()
                .map(|owner| owner.path.clone())
                .filter(|path| path != &candidate.base.path)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            finding(
                "oop-refused-bequest",
                &candidate.base.path,
                candidate.base.line,
                format!(
                    "{} has {} inherited operations rejected by {} direct subclasses",
                    candidate.base.name,
                    candidate.rejected_methods.len(),
                    candidate.rejecting_subclasses.len()
                ),
                "high",
                related,
            )
        })
        .collect()
}

fn rejects(body: &str) -> bool {
    REJECTS.is_match(body)
}

#[derive(Clone, Copy)]
struct SingleUseAbstractionCandidate<'a> {
    contract: &'a OopClass,
    implementation: &'a OopClass,
}

#[derive(Default)]
struct SingleUseUsageIndex<'a> {
    contract_references: BTreeMap<&'a str, usize>,
    constructions: BTreeMap<&'a str, usize>,
}

fn single_use_abstractions(project: &Project) -> Vec<Finding> {
    let candidates = collect_single_use_abstraction_candidates(project);
    let usage = aggregate_single_use_usage(project, &candidates);
    emit_single_use_abstraction_findings(candidates, &usage)
}

fn collect_single_use_abstraction_candidates(
    project: &Project,
) -> Vec<SingleUseAbstractionCandidate<'_>> {
    let mut implementations_by_contract = BTreeMap::<&str, Vec<&OopClass>>::new();
    for implementation in project.classes.iter().filter(|class| {
        !class.is_interface && class.parent.is_none() && class.interfaces.len() == 1
    }) {
        if let Some(contract_name) = implementation.interfaces.first() {
            implementations_by_contract
                .entry(contract_name)
                .or_default()
                .push(implementation);
        }
    }

    project
        .classes
        .iter()
        .filter(|class| class.is_interface && class.methods.len() == 1)
        .filter_map(|contract| {
            let implementations = implementations_by_contract.get(contract.name.as_str())?;
            let [implementation] = implementations.as_slice() else {
                return None;
            };
            Some(SingleUseAbstractionCandidate {
                contract,
                implementation,
            })
        })
        .collect()
}

fn aggregate_single_use_usage<'a>(
    project: &Project,
    candidates: &[SingleUseAbstractionCandidate<'a>],
) -> SingleUseUsageIndex<'a> {
    let contract_names = candidates
        .iter()
        .map(|candidate| candidate.contract.name.as_str())
        .collect::<BTreeSet<_>>();
    let implementation_names = candidates
        .iter()
        .map(|candidate| candidate.implementation.name.as_str())
        .collect::<BTreeSet<_>>();

    SingleUseUsageIndex {
        contract_references: contract_names
            .into_iter()
            .map(|name| {
                let pattern = identifier_pattern(name);
                (name, count_project_matches(project, &pattern))
            })
            .collect(),
        constructions: implementation_names
            .into_iter()
            .map(|name| {
                let pattern = word_pattern(&format!("new {name}"));
                (name, count_project_matches(project, &pattern))
            })
            .collect(),
    }
}

fn count_project_matches(project: &Project, pattern: &Regex) -> usize {
    project
        .sources
        .values()
        .map(|source| pattern.find_iter(source).count())
        .sum()
}

fn qualifies_as_single_use_abstraction(
    candidate: SingleUseAbstractionCandidate<'_>,
    usage: &SingleUseUsageIndex<'_>,
) -> bool {
    let Some(contract_behavior) = candidate.contract.methods.first() else {
        return false;
    };
    let Some(implementation_behavior) = single_owned_behavior(candidate.implementation) else {
        return false;
    };

    implementation_behavior.name == contract_behavior.name
        && candidate.implementation.fields.is_empty()
        && is_trivial_owned_behavior(&implementation_behavior.body)
        && usage
            .constructions
            .get(candidate.implementation.name.as_str())
            .copied()
            == Some(1)
        && usage
            .contract_references
            .get(candidate.contract.name.as_str())
            .copied()
            .is_some_and(|references| references <= 2)
}

fn single_owned_behavior(implementation: &OopClass) -> Option<&OopMethod> {
    let mut behaviors = implementation.methods.iter().filter(|method| {
        !method.is_static
            && method.name != implementation.name
            && method.name != "constructor"
    });
    let behavior = behaviors.next()?;
    if behaviors.next().is_some() {
        return None;
    }
    Some(behavior)
}

fn emit_single_use_abstraction_findings(
    mut candidates: Vec<SingleUseAbstractionCandidate<'_>>,
    usage: &SingleUseUsageIndex<'_>,
) -> Vec<Finding> {
    candidates.sort_by(|left, right| {
        (&left.contract.path, left.contract.line)
            .cmp(&(&right.contract.path, right.contract.line))
    });
    candidates
        .into_iter()
        .filter(|candidate| qualifies_as_single_use_abstraction(*candidate, usage))
        .map(|candidate| {
            single_use_abstraction_finding(
                "oop-single-use-abstraction",
                &candidate.contract.name,
                &candidate.implementation.name,
                &candidate.contract.path,
                candidate.contract.line,
                &candidate.implementation.path,
            )
        })
        .collect()
}

fn is_trivial_owned_behavior(body: &str) -> bool {
    let normalized = body.trim();
    !normalized.is_empty()
        && normalized.len() <= 180
        && !COMPLEX_BEHAVIOR.is_match(normalized)
        && !NEW_EXPRESSION.is_match(normalized)
        && normalized.matches(';').count() <= 1
}

struct MiddleManCandidate<'a> {
    owner: &'a OopClass,
    public_method_count: usize,
    forwarding_counts: BTreeMap<&'a str, usize>,
}

struct QualifiedMiddleMan<'a> {
    owner: &'a OopClass,
    public_method_count: usize,
    field: &'a str,
    forwarded_count: usize,
}

fn middle_men(project: &Project) -> Vec<Finding> {
    let candidates = collect_middle_man_candidates(project);
    emit_middle_man_findings(candidates)
}

fn collect_middle_man_candidates(project: &Project) -> Vec<MiddleManCandidate<'_>> {
    project
        .classes
        .iter()
        .filter_map(aggregate_middle_man_candidate)
        .collect()
}

fn aggregate_middle_man_candidate(owner: &OopClass) -> Option<MiddleManCandidate<'_>> {
    if owner.is_interface
        || owner.parent.is_some()
        || !owner.interfaces.is_empty()
        || owner.fields.is_empty()
    {
        return None;
    }
    let public_method_count = owner
        .methods
        .iter()
        .filter(|method| method.is_public && !method.is_static)
        .count();
    if public_method_count < 5 {
        return None;
    }
    let mut forwarding_counts = BTreeMap::<&str, usize>::new();
    for method in owner
        .methods
        .iter()
        .filter(|method| method.is_public && !method.is_static)
    {
        if let Some(field) = forwarded_field(method, &owner.fields) {
            *forwarding_counts.entry(field).or_default() += 1;
        }
    }
    Some(MiddleManCandidate {
        owner,
        public_method_count,
        forwarding_counts,
    })
}

fn qualify_middle_man_candidate(
    candidate: MiddleManCandidate<'_>,
) -> Option<QualifiedMiddleMan<'_>> {
    let (field, forwarded_count) = candidate
        .forwarding_counts
        .into_iter()
        .max_by(|left, right| left.1.cmp(&right.1).then_with(|| right.0.cmp(left.0)))?;
    (forwarded_count >= 4 && forwarded_count * 5 >= candidate.public_method_count * 4).then_some(
        QualifiedMiddleMan {
            owner: candidate.owner,
            public_method_count: candidate.public_method_count,
            field,
            forwarded_count,
        },
    )
}

fn emit_middle_man_findings(candidates: Vec<MiddleManCandidate<'_>>) -> Vec<Finding> {
    candidates
        .into_iter()
        .filter_map(qualify_middle_man_candidate)
        .map(|candidate| {
            finding(
                "oop-middle-man-delegation",
                &candidate.owner.path,
                candidate.owner.line,
                format!(
                    "{} forwards {} of {} public methods unchanged to {}",
                    candidate.owner.name,
                    candidate.forwarded_count,
                    candidate.public_method_count,
                    candidate.field
                ),
                "high",
                Vec::new(),
            )
        })
        .collect()
}

fn forwarded_field<'a>(
    method: &'a OopMethod,
    fields: &BTreeSet<String>,
) -> Option<&'a str> {
    let call = FORWARDED_CALL.captures(&method.body)?;
    let field = call.get(1)?.as_str();
    if call[2] != method.name || !fields.contains(field) {
        return None;
    }
    let parameters = method
        .parameters
        .iter()
        .map(|parameter| parameter.name.as_str());
    let arguments_match = if call[3].trim().is_empty() {
        method.parameters.is_empty()
    } else {
        call[3].split(',').map(str::trim).eq(parameters)
    };
    arguments_match.then_some(field)
}

// code-buster-ignore complex-function: strategy evidence requires one nested class traversal before grouping.
fn strategy_dispatch(project: &Project) -> Vec<Finding> {
    let mut groups = BTreeMap::<String, Vec<&OopClass>>::new();
    for owner in &project.classes {
        for method in &owner.methods {
            for switch in SWITCH_BODY.captures_iter(&method.body) {
                let variants = CASE_LABEL
                    .captures_iter(&switch[1])
                    .map(|capture| capture[1].to_owned())
                    .collect::<BTreeSet<_>>();
                if variants.len() >= 3 {
                    groups
                        .entry(variants.into_iter().collect::<Vec<_>>().join("|"))
                        .or_default()
                        .push(owner);
                }
            }
        }
    }
    let mut findings = Vec::new();
    for (key, owners) in groups {
        let paths = owners
            .iter()
            .map(|owner| owner.path.clone())
            .collect::<BTreeSet<_>>();
        if owners.len() < 3 || paths.len() < 2 {
            continue;
        }
        let first = owners[0];
        findings.push(finding(
            "oop-repeated-strategy-dispatch",
            &first.path,
            first.line,
            format!(
                "{} switches repeat dispatch for {} across {} files",
                owners.len(),
                key.split('|').collect::<Vec<_>>().join(", "),
                paths.len()
            ),
            "medium",
            paths
                .into_iter()
                .filter(|path| path != &first.path)
                .collect(),
        ));
    }
    findings
}

#[derive(Default)]
struct StateBehaviorEvidence {
    switch_count: usize,
    labels: BTreeSet<String>,
}

struct StateBehaviorCandidate<'a> {
    owner: &'a OopClass,
    field: String,
    evidence: StateBehaviorEvidence,
}

fn state_behavior(project: &Project) -> Vec<Finding> {
    state_behavior_candidates(project)
        .filter(qualifies_as_state_behavior)
        .map(state_behavior_finding)
        .collect()
}

fn state_behavior_candidates(
    project: &Project,
) -> impl Iterator<Item = StateBehaviorCandidate<'_>> {
    project
        .classes
        .iter()
        .filter(|class| !class.is_interface)
        .flat_map(|owner| {
            aggregate_state_behavior(owner).into_iter().map(
                move |(field, evidence)| StateBehaviorCandidate {
                    owner,
                    field,
                    evidence,
                },
            )
        })
}

fn aggregate_state_behavior(owner: &OopClass) -> BTreeMap<String, StateBehaviorEvidence> {
    let mut behavior = BTreeMap::<String, StateBehaviorEvidence>::new();
    for method in owner.methods.iter().filter(|method| !method.is_static) {
        for switch in STATE_SWITCH.captures_iter(&method.body) {
            let evidence = behavior.entry(switch[1].to_owned()).or_default();
            evidence.switch_count += 1;
            evidence.labels.extend(
                RAW_CASE_LABEL
                    .captures_iter(&switch[2])
                    .map(|capture| capture[1].trim().to_owned()),
            );
        }
    }
    behavior
}

fn qualifies_as_state_behavior(candidate: &StateBehaviorCandidate<'_>) -> bool {
    candidate.evidence.switch_count >= 3
        && candidate.evidence.labels.len() >= 3
        && candidate.owner.fields.contains(&candidate.field)
}

fn state_behavior_finding(candidate: StateBehaviorCandidate<'_>) -> Finding {
    finding(
        "oop-state-behavior-candidate",
        &candidate.owner.path,
        candidate.owner.line,
        format!(
            "{} repeats behavior over mutable state {} in {} methods across {} states",
            candidate.owner.name,
            candidate.field,
            candidate.evidence.switch_count,
            candidate.evidence.labels.len()
        ),
        "high",
        Vec::new(),
    )
}

struct MethodAccessSummary<'a> {
    received: usize,
    by_receiver: BTreeMap<&'a str, (usize, BTreeSet<&'a str>)>,
}

struct FeatureEnvyCandidate<'a> {
    owner: &'a OopClass,
    method: &'a OopMethod,
    parameter: &'a Parameter,
    accesses: usize,
    member_count: usize,
}

fn feature_envy(project: &Project) -> Vec<Finding> {
    project
        .classes
        .iter()
        .flat_map(|owner| {
            owner
                .methods
                .iter()
                .filter(|method| !method.is_static)
                .filter_map(move |method| {
                    let accesses = aggregate_method_accesses(method);
                    qualify_feature_envy(owner, method, &accesses)
                })
        })
        .map(feature_envy_finding)
        .collect()
}

fn aggregate_method_accesses(method: &OopMethod) -> MethodAccessSummary<'_> {
    let mut summary = MethodAccessSummary {
        received: 0,
        by_receiver: BTreeMap::new(),
    };
    for access in MEMBER_ACCESS.captures_iter(&method.body) {
        let (Some(receiver), Some(member)) = (access.get(1), access.get(2)) else {
            continue;
        };
        summary.received += 1;
        let entry = summary.by_receiver.entry(receiver.as_str()).or_default();
        entry.0 += 1;
        entry.1.insert(member.as_str());
    }
    summary
}

fn qualify_feature_envy<'a>(
    owner: &'a OopClass,
    method: &'a OopMethod,
    summary: &MethodAccessSummary<'_>,
) -> Option<FeatureEnvyCandidate<'a>> {
    method.parameters.iter().find_map(|parameter| {
        let (accesses, members) = summary.by_receiver.get(parameter.name.as_str())?;
        (*accesses >= 5 && members.len() >= 3 && *accesses * 5 >= summary.received * 3).then_some(
            FeatureEnvyCandidate {
                owner,
                method,
                parameter,
                accesses: *accesses,
                member_count: members.len(),
            },
        )
    })
}

fn feature_envy_finding(candidate: FeatureEnvyCandidate<'_>) -> Finding {
    finding(
        "oop-feature-envy",
        &candidate.owner.path,
        candidate.owner.line,
        format!(
            "{}.{} accesses {} parameter {} {} times across {} members",
            candidate.owner.name,
            candidate.method.name,
            candidate.parameter.type_name,
            candidate.parameter.name,
            candidate.accesses,
            candidate.member_count
        ),
        "high",
        Vec::new(),
    )
}

fn service_locators(project: &Project) -> Vec<Finding> {
    let mut uses = BTreeMap::<String, Vec<(&OopClass, BTreeSet<String>)>>::new();
    for owner in &project.classes {
        let mut owner_uses = BTreeMap::<String, BTreeSet<String>>::new();
        for method in &owner.methods {
            for call in SERVICE_LOCATOR.captures_iter(&method.body) {
                let (Some(locator), Some(service)) =
                    (call.get(1), call.get(2).or_else(|| call.get(3)))
                else {
                    continue;
                };
                owner_uses
                    .entry(locator.as_str().to_owned())
                    .or_default()
                    .insert(service.as_str().to_owned());
            }
        }
        for (locator, services) in owner_uses {
            uses.entry(locator).or_default().push((owner, services));
        }
    }
    let mut findings = Vec::new();
    for (locator, owners) in uses {
        let paths = owners
            .iter()
            .map(|(owner, _)| owner.path.clone())
            .collect::<BTreeSet<_>>();
        let services = owners
            .iter()
            .flat_map(|(_, services)| services.iter().cloned())
            .collect::<BTreeSet<_>>();
        if owners.len() < 3 || paths.len() < 2 || services.len() < 3 {
            continue;
        }
        let first = owners[0].0;
        findings.push(finding(
            "oop-service-locator-dependency",
            &first.path,
            first.line,
            format!(
                "{} resolves {} service types from {} classes across {} files",
                locator,
                services.len(),
                owners.len(),
                paths.len()
            ),
            "high",
            paths
                .into_iter()
                .filter(|path| path != &first.path)
                .collect(),
        ));
    }
    findings
}

// code-buster-ignore complex-function: observer registration and removal evidence share one class traversal.
fn observer_notifications(project: &Project) -> Vec<Finding> {
    let mut findings = Vec::new();
    for owner in &project.classes {
        for field in &owner.fields {
            let add = Regex::new(&format!(
                r"\b{}\s*\.\s*(?:[Aa]dd|push)\s*\(",
                regex::escape(field)
            ))
            .expect("escaped observer add regex must compile");
            let remove = Regex::new(&format!(
                r"\b{}\s*\.\s*(?:[Rr]emove|delete|splice)\s*\(",
                regex::escape(field)
            ))
            .expect("escaped observer remove regex must compile");
            if !owner
                .methods
                .iter()
                .any(|method| add.is_match(&method.body))
                || !owner
                    .methods
                    .iter()
                    .any(|method| remove.is_match(&method.body))
            {
                continue;
            }
            let mut callbacks = BTreeMap::<String, BTreeSet<String>>::new();
            for method in &owner.methods {
                for (callback, _) in observer_callbacks(&method.body, field) {
                    callbacks
                        .entry(callback)
                        .or_default()
                        .insert(method.name.clone());
                }
            }
            for (callback, methods) in callbacks
                .into_iter()
                .filter(|(_, methods)| methods.len() >= 3)
            {
                findings.push(finding(
                    "oop-repeated-observer-notification",
                    &owner.path,
                    owner.line,
                    format!(
                        "{} repeats {} traversal calling {} from {} methods",
                        owner.name,
                        field,
                        callback,
                        methods.len()
                    ),
                    "high",
                    Vec::new(),
                ));
            }
        }
    }
    findings
}

fn observer_callbacks(body: &str, field: &str) -> Vec<(String, String)> {
    let escaped = regex::escape(field);
    let patterns = [
        format!(
            r"(?s)foreach\s*\(\s*(?:var|[A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s+in\s+(?:this\.)?{escaped}\s*\)\s*\{{?\s*([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\("
        ),
        format!(
            r"(?s)for\s*\(\s*[A-Za-z_]\w*(?:<[^>]+>)?\s+([A-Za-z_]\w*)\s*:\s*(?:this\.)?{escaped}\s*\)\s*\{{?\s*([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\("
        ),
        format!(
            r"(?s)for\s*\(\s*(?:const|let)\s+([A-Za-z_]\w*)\s+of\s+(?:this\.)?{escaped}\s*\)\s*\{{?\s*([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\("
        ),
    ];
    let mut result = Vec::new();
    for pattern in patterns {
        let Ok(regex) = Regex::new(&pattern) else {
            continue;
        };
        for capture in regex.captures_iter(body) {
            let (Some(loop_variable), Some(receiver), Some(callback)) =
                (capture.get(1), capture.get(2), capture.get(3))
            else {
                continue;
            };
            if loop_variable.as_str() == receiver.as_str() {
                result.push((
                    callback.as_str().to_owned(),
                    loop_variable.as_str().to_owned(),
                ));
            }
        }
    }
    result
}

fn message_chains(project: &Project) -> Vec<Finding> {
    let mut findings = Vec::new();
    for owner in &project.classes {
        let mut count = 0;
        let mut methods = 0;
        for method in &owner.methods {
            let current = MESSAGE_CHAIN.find_iter(&method.body).count();
            if current > 0 {
                methods += 1;
            }
            count += current;
        }
        if count < 3 || methods < 2 {
            continue;
        }
        findings.push(finding(
            "oop-message-chain",
            &owner.path,
            owner.line,
            format!(
                "{} contains {} collaboration chains of at least four hops across {} methods",
                owner.name, count, methods
            ),
            "high",
            Vec::new(),
        ));
    }
    findings
}

#[derive(Clone, Copy)]
struct BoundaryPolicy {
    role: &'static str,
    rule: &'static str,
    minimum_coverage: usize,
    direct_threshold: usize,
}

struct BoundaryCandidate<'a> {
    policy: BoundaryPolicy,
    boundary: &'a OopClass,
    covered: BTreeSet<String>,
}

struct BoundaryBypassGroup<'a> {
    rule: &'static str,
    boundary: &'a OopClass,
    bypasses: Vec<&'a str>,
}

fn boundary_bypasses(project: &Project) -> Vec<Finding> {
    boundary_candidates(project)
        .filter_map(|candidate| dominant_boundary_bypasses(project, candidate))
        .flat_map(boundary_bypass_findings)
        .collect()
}

fn boundary_candidates(project: &Project) -> impl Iterator<Item = BoundaryCandidate<'_>> {
    [
        BoundaryPolicy {
            role: "Factory",
            rule: "oop-factory-bypass",
            minimum_coverage: 1,
            direct_threshold: 1,
        },
        BoundaryPolicy {
            role: "Facade",
            rule: "oop-facade-bypass",
            minimum_coverage: 3,
            direct_threshold: 2,
        },
        BoundaryPolicy {
            role: "Repository",
            rule: "oop-repository-bypass",
            minimum_coverage: 1,
            direct_threshold: 1,
        },
        BoundaryPolicy {
            role: "Proxy",
            rule: "oop-proxy-bypass",
            minimum_coverage: 1,
            direct_threshold: 1,
        },
    ]
    .into_iter()
    .flat_map(move |policy| {
        project
            .classes
            .iter()
            .filter(move |class| class.name.ends_with(policy.role))
            .filter_map(move |boundary| {
                let source = project.sources.get(&boundary.path)?;
                let covered = covered_boundary_types(boundary, policy.role, source);
                (covered.len() >= policy.minimum_coverage).then_some(BoundaryCandidate {
                    policy,
                    boundary,
                    covered,
                })
            })
    })
}

fn covered_boundary_types(
    boundary: &OopClass,
    role: &str,
    source: &str,
) -> BTreeSet<String> {
    let mut covered = BTreeSet::new();
    if role == "Factory" {
        covered.extend(
            NEW_NAMED
                .captures_iter(source)
                .map(|capture| capture[1].to_owned()),
        );
    } else {
        covered.extend(
            BOUNDARY_FIELD
                .captures_iter(source)
                .map(|capture| capture[1].to_owned()),
        );
        if is_typescript(&boundary.path) {
            covered.extend(
                TS_BOUNDARY_FIELD
                    .captures_iter(source)
                    .map(|capture| capture[1].to_owned()),
            );
        }
    }
    covered
}

fn dominant_boundary_bypasses<'a>(
    project: &'a Project,
    candidate: BoundaryCandidate<'a>,
) -> Option<BoundaryBypassGroup<'a>> {
    let boundary_pattern = identifier_pattern(&candidate.boundary.name);
    let covered_patterns = candidate
        .covered
        .iter()
        .map(|type_name| identifier_pattern(type_name))
        .collect::<Vec<_>>();
    let mut uses = BTreeSet::new();
    let mut bypasses = Vec::new();
    for (path, source) in &project.sources {
        if path == &candidate.boundary.path {
            continue;
        }
        if boundary_pattern.is_match(source) {
            uses.insert(path.as_str());
        }
        let direct = covered_patterns
            .iter()
            .filter(|pattern| pattern.is_match(source))
            .count();
        if direct >= candidate.policy.direct_threshold {
            bypasses.push(path.as_str());
        }
    }
    (uses.len() >= 3 && uses.len() > bypasses.len()).then_some(BoundaryBypassGroup {
        rule: candidate.policy.rule,
        boundary: candidate.boundary,
        bypasses,
    })
}

fn boundary_bypass_findings<'a>(
    group: BoundaryBypassGroup<'a>,
) -> impl Iterator<Item = Finding> + 'a {
    group.bypasses.into_iter().map(move |path| {
        finding(
            group.rule,
            path,
            1,
            format!(
                "{} accesses an implementation directly although {} is the dominant boundary",
                path, group.boundary.name
            ),
            "high",
            Vec::new(),
        )
    })
}

type AdapterMappingOwners<'a> = BTreeMap<String, Vec<&'a OopClass>>;

struct AdapterMappingGroups<'a> {
    named: AdapterMappingOwners<'a>,
    typescript_objects: AdapterMappingOwners<'a>,
}

fn repeated_adapter_mappings(project: &Project) -> Vec<Finding> {
    let groups = collect_adapter_mapping_groups(project);
    groups
        .typescript_objects
        .into_values()
        .chain(groups.named.into_values())
        .filter_map(repeated_adapter_mapping_finding)
        .collect()
}

fn collect_adapter_mapping_groups(project: &Project) -> AdapterMappingGroups<'_> {
    let mut groups = AdapterMappingGroups {
        named: BTreeMap::new(),
        typescript_objects: BTreeMap::new(),
    };
    for owner in &project.classes {
        for method in &owner.methods {
            collect_named_object_mappings(&mut groups.named, owner, &method.body);
            if owner.path.ends_with(".java") {
                collect_java_constructor_mappings(&mut groups.named, owner, &method.body);
            }
            if is_typescript(&owner.path) {
                collect_typescript_object_mappings(
                    &mut groups.typescript_objects,
                    owner,
                    &method.body,
                );
            }
        }
    }
    groups
}

fn collect_named_object_mappings<'a>(
    maps: &mut AdapterMappingOwners<'a>,
    owner: &'a OopClass,
    body: &str,
) {
    for initialization in OBJECT_INITIALIZER.captures_iter(body) {
        let mut pairs = OBJECT_PAIR
            .captures_iter(&initialization[2])
            .map(|capture| format!("{}={}", &capture[1], &capture[3]))
            .collect::<Vec<_>>();
        pairs.sort();
        if pairs.len() >= 3 {
            maps.entry(format!("{}|{}", &initialization[1], pairs.join(",")))
                .or_default()
                .push(owner);
        }
    }
}

fn collect_java_constructor_mappings<'a>(
    maps: &mut AdapterMappingOwners<'a>,
    owner: &'a OopClass,
    body: &str,
) {
    for constructor in JAVA_MAPPING.captures_iter(body) {
        let members = JAVA_GETTER
            .captures_iter(&constructor[2])
            .map(|capture| capture[1].to_owned())
            .collect::<Vec<_>>();
        if members.len() >= 3 {
            maps.entry(format!(
                "{}|{}",
                &constructor[1],
                members
                    .iter()
                    .map(|member| format!("{member}={member}"))
                    .collect::<Vec<_>>()
                    .join(",")
            ))
            .or_default()
            .push(owner);
        }
    }
}

fn collect_typescript_object_mappings<'a>(
    maps: &mut AdapterMappingOwners<'a>,
    owner: &'a OopClass,
    body: &str,
) {
    for object in TS_OBJECT_LITERAL.captures_iter(body) {
        let mut pairs = TS_OBJECT_PAIR
            .captures_iter(&object[1])
            .map(|capture| format!("{}={}", &capture[1], &capture[3]))
            .collect::<Vec<_>>();
        pairs.sort();
        if pairs.len() >= 3 {
            maps.entry(pairs.join(",")).or_default().push(owner);
        }
    }
}

fn repeated_adapter_mapping_finding(owners: Vec<&OopClass>) -> Option<Finding> {
    let paths = owners
        .iter()
        .map(|owner| owner.path.clone())
        .collect::<BTreeSet<_>>();
    if owners.len() < 3 || paths.len() < 2 {
        return None;
    }
    let first = owners[0];
    Some(finding(
        "oop-repeated-adapter-mapping",
        &first.path,
        first.line,
        format!(
            "Object mapping is repeated {} times across {} files",
            owners.len(),
            paths.len()
        ),
        "high",
        paths
            .into_iter()
            .filter(|path| path != &first.path)
            .collect(),
    ))
}

struct TemplateWorkflowCandidate<'a> {
    left: &'a OopClass,
    left_method: &'a OopMethod,
    right: &'a OopClass,
    right_method: &'a OopMethod,
}

struct NormalizedTemplateWorkflow<'a> {
    left: &'a OopClass,
    left_method_name: &'a str,
    right: &'a OopClass,
    right_method_name: &'a str,
}

fn template_workflows(project: &Project) -> Vec<Finding> {
    collect_template_workflow_candidates(project)
        .into_iter()
        .filter_map(normalize_template_workflow)
        .map(template_workflow_finding)
        .collect()
}

fn collect_template_workflow_candidates(project: &Project) -> Vec<TemplateWorkflowCandidate<'_>> {
    let mut candidates = Vec::new();
    for (left_index, left) in project
        .classes
        .iter()
        .enumerate()
        .filter(|(_, class)| class.parent.is_some())
    {
        for right in project.classes[left_index + 1..]
            .iter()
            .filter(|class| class.parent.is_some())
        {
            let left_implicit = is_implicit_override_language(&left.path);
            if !is_template_workflow_class_pair(left, right, left_implicit) {
                continue;
            }
            collect_matching_workflow_methods(
                left,
                right,
                left_implicit,
                &mut candidates,
            );
        }
    }
    candidates
}

fn is_template_workflow_class_pair(
    left: &OopClass,
    right: &OopClass,
    left_implicit: bool,
) -> bool {
    left.parent == right.parent
        && left.path != right.path
        && !(left_implicit
            && (left.name == right.name
                || left.path.rsplit('/').next() == right.path.rsplit('/').next()))
}

fn collect_matching_workflow_methods<'a>(
    left: &'a OopClass,
    right: &'a OopClass,
    left_implicit: bool,
    candidates: &mut Vec<TemplateWorkflowCandidate<'a>>,
) {
    let right_implicit = is_implicit_override_language(&right.path);
    for left_method in left
        .methods
        .iter()
        .filter(|method| method.is_override || left_implicit)
    {
        for right_method in right
            .methods
            .iter()
            .filter(|method| (method.is_override || right_implicit) && method.name == left_method.name)
        {
            candidates.push(TemplateWorkflowCandidate {
                left,
                left_method,
                right,
                right_method,
            });
        }
    }
}

fn normalize_template_workflow<'a>(
    candidate: TemplateWorkflowCandidate<'a>,
) -> Option<NormalizedTemplateWorkflow<'a>> {
    let left_calls = normalized_workflow_calls(&candidate.left_method.body);
    let right_calls = normalized_workflow_calls(&candidate.right_method.body);
    let differences = left_calls
        .iter()
        .zip(&right_calls)
        .filter(|(left, right)| left != right)
        .count();
    if left_calls.len() < 4 || left_calls.len() != right_calls.len() || differences != 1 {
        return None;
    }
    Some(NormalizedTemplateWorkflow {
        left: candidate.left,
        left_method_name: &candidate.left_method.name,
        right: candidate.right,
        right_method_name: &candidate.right_method.name,
    })
}

fn normalized_workflow_calls(body: &str) -> Vec<&str> {
    CALL_NAME
        .captures_iter(body)
        .filter_map(|capture| capture.get(1).map(|matched| matched.as_str()))
        .collect()
}

fn template_workflow_finding(workflow: NormalizedTemplateWorkflow<'_>) -> Finding {
    finding(
        "oop-template-workflow-candidate",
        &workflow.left.path,
        workflow.left.line,
        format!(
            "{}.{} and {}.{} repeat a stable workflow",
            workflow.left.name,
            workflow.left_method_name,
            workflow.right.name,
            workflow.right_method_name
        ),
        "high",
        vec![workflow.right.path.clone()],
    )
}
