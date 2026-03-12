import 'package:code_buster/src/internal.dart';
import 'package:test/test.dart';

import '../support/source_fixture.dart';

void main() {
  final AnalysisConfig config = AnalysisConfig(
    root: '.',
    severityOverrides: <String, RuleSeverity>{
      for (final RuleMetadata rule in RuleCatalog.all.where(
        (RuleMetadata rule) =>
            rule.id.startsWith('html-') || rule.id.startsWith('css-'),
      ))
        rule.id: rule.defaultSeverity,
    },
  );

  test('finds HTML accessibility and security hazards', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'index.html': sourceFixture(
            'html-css/finds_html_accessibility_and_security_hazards/index.html',
          ),
        }, config)
        .findings;
    expect(
      findings.map((Finding item) => item.code),
      containsAll(<String>[
        'html-inline-script',
        'html-blank-no-rel',
        'html-img-alt',
        'html-http-resource',
        'html-input-label',
        'html-duplicate-id',
        'html-form-method',
        'html-missing-lang',
        'html-missing-viewport',
        'html-missing-title',
      ]),
    );
  });

  test('checks blank-link rel across multiline start tags', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'links.html': sourceFixture(
            'html-css/checks_blank_link_rel_across_multiline_start_tags/links.html',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'html-blank-no-rel')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 7);
  });

  test('checks image alt text across multiline start tags', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'images.html': sourceFixture(
            'html-css/checks_image_alt_text_across_multiline_start_tags/images.html',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'html-img-alt')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 4);
  });

  test('ignores image-like markup in HTML comments', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'images.html': '''
<!-- Replace the <img> after rendering the video. -->
<img src="missing-alt.png">
''',
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'html-img-alt')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 2);
  });

  test('accepts image inputs with alt text as labeled controls', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'inputs.html': '''
<input type="image" src="submit.png" alt="Submit">
<input type="image" src="unlabeled.png">
''',
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'html-input-label')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 2);
  });

  test('recognizes labels across complete multiline input tags', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'inputs.html': sourceFixture(
            'html-css/recognizes_labels_across_complete_multiline_input_tags/inputs.html',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'html-input-label')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 13);
  });

  test('pairs inputs with matching framework-bound labels', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'inputs.html': sourceFixture(
            'html-css/pairs_inputs_with_matching_framework_bound_labels/inputs.html',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'html-input-label')
        .toList();

    expect(findings.map((Finding finding) => finding.line), <int>[6, 7]);
  });

  test('requires a method only for native form submission', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'forms.html': sourceFixture(
            'html-css/requires_a_method_only_for_native_form_submission/forms.html',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'html-form-method')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 4);
  });

  test('accepts metadata supplied by a markup-emitting head template', () {
    final List<Finding>
    findings = LanguagePluginRegistry.standard().require('html').analyze(<
      String,
      String
    >{
      'page.html': sourceFixture(
        'html-css/accepts_metadata_supplied_by_a_markup_emitting_head_template/page.html',
      ),
    }, config).findings;

    expect(
      findings.where(
        (Finding finding) =>
            finding.code == 'html-missing-title' ||
            finding.code == 'html-missing-viewport',
      ),
      isEmpty,
    );
  });

  test('recognizes a full head supplied by a named template include', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'head-layout.html': sourceFixture(
            'html-css/recognizes_a_full_head_supplied_by_a_named_template_include/head-layout.html',
          ),
          'body-layout.html': sourceFixture(
            'html-css/recognizes_a_full_head_supplied_by_a_named_template_include/body-layout.html',
          ),
        }, config)
        .findings
        .where(
          (Finding finding) =>
              finding.code == 'html-missing-title' ||
              finding.code == 'html-missing-viewport',
        )
        .toList();

    expect(findings, hasLength(2));
    expect(findings.map((Finding finding) => finding.path).toSet(), <String>{
      'body-layout.html',
    });
  });

  test('accepts a title supplied by the Jekyll SEO tag', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'page.html': sourceFixture(
            'html-css/accepts_a_title_supplied_by_the_jekyll_seo_tag/page.html',
          ),
        }, config)
        .findings;

    expect(
      findings.map((Finding finding) => finding.code),
      isNot(contains('html-missing-title')),
    );
    expect(
      findings.map((Finding finding) => finding.code),
      contains('html-missing-viewport'),
    );
  });

  test('recognizes attribute-bearing multiline title content', () {
    final List<Finding>
    findings = LanguagePluginRegistry.standard().require('html').analyze(<
      String,
      String
    >{
      'report.html': sourceFixture(
        'html-css/recognizes_attribute_bearing_multiline_title_content/report.html',
      ),
    }, config).findings;

    expect(
      findings.map((Finding finding) => finding.code),
      isNot(contains('html-missing-title')),
    );
  });

  test('recognizes viewport on a multiline meta start tag', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'with-viewport.html': sourceFixture(
            'html-css/recognizes_viewport_on_a_multiline_meta_start_tag/with-viewport.html',
          ),
          'without-viewport.html': sourceFixture(
            'html-css/recognizes_viewport_on_a_multiline_meta_start_tag/without-viewport.html',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'html-missing-viewport')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.path, 'without-viewport.html');
  });

  test('recognizes lang on a multiline html start tag', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'index.html': sourceFixture(
            'html-css/recognizes_lang_on_a_multiline_html_start_tag/index.html',
          ),
        }, config)
        .findings;

    expect(
      findings.map((Finding finding) => finding.code),
      isNot(contains('html-missing-lang')),
    );
  });

  test('ignores non-executable inline script data', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'index.html': sourceFixture(
            'html-css/ignores_non_executable_inline_script_data/index.html',
          ),
        }, config)
        .findings;

    expect(
      findings.where((Finding finding) => finding.code == 'html-inline-script'),
      hasLength(1),
    );
  });

  test('ignores nonce-protected inline scripts', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'index.html': r'''<script nonce="server-value">literal();</script>
<script {{ $nonceAttribute }}>templated();</script>
<script>unprotected();</script>
''',
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'html-inline-script')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 3);
  });

  test('reports script elements but ignores script-like raw text', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'index.html': sourceFixture(
            'html-css/reports_script_elements_but_ignores_script_like_raw_text/index.html',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'html-inline-script')
        .toList();

    expect(findings, hasLength(2));
    expect(findings.map((Finding finding) => finding.line).toList(), <int>[
      1,
      7,
    ]);
  });

  test('ignores navigation links and mutually exclusive Doxygen ids', () {
    final List<Finding>
    findings = LanguagePluginRegistry.standard().require('html').analyze(<
      String,
      String
    >{
      'template.html': sourceFixture(
        'html-css/ignores_navigation_links_and_mutually_exclusive_doxygen_ids/template.html',
      ),
    }, config).findings;

    expect(
      findings.where((Finding finding) => finding.code == 'html-http-resource'),
      hasLength(1),
    );
    expect(
      findings.where((Finding finding) => finding.code == 'html-duplicate-id'),
      hasLength(1),
    );
  });

  test('ignores HTTP profile relation URIs but finds fetched resources', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'links.html': '''
<link rel="profile" href="http://gmpg.org/xfn/11">
<link rel="stylesheet" href="http://example.test/theme.css">
''',
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'html-http-resource')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 2);
  });

  test('ignores insecure resource markup inside HTML comments', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'links.html': sourceFixture(
            'html-css/ignores_insecure_resource_markup_inside_html_comments/links.html',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'html-http-resource')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 5);
  });

  test('finds CSS cascade, accessibility, and maintainability hazards', () {
    final List<Finding>
    findings = LanguagePluginRegistry.standard().require('css').analyze(<
      String,
      String
    >{
      'style.css': sourceFixture(
        'html-css/finds_css_cascade_accessibility_and_maintainability_hazards/style.css',
      ),
    }, config).findings;
    expect(
      findings.map((Finding item) => item.code),
      containsAll(<String>[
        'css-selector-depth',
        'css-universal-selector',
        'css-duplicate-property',
        'css-important',
        'css-fixed-font-px',
        'css-high-z-index',
        'css-animation-no-reduced-motion',
        'css-vendor-prefix-only',
      ]),
    );
  });

  test('distinguishes universal selector tokens from attribute operators', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('css')
        .analyze(<String, String>{
          'style.css': sourceFixture(
            'html-css/distinguishes_universal_selector_tokens_from_attribute_operators/style.css',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'css-universal-selector')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 10);
  });

  test('measures selector depth outside pseudo arguments and at-rules', () {
    final List<Finding>
    findings = LanguagePluginRegistry.standard().require('css').analyze(<
      String,
      String
    >{
      'style.css': sourceFixture(
        'html-css/measures_selector_depth_outside_pseudo_arguments_and_at_rules/style.css',
      ),
    }, config).findings;

    final Iterable<Finding> depths = findings.where(
      (Finding finding) => finding.code == 'css-selector-depth',
    );
    expect(depths, hasLength(1));
    expect(depths.single.line, 10);
    expect(
      findings.where(
        (Finding finding) => finding.code == 'css-universal-selector',
      ),
      isEmpty,
    );
  });

  test('ignores vendor-only properties without standard counterparts', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('css')
        .analyze(<String, String>{
          'style.css': sourceFixture(
            'html-css/ignores_vendor_only_properties_without_standard_counterparts/style.css',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'css-vendor-prefix-only')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 6);
  });

  test('ignores HTML fragments and paired CSS vendor fallbacks', () {
    final List<Finding> html = LanguagePluginRegistry.standard()
        .require('html')
        .analyze(<String, String>{
          'partial.html': '''
{% extends "base.html" %}
{% block body %}<strong>Content</strong>{% endblock %}
''',
        }, config)
        .findings;
    final List<Finding>
    css = LanguagePluginRegistry.standard().require('css').analyze(<
      String,
      String
    >{
      'style.css': sourceFixture(
        'html-css/ignores_html_fragments_and_paired_css_vendor_fallbacks/style.css',
      ),
    }, config).findings;

    expect(
      html.where((Finding finding) => finding.code.startsWith('html-missing-')),
      isEmpty,
    );
    expect(
      css.where((Finding finding) => finding.code == 'css-vendor-prefix-only'),
      isEmpty,
    );
  });
  test('ignores CSS compatibility fallbacks and non-motion declarations', () {
    final List<Finding>
    findings = LanguagePluginRegistry.standard().require('css').analyze(<
      String,
      String
    >{
      'style.css': sourceFixture(
        'html-css/ignores_css_compatibility_fallbacks_and_non_motion_declarations/style.css',
      ),
    }, config).findings;

    expect(
      findings.where(
        (Finding finding) => finding.code == 'css-duplicate-property',
      ),
      hasLength(1),
    );
    expect(
      findings.where(
        (Finding finding) => finding.code == 'css-animation-no-reduced-motion',
      ),
      hasLength(1),
    );
    expect(
      findings.where((Finding finding) => finding.code == 'css-selector-depth'),
      hasLength(1),
    );
  });

  test('distinguishes CSS fallback chains from duplicate declarations', () {
    final List<Finding>
    findings = LanguagePluginRegistry.standard().require('css').analyze(<
      String,
      String
    >{
      'style.css': sourceFixture(
        'html-css/distinguishes_css_fallback_chains_from_duplicate_declarations/style.css',
      ),
    }, config).findings;

    final Iterable<Finding> duplicates = findings.where(
      (Finding finding) => finding.code == 'css-duplicate-property',
    );
    expect(duplicates, hasLength(5));
  });

  test('accepts a multiline font source compatibility fallback', () {
    final List<Finding> duplicates = LanguagePluginRegistry.standard()
        .require('css')
        .analyze(<String, String>{
          'font.css': sourceFixture(
            'html-css/accepts_a_multiline_font_source_compatibility_fallback/font.css',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'css-duplicate-property')
        .toList();

    expect(duplicates.map((Finding finding) => finding.line), <int>[10]);
  });

  test('only ignores consecutive standard-to-vendor value fallbacks', () {
    final List<Finding> duplicates = LanguagePluginRegistry.standard()
        .require('css')
        .analyze(<String, String>{
          'style.css': sourceFixture(
            'html-css/only_ignores_consecutive_standard_to_vendor_value_fallbacks/style.css',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'css-duplicate-property')
        .toList();

    expect(
      duplicates.map((Finding finding) => finding.line),
      orderedEquals(<int>[7, 11, 16]),
    );
  });

  test('accepts disjoint Tailwind utility value overloads', () {
    final List<Finding> duplicates = LanguagePluginRegistry.standard()
        .require('css')
        .analyze(<String, String>{
          'utilities.css': sourceFixture(
            'html-css/accepts_disjoint_tailwind_utility_value_overloads/utilities.css',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'css-duplicate-property')
        .toList();

    expect(
      duplicates.map((Finding finding) => finding.line),
      orderedEquals(<int>[7, 11]),
    );
  });

  test('ignores declarations inside multiline image-set values', () {
    final List<Finding> duplicates = LanguagePluginRegistry.standard()
        .require('css')
        .analyze(<String, String>{
          'style.css': sourceFixture(
            'html-css/ignores_declarations_inside_multiline_image_set_values/style.css',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'css-duplicate-property')
        .toList();

    expect(
      duplicates.map((Finding finding) => finding.line),
      orderedEquals(<int>[9]),
    );
  });

  test('distinguishes logical text alignment fallbacks from overwrites', () {
    final List<Finding> duplicates = LanguagePluginRegistry.standard()
        .require('css')
        .analyze(<String, String>{
          'style.css': sourceFixture(
            'html-css/distinguishes_logical_text_alignment_fallbacks_from_overwrites/style.css',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'css-duplicate-property')
        .toList();

    expect(
      duplicates.map((Finding finding) => finding.line),
      orderedEquals(<int>[11, 15, 19, 23]),
    );
  });
  test('does not treat CSS at-rules as selectors', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('css')
        .analyze(<String, String>{
          'style.css': sourceFixture(
            'html-css/does_not_treat_css_at_rules_as_selectors/style.css',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'css-selector-depth')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 6);
  });

  test('ignores CSS hazards mentioned inside comments', () {
    final List<Finding> findings = LanguagePluginRegistry.standard()
        .require('css')
        .analyze(<String, String>{
          'style.css': sourceFixture(
            'html-css/ignores_css_hazards_mentioned_inside_comments/style.css',
          ),
        }, config)
        .findings
        .where((Finding finding) => finding.code == 'css-important')
        .toList();

    expect(findings, hasLength(1));
    expect(findings.single.line, 6);
  });
}
