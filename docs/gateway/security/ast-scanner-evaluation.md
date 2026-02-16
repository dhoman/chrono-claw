# AST-Based Skill Scanner Evaluation

## Status: CONDITIONAL GO

Recommended as a Phase 10+ enhancement, not a Phase 7 deliverable. The regex-based scanner with Phase 7 evasion rules provides sufficient coverage for known supply-chain attack patterns. AST analysis should be pursued when regex rules start producing unacceptable false-positive rates or when a real-world bypass is discovered that regex cannot address.

## Current State (Post-Phase 7)

The regex-based scanner now has 19 rules (8 original + 11 evasion) covering:

- Direct dangerous calls (exec, eval, new Function, crypto-mining, suspicious WebSocket)
- Dynamic import() expressions
- Function constructor evasion (aliasing, bracket notation, Reflect.construct)
- Computed/concatenated require() arguments
- Bracket notation access to dangerous properties (process["env"], global["eval"])
- Node.js vm module code execution
- Indirect eval patterns ((0,eval), globalThis.eval)
- Shell script references with execution context
- Base64 decode + code execution combinations
- Unicode escape obfuscation clusters
- Template literal interpolation in require/import

### What Regex Cannot Catch

1. **Multi-hop aliasing**: `const a = require; const b = a; b("child_process")` — the scanner detects single-step patterns but cannot follow variable assignments across multiple hops.
2. **Computed property chains**: `const key = "ev" + "al"; globalThis[key]("code")` — the scanner catches `process["env"]` and `global["eval"]` as literal strings but not dynamically constructed property names.
3. **Cross-file data flow**: Module A exports a dangerous function, Module B imports and calls it innocuously. Regex operates per-file.
4. **Minified/bundled code**: Webpack/esbuild output with variable renaming makes pattern matching unreliable.
5. **Conditional execution paths**: `if (isCI) { eval(payload) }` — regex cannot determine reachability.

## Candidate Parsers

| Parser                    | Size          | Parse Time (1KB file) | Language Support            | Maintenance                   |
| ------------------------- | ------------- | --------------------- | --------------------------- | ----------------------------- |
| **acorn**                 | ~120KB        | ~0.5ms                | ES2024 JS only              | Active, Mozilla-backed        |
| **acorn + acorn-jsx**     | ~140KB        | ~0.6ms                | ES2024 JS + JSX             | Active                        |
| **@babel/parser**         | ~1.8MB        | ~2ms                  | JS + JSX + TS + Flow        | Active, heavy                 |
| **TypeScript compiler**   | ~8MB          | ~15ms                 | Full TS + JS                | Active, very heavy            |
| **tree-sitter**           | ~2MB (native) | ~0.3ms                | Multi-language, incremental | Active, requires native addon |
| **oxc-parser** (via WASM) | ~3MB          | ~0.2ms                | JS + TS + JSX + TSX         | Active, very fast             |

### Recommendation: acorn (+ acorn-jsx if needed)

- Smallest footprint, fastest for JS-only analysis
- Sufficient for skill scanning (skills are typically plain JS/TS, not complex TSX)
- For TypeScript support, strip types first with `ts-blank-space` (zero-config type erasure, ~50KB) then parse with acorn
- Alternative: oxc-parser via WASM if TypeScript-native parsing is needed and the binary size is acceptable

## What AST Would Enable

### Top 3 High-Value AST Detections

1. **Dynamic import/require with non-literal specifiers**:
   Walk `CallExpression` nodes where callee is `require` or `ImportExpression`, check if argument is a `Literal` node. Non-literal arguments (identifiers, binary expressions, template literals with expressions) are flagged. This replaces several regex patterns with a single, precise check.

2. **Dangerous global access through computed properties**:
   Walk `MemberExpression` nodes where `computed: true` and the object is `process`, `global`, `globalThis`, or `window`. Check if the property is a `Literal` matching a dangerous set (`env`, `eval`, `Function`, `require`). Catches all bracket-notation evasion patterns precisely.

3. **Function constructor through any call path**:
   Resolve `CallExpression` where the callee resolves to `Function` (including through `MemberExpression` like `globalThis.Function` or `Reflect.construct`). This catches aliasing that regex misses.

### Implementation Cost

- **Parser integration**: ~100 lines (parse file, walk AST, report findings)
- **3 AST rules**: ~150 lines (the three detections above)
- **Type stripping**: ~20 lines (integrate ts-blank-space for .ts/.tsx files)
- **Testing**: ~50 tests (positive + negative for each AST rule)
- **Total estimate**: ~320 lines of code, 1 new dependency (acorn), 1 optional dependency (ts-blank-space)

### Risks

1. **Dependency surface**: Adding acorn increases the supply-chain surface of the scanner itself. Mitigated by acorn's small size and Mozilla stewardship.
2. **Parse failures**: Malformed JS/TS will fail to parse. Fallback to regex scanning ensures coverage is never reduced.
3. **Performance**: AST parsing adds ~0.5ms per file. For 500 files (the default limit), that's ~250ms — acceptable for CI.

## Recommended Approach

1. Keep regex scanner as the primary engine (fast, zero-dependency, good enough for 90% of cases).
2. Add AST as an optional second pass (`--deep-scan` flag) for CI and audit contexts.
3. AST findings supplement regex findings — never replace them.
4. Start with acorn + the 3 high-value detections above.
5. Add ts-blank-space for TypeScript support if skills written in TS become common.

## Decision Criteria for Full Implementation

Implement AST scanning when any of these occur:

- A real supply-chain attack bypasses the regex scanner in production
- False positive rate from regex rules exceeds 10% on the skills directory
- Skills ecosystem grows beyond 50 skills (more code to scan = more edge cases)
- A security audit specifically recommends AST-based analysis
