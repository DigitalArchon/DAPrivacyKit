// ESLint for the page's script (packaging/check.sh's web step: npx --prefix tests/web eslint -c tests/web/eslint.config.mjs
// src/daprivacyscanner/web/app.js). Few rules, each for a mistake that has cost something here: a name that isn't
// defined, one left unused, HTML written as text (every node is built with h() and text nodes: nothing a server or a
// file name says is ever parsed as HTML), eval (the page's CSP refuses it anyway), and a promise dropped unawaited.

// Browser globals the page uses: listed rather than taken from a package, so that a new one is a decision
const browser = Object.fromEntries(["window", "document", "navigator", "history", "location", "fetch", "AbortController",
  "AbortSignal", "setTimeout", "clearTimeout", "setInterval", "clearInterval", "localStorage", "sessionStorage", "console",
  "getSelection", "MutationObserver", "Node", "Event", "KeyboardEvent", "MouseEvent", "CSS", "URL"].map(n => [n, "readonly"]));

// A call, as a statement of its own, to an async function of this file: the promise it returns is dropped, and a
// failure in it surfaces only as an unhandled rejection (app.js's pageProblem says it then). Awaiting it, or
// `void f()` where it is meant to run on by itself, says which.
// The name is resolved as JavaScript does (the scope it is called in, then the ones around it), so a sync helper of the
// same name as an async one elsewhere isn't taken for it.
const noFloatingAsync = {
  meta: { type: "problem", messages: { dropped: "{{name}}() returns a promise that is dropped: await it, or write void {{name}}() "
    + "where it is meant to run on by itself." }, schema: [] },
  create(context) {
    const isAsync = (variable) => {
      const def = variable?.defs?.[0];
      const fn = def?.type === "FunctionName" ? def.node : def?.type === "Variable" ? def.node.init : null;
      return !!fn && /Function/.test(fn.type) && fn.async;
    };
    return {
      "ExpressionStatement > CallExpression"(node) {
        if (node.callee.type !== "Identifier") return;
        let variable = null;
        for (let s = context.sourceCode.getScope(node); s && !variable; s = s.upper) variable = s.set.get(node.callee.name) || null;
        if (isAsync(variable)) context.report({ node, messageId: "dropped", data: { name: node.callee.name } });
      },
    };
  },
};

export default [
  {
    files: ["**/*.js"],
    languageOptions: { ecmaVersion: 2023, sourceType: "script", globals: browser },
    plugins: { local: { rules: { "no-floating-async": noFloatingAsync } } },
    linterOptions: { reportUnusedDisableDirectives: "error" },
    rules: {
      "no-undef": "error",
      "no-unused-vars": ["error", { args: "none", caughtErrors: "none" }],
      "no-restricted-properties": ["error",
        { property: "innerHTML", message: "Build nodes with h() and text: nothing is parsed as HTML." },
        { property: "outerHTML", message: "Build nodes with h() and text: nothing is parsed as HTML." },
        { property: "insertAdjacentHTML", message: "Build nodes with h() and text: nothing is parsed as HTML." },
        { object: "document", property: "write", message: "Build nodes with h() and text: nothing is parsed as HTML." },
        { object: "document", property: "writeln", message: "Build nodes with h() and text: nothing is parsed as HTML." }],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "local/no-floating-async": "error",
    },
  },
];
