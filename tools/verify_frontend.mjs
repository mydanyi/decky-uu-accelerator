#!/usr/bin/env node
/**
 * Smoke-test the *built* frontend bundle (dist/index.js) under a *simulated*
 * Decky host, using only the Node.js standard library.
 *
 * This is NOT real Decky and NOT game/device acceptance. It verifies only that:
 *
 *   * the bundle imports when the Decky global externals are present;
 *   * its default export is a plugin factory whose manifest has the exact name
 *     ``UU加速器`` plus ``titleView``/``content``/``icon``/``onDismount``;
 *   * exactly the eight expected RPC routes are registered at import time;
 *   * importing the bundle, building the manifest and calling ``onDismount``
 *     invoke no RPC and trigger no core operation (no start/stop).
 *
 * The React component is never rendered, so React hooks and most ``@decky/ui``
 * components are intentionally never exercised; the simulated stubs exist only
 * so the module can be evaluated.
 *
 * Usage (from the project root, after ``npm run build``):
 *   node tools/verify_frontend.mjs [--bundle <path-to-dist/index.js>]
 *
 * The tool imports the bundle read-only and prints a JSON report to stdout.
 */

import { existsSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(SCRIPT_DIR, "..");

// Exact plugin display name the manifest must declare.
const PLUGIN_NAME = "UU加速器";

// The eight RPC routes that ``src/api.ts`` registers through ``callable``.
const EXPECTED_ROUTES = [
  "get_status",
  "check_updates",
  "install_core",
  "start_core",
  "stop_core",
  "set_autostart",
  "uninstall_core",
  "reset_binding",
];

const MODE =
  "simulated Decky globals (SP_REACT/SP_JSX/DFL + loader API) — not the real " +
  "Decky runtime, not a rendered-UI, RPC-behaviour or device/game test";

// Interaction evidence recorded by the simulated host.
const evidence = {
  rpc_routes: [],
  rpc_invoked: [],
  toasts: [],
  connect_names: [],
};

function parseArgs(argv) {
  let bundle = resolve(PROJECT_ROOT, "dist", "index.js");
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--bundle") {
      const value = argv[i + 1];
      if (!value) {
        throw new Error("--bundle requires a path");
      }
      bundle = resolve(value);
      i += 1;
    }
  }
  return { bundle };
}

/**
 * Install the minimal Decky host globals *before* importing the bundle.
 *
 * The loader bridge records which RPC routes are registered and refuses to run
 * any of them (any real call is unexpected in a smoke test). React hooks throw
 * because the component is never rendered.
 */
function installSimulatedDeckyGlobals() {
  // ``window`` and ``globalThis`` are unified, matching the loader context.
  globalThis.window = globalThis;

  // --- @decky/api loader bridge -----------------------------------------
  // The real bundled @decky/api calls ``connect(version, pluginName)`` and uses
  // the returned api object (``{_version, callable, toaster}``); record the
  // plugin name so the assertions can flag a wrong one, and hand back the same
  // api object so the bundle's import-time wiring keeps working.
  const loaderAPI = {
    _version: 2,
    connect(version, pluginName) {
      evidence.connect_names.push(pluginName);
      return loaderAPI;
    },
    callable(route) {
      evidence.rpc_routes.push(route);
      return async (..._args) => {
        evidence.rpc_invoked.push(route);
        throw new Error(`unexpected RPC call: ${route}`);
      };
    },
    toaster: {
      toast(data) {
        evidence.toasts.push(data);
      },
    },
  };
  globalThis.__DECKY_SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED_deckyLoaderAPIInit =
    loaderAPI;

  // --- react (provided by the loader as SP_REACT) ------------------------
  const rejectHook = (hook) => () => {
    throw new Error(`unexpected React hook call: ${hook}`);
  };
  const SP_REACT = {
    createContext(defaultValue) {
      const ctx = { _currentValue: defaultValue };
      ctx.Provider = function Provider(props) {
        return props ? props.children : null;
      };
      ctx.Consumer = function Consumer(_props) {
        return null;
      };
      return ctx;
    },
    createElement(type, props, ...children) {
      const normalized =
        children.length === 0
          ? undefined
          : children.length === 1
            ? children[0]
            : children;
      return { type, props: { ...(props || {}), children: normalized } };
    },
    // Hooks must never run: the component is not rendered.
    useState: rejectHook("useState"),
    useEffect: rejectHook("useEffect"),
    useRef: rejectHook("useRef"),
    useCallback: rejectHook("useCallback"),
    useMemo: rejectHook("useMemo"),
    useContext: rejectHook("useContext"),
    useReducer: rejectHook("useReducer"),
    useLayoutEffect: rejectHook("useLayoutEffect"),
  };
  SP_REACT.default = SP_REACT;
  globalThis.SP_REACT = SP_REACT;

  // --- JSX automatic runtime (provided by the loader as SP_JSX) ----------
  const createElementObject = (type, props, key) => ({
    type,
    props: props ?? {},
    key: key ?? null,
  });
  globalThis.SP_JSX = {
    Fragment: Symbol.for("react.fragment"),
    jsx: createElementObject,
    jsxs: createElementObject,
    jsxDEV: createElementObject,
  };

  // --- @decky/ui (provided by the loader as DFL) -------------------------
  // Only ``staticClasses.Title`` is read when the factory builds titleView;
  // every other field is only touched during component render (skipped here).
  globalThis.DFL = { staticClasses: { Title: "test-title" } };
}

function sorted(list) {
  return [...list].sort();
}

async function run() {
  const args = parseArgs(process.argv.slice(2));
  const checks = {};

  const report = {
    mode: MODE,
    bundle: args.bundle,
    checks,
    evidence,
    ok: false,
    not_tested: [
      "React component rendering and UI structure",
      "user actions and RPC request/response behaviour",
      "the real Decky host and plugin lifecycle",
      "game / real-device acceptance",
    ],
  };

  if (!existsSync(args.bundle) || !statSync(args.bundle).isFile()) {
    checks.bundle_present = false;
    report.error = `bundle not found: ${args.bundle} (run \`npm run build\`)`;
    console.log(JSON.stringify(report, null, 2));
    return 1;
  }
  checks.bundle_present = true;

  installSimulatedDeckyGlobals();

  // --- import -----------------------------------------------------------
  let imported = null;
  try {
    imported = await import(pathToFileURL(args.bundle).href);
    checks.import_ok = true;
  } catch (error) {
    checks.import_ok = false;
    report.error = `import failed: ${error && error.message ? error.message : error}`;
  }

  // --- factory + manifest ----------------------------------------------
  if (checks.import_ok) {
    checks.default_is_function = typeof imported.default === "function";

    if (checks.default_is_function) {
      let manifest = null;
      try {
        manifest = imported.default();
        checks.factory_ok = true;
      } catch (error) {
        checks.factory_ok = false;
        report.error = `factory threw: ${error && error.message ? error.message : error}`;
      }

      if (checks.factory_ok) {
        const titleView = manifest && manifest.titleView;
        checks.name_exact =
          !!manifest && manifest.name === PLUGIN_NAME;
        checks.title_view_object =
          !!titleView && typeof titleView === "object";
        checks.title_children_exact_name =
          checks.title_view_object &&
          !!titleView.props &&
          titleView.props.children === PLUGIN_NAME;
        checks.title_class_from_static_classes =
          checks.title_view_object &&
          !!titleView.props &&
          titleView.props.className === "test-title";
        checks.content_present =
          !!manifest && typeof manifest.content === "object";
        checks.icon_present =
          !!manifest && typeof manifest.icon === "object";
        checks.on_dismount_function =
          !!manifest && typeof manifest.onDismount === "function";

        report.manifest = {
          name: manifest ? manifest.name : null,
          title_children: titleView && titleView.props ? titleView.props.children : null,
          title_class: titleView && titleView.props ? titleView.props.className : null,
          has_content: !!(manifest && manifest.content),
          has_icon: !!(manifest && manifest.icon),
          on_dismount: manifest ? typeof manifest.onDismount : "missing",
        };

        // --- RPC registration -------------------------------------------
        const registered = evidence.rpc_routes;
        const uniqueRegistered = new Set(registered);
        checks.rpc_route_count = registered.length === EXPECTED_ROUTES.length;
        checks.rpc_routes_unique =
          uniqueRegistered.size === registered.length;
        checks.rpc_routes_exact =
          JSON.stringify(sorted(registered)) ===
          JSON.stringify(sorted(EXPECTED_ROUTES));

        // --- host interaction before/at construction --------------------
        checks.no_rpc_invoked_on_import = evidence.rpc_invoked.length === 0;
        checks.no_toast_on_import = evidence.toasts.length === 0;

        // --- connect manifest name (loader may or may not call it) ------
        const namedConnects = evidence.connect_names.filter(
          (name) => name !== undefined,
        );
        checks.connect_manifest_name_ok = namedConnects.every(
          (name) => name === PLUGIN_NAME,
        );

        // --- lifecycle: onDismount must not stop the core ---------------
        if (checks.on_dismount_function) {
          try {
            manifest.onDismount();
            checks.on_dismount_ok = true;
          } catch (error) {
            checks.on_dismount_ok = false;
            report.error = `onDismount threw: ${error && error.message ? error.message : error}`;
          }
          checks.no_rpc_after_dismount = evidence.rpc_invoked.length === 0;
          checks.no_stop_after_dismount = !evidence.rpc_invoked.includes(
            "stop_core",
          );
          checks.no_toast_after_dismount = evidence.toasts.length === 0;
        }
      }
    }
  }

  report.evidence = {
    rpc_routes: evidence.rpc_routes,
    rpc_routes_expected: EXPECTED_ROUTES,
    rpc_invoked: evidence.rpc_invoked,
    toasts: evidence.toasts,
    connect_names: evidence.connect_names,
  };

  const failed = Object.values(checks).some((value) => value === false);
  report.ok = !failed;

  console.log(JSON.stringify(report, null, 2));
  return failed ? 1 : 0;
}

run()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    console.error(error && error.stack ? error.stack : error);
    process.exitCode = 1;
  });
