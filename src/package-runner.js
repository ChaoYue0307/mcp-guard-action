import path from "node:path";

const DIRECT_REMOTE_RUNNERS = new Set(["npx", "bunx", "uvx"]);
const PACKAGE_MANAGER_REMOTE_RUNNERS = new Map([
  ["npm", new Set(["exec", "x"])],
  ["pnpm", new Set(["dlx"])],
  ["yarn", new Set(["dlx"])]
]);
const NPM_PACKAGE_OPTIONS = new Set(["--package", "-p"]);
const PIPX_PACKAGE_OPTIONS = new Set(["--spec"]);
const UVX_PACKAGE_OPTIONS = new Set(["--from"]);
const EMPTY_PACKAGE_OPTIONS = new Set();
const OPTION_VALUE_ARGS = new Set([
  "--cache",
  "--cwd",
  "--from",
  "--prefix",
  "--registry",
  "--spec",
  "--tag",
  "--userconfig",
  "--workspace",
  "-p",
  "-c"
]);

export function commandBase(command) {
  if (!command) return "";
  return path.basename(command).toLowerCase();
}

export function remotePackageSpec(server) {
  const command = commandBase(server.command);
  if (DIRECT_REMOTE_RUNNERS.has(command)) {
    const packageOptions = command === "npx" ? NPM_PACKAGE_OPTIONS : command === "uvx" ? UVX_PACKAGE_OPTIONS : EMPTY_PACKAGE_OPTIONS;
    return packageSpec(command, findPackageArg(server.args, 0, packageOptions));
  }

  if (command === "pipx" && server.args[0] === "run") {
    return packageSpec(command, findPackageArg(server.args, 1, PIPX_PACKAGE_OPTIONS));
  }

  const packageManagerSubcommands = PACKAGE_MANAGER_REMOTE_RUNNERS.get(command);
  if (packageManagerSubcommands?.has(server.args[0])) {
    const packageOptions = command === "npm" ? NPM_PACKAGE_OPTIONS : EMPTY_PACKAGE_OPTIONS;
    return packageSpec(command, findPackageArg(server.args, 1, packageOptions));
  }

  return null;
}

export function isPinnedPackage(packageName) {
  if (pythonExactVersionIndex(packageName) > 0) return true;
  if (packageName.startsWith("@")) {
    const secondAt = packageName.indexOf("@", 1);
    return secondAt > 1 && secondAt < packageName.length - 1;
  }
  const at = packageName.lastIndexOf("@");
  return at > 0 && at < packageName.length - 1;
}

export function packageIdentity(packageName) {
  const pythonVersionIndex = pythonExactVersionIndex(packageName);
  if (pythonVersionIndex > 0) {
    return packageName.slice(0, pythonVersionIndex);
  }

  if (packageName.startsWith("@")) {
    const secondAt = packageName.indexOf("@", 1);
    return secondAt > 1 ? packageName.slice(0, secondAt) : packageName;
  }
  const at = packageName.lastIndexOf("@");
  return at > 0 ? packageName.slice(0, at) : packageName;
}

function packageSpec(command, packageArg) {
  return {
    command,
    packageArg,
    packageName: packageArg ? packageIdentity(packageArg) : "",
    isPinned: packageArg ? isPinnedPackage(packageArg) : false
  };
}

function findPackageArg(args, startIndex, packageOptions) {
  for (let index = startIndex; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg) continue;

    if (packageOptions.has(arg)) {
      return args[index + 1] || "";
    }

    const packageOptionValue = optionValue(arg, packageOptions);
    if (packageOptionValue) {
      return packageOptionValue;
    }

    if (arg === "--") {
      break;
    }

    if (OPTION_VALUE_ARGS.has(arg)) {
      index += 1;
      continue;
    }

    if (arg.startsWith("-")) {
      continue;
    }

    return arg;
  }

  return "";
}

function optionValue(arg, options) {
  for (const option of options) {
    if (arg.startsWith(`${option}=`)) {
      return arg.slice(option.length + 1);
    }
  }
  return "";
}

function pythonExactVersionIndex(packageName) {
  const doubleEquals = packageName.indexOf("==");
  const tripleEquals = packageName.indexOf("===");
  if (tripleEquals > -1) return tripleEquals;
  return doubleEquals;
}
