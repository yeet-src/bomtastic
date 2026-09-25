/* sys_graph access for the tools: one-shot queries plus enough
 * introspection to hand the model a schema slice instead of the whole
 * 2600-line SDL.
 */

const DESCRIPTION_LIMIT = 100;
/* Walking /proc races process exit; on a busy host with short-lived
 * children (a build, a shell loop) six tries is not enough. Each retry
 * waits a little so the exiting process is gone before the next walk. */
/* A process that exits between the listing and the read fails the whole
 * query. Under heavy churn (a compiler build spawns and reaps dozens a
 * second) any one attempt is likely to lose, so the answer is many
 * quick retries rather than a few slow ones. */
const RACE_ATTEMPTS = 60;
const RACE_BACKOFF_MS = 10;

/* One snapshot of the graph. `yeet.graph.query` is the one-shot form of
 * sys_graph (the `yeet:graph` module only wraps `subscribe`); it resolves
 * `{ data }` and rejects with a plain `{ message }` object, so normalize
 * that into an Error a tool can hand back to the model.
 */
export async function graphOnce(query, attempts = RACE_ATTEMPTS) {
  for (let attempt = 1; ; attempt++) {
    try {
      return await once(query);
    } catch (error) {
      if (attempt >= attempts || !racedProcessExit(error)) {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, RACE_BACKOFF_MS + Math.random() * RACE_BACKOFF_MS));
    }
  }
}

async function once(query) {
  let result;
  try {
    result = await yeet.graph.query(query);
  } catch (error) {
    throw asError(error);
  }
  return result.data;
}

/* Walking `/proc` is not atomic: a process exiting mid-query fails the
 * whole thing. Nothing about the query is wrong, so retry rather than
 * hand the model an error it cannot act on.
 */
function racedProcessExit(error) {
  return /File not found: \/proc\//.test(error.message);
}

function asError(value) {
  return value instanceof Error ? value : new Error(String(value?.message ?? value));
}

export async function queryRoot() {
  const data = await graphOnce(`{ __schema { queryType { ${FIELDS} } } }`);

  return render("type Query", data.__schema.queryType.fields);
}

export async function describeType(name) {
  const data = await graphOnce(`{ __type(name: ${JSON.stringify(name)}) {
    kind
    description
    ${FIELDS}
    inputFields { name description type ${REF} }
    enumValues { name }
  } }`);

  const type = data.__type;
  if (type === null) {
    return `Unknown type "${name}".`;
  }

  if (type.kind === "ENUM") {
    return `enum ${name} { ${type.enumValues.map((value) => value.name).join(" ")} }`;
  }

  const fields = type.fields ?? type.inputFields;
  if (!fields) {
    return `${type.kind.toLowerCase()} ${name}${comment(type.description)}`;
  }

  return render(`${type.kind === "INPUT_OBJECT" ? "input" : "type"} ${name}`, fields);
}

function render(header, fields) {
  const body = fields
    .map((field) => `  ${field.name}${args(field)}: ${typeName(field.type)}${comment(field.description)}`)
    .join("\n");

  return `${header} {\n${body}\n}`;
}

function args(field) {
  if (!field.args?.length) {
    return "";
  }

  return `(${field.args.map((arg) => `${arg.name}: ${typeName(arg.type)}`).join(", ")})`;
}

// Unwrap the NON_NULL / LIST chain introspection returns as nested refs.
function typeName(ref) {
  if (!ref) {
    return "Unknown";
  }
  if (ref.kind === "NON_NULL") {
    return `${typeName(ref.ofType)}!`;
  }
  if (ref.kind === "LIST") {
    return `[${typeName(ref.ofType)}]`;
  }

  return ref.name ?? "Unknown";
}

function comment(description) {
  if (!description) {
    return "";
  }

  const line = description.replace(/\s+/g, " ").trim();
  const clipped = line.length > DESCRIPTION_LIMIT ? `${line.slice(0, DESCRIPTION_LIMIT)}…` : line;

  return `  # ${clipped}`;
}

// Introspection has no fragments here, so the type ref is inlined to
// the four levels a `[Thing!]!` style chain can reach.
const REF = "{ kind name ofType { kind name ofType { kind name ofType { kind name } } } }";
const FIELDS = `fields { name description args { name type ${REF} } type ${REF} }`;

/* The process table, one pid at a time behind the scenes.
 *
 * `procs { … }` is all-or-nothing: one process exiting between the
 * listing and the read fails the whole field, and on a box where
 * something spawns a `sleep` every second no attempt ever wins. So the
 * listing is taken cheaply, then the fields are asked for per pid in
 * aliased chunks. A chunk that loses the race names the pid in its
 * error; that pid is dropped — it is gone anyway — and the chunk retried
 * without it. Nothing else in the scan notices.
 */
const CHUNK = 40;
const CHUNK_ATTEMPTS = 25;

export async function procsRobust(fields) {
  const { procs } = await graphOnce(`{ procs { pid } }`);
  const pids = procs.map((p) => p.pid);
  const chunks = [];
  for (let i = 0; i < pids.length; i += CHUNK) chunks.push(pids.slice(i, i + CHUNK));

  /* allSettled, not all: when one chunk gives up, the others are still
   * running and would reject later with nobody listening — in a Worker
   * an unhandled rejection kills the isolate mid-flight, before the
   * caller's catch gets to run. */
  const rows = [];
  const outcomes = await Promise.allSettled(
    chunks.map(async (ids) => {
      let remaining = ids;
      for (let attempt = 1; remaining.length; attempt++) {
        const query = `{ ${remaining.map((pid) => `p${pid}: proc(pid: ${pid}) { pid ${fields} }`).join(" ")} }`;
        try {
          const data = await once(query);
          for (const row of Object.values(data)) if (row) rows.push(row);
          return;
        } catch (error) {
          const gone = /File not found: \/proc\/(\d+)(?:\/|$|\W)/.exec(error.message);
          if (!gone || attempt >= CHUNK_ATTEMPTS) throw error;
          remaining = remaining.filter((pid) => pid !== Number(gone[1]));
        }
      }
    }),
  );
  const failed = outcomes.find((o) => o.status === "rejected");
  if (failed) throw failed.reason;
  return rows.sort((a, b) => a.pid - b.pid);
}
