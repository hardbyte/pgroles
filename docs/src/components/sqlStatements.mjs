// Statement-at-a-time SQL execution for the labs, shared by the React engine
// and the Node test suite.
//
// PGlite's `exec` runs a multi-statement string inside one implicit
// transaction, so a failing statement rolls back everything before it. psql
// does the opposite: each statement autocommits and execution stops at the
// first error. The lessons rely on psql's behavior — a step can GRANT, then
// deliberately hit an expected error, and the grant must survive — so we
// split the input into statements and execute them one at a time.

/**
 * Split SQL text into individual statements on top-level semicolons,
 * respecting single-quoted strings (with '' escapes), double-quoted
 * identifiers, line and nested block comments, and dollar-quoted bodies.
 */
export function splitSqlStatements(sql) {
  const statements = [];
  let start = 0;
  let i = 0;

  while (i < sql.length) {
    const ch = sql[i];
    const next = sql[i + 1];

    if (ch === "'") {
      i += 1;
      while (i < sql.length) {
        if (sql[i] === "'") {
          if (sql[i + 1] === "'") i += 2;
          else break;
        } else i += 1;
      }
      i += 1;
    } else if (ch === '"') {
      i += 1;
      while (i < sql.length && sql[i] !== '"') i += 1;
      i += 1;
    } else if (ch === "-" && next === "-") {
      while (i < sql.length && sql[i] !== "\n") i += 1;
    } else if (ch === "/" && next === "*") {
      let depth = 1;
      i += 2;
      while (i < sql.length && depth > 0) {
        if (sql[i] === "/" && sql[i + 1] === "*") {
          depth += 1;
          i += 2;
        } else if (sql[i] === "*" && sql[i + 1] === "/") {
          depth -= 1;
          i += 2;
        } else i += 1;
      }
    } else if (ch === "$") {
      const tag = /^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$/.exec(sql.slice(i));
      if (tag) {
        const close = sql.indexOf(tag[0], i + tag[0].length);
        i = close === -1 ? sql.length : close + tag[0].length;
      } else i += 1;
    } else if (ch === ";") {
      statements.push(sql.slice(start, i));
      i += 1;
      start = i;
    } else {
      i += 1;
    }
  }

  statements.push(sql.slice(start));
  return statements.map((s) => s.trim()).filter(Boolean);
}

/**
 * Execute SQL statement-by-statement against a PGlite database. Earlier
 * statements autocommit; execution stops at the first error, which is
 * reported alongside every result produced before it.
 */
export async function runSql(database, sql) {
  const output = { commands: [], results: [], error: null, errorCode: null };
  for (const statement of splitSqlStatements(sql)) {
    try {
      const values = await database.exec(statement);
      for (const value of values) {
        if (value.command) output.commands.push(value.command);
        if (value.fields?.length) {
          output.results.push({
            fields: value.fields.map((field) => field.name),
            rows: value.rows,
          });
        }
      }
    } catch (error) {
      output.error = error.message;
      output.errorCode = error.code;
      break;
    }
  }
  return output;
}
