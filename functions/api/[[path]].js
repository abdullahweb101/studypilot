const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 210000;
const MAX_BODY_SIZE = 1_000_000;

const EMPTY_WORKSPACE = {
  profile: null,
  subjects: [],
  assignments: [],
  assessments: [],
  semesters: [],
  schedule: [],
  theme: "light"
};

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers
    }
  });

function randomId(bytes = 32) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));

  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function sha256(value) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return [...new Uint8Array(result)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return [...new Uint8Array(bits)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function sessionCookie(token) {
  return [
    `sp_session=${token}`,
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    "Path=/",
    `Max-Age=${SESSION_DAYS * 86400}`
  ].join("; ");
}

function clearSessionCookie() {
  return [
    "sp_session=",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    "Path=/",
    "Max-Age=0"
  ].join("; ");
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";

  const item = cookies
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(name + "="));

  return item ? item.substring(name.length + 1) : null;
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function readBody(request) {
  const length = Number(request.headers.get("Content-Length") || 0);

  if (length > MAX_BODY_SIZE) {
    throw new Error("Request is too large.");
  }

  const text = await request.text();

  if (text.length > MAX_BODY_SIZE) {
    throw new Error("Request is too large.");
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error("Invalid request data.");
  }
}

async function getUser(request, env) {
  const token = getCookie(request, "sp_session");

  if (!token) return null;

  const tokenHash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);

  return await env.DB.prepare(`
    SELECT
      users.id,
      users.name,
      users.email
    FROM sessions
    INNER JOIN users
      ON users.id = sessions.user_id
    WHERE sessions.id = ?
      AND sessions.expires_at > ?
    LIMIT 1
  `).bind(tokenHash, now).first();
}

async function createSession(userId, env) {
  const token = randomId(32);
  const tokenHash = await sha256(token);

  const expiresAt =
    Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;

  await env.DB.prepare(`
    INSERT INTO sessions (id, user_id, expires_at)
    VALUES (?, ?, ?)
  `).bind(tokenHash, userId, expiresAt).run();

  return token;
}

function validWorkspace(data) {
  if (
    !data ||
    typeof data !== "object" ||
    Array.isArray(data)
  ) {
    return false;
  }

  const arrays = [
    "subjects",
    "assignments",
    "assessments",
    "semesters",
    "schedule"
  ];

  for (const key of arrays) {
    if (!Array.isArray(data[key]) || data[key].length > 5000) {
      return false;
    }
  }

  if (
    data.profile !== null &&
    (typeof data.profile !== "object" || Array.isArray(data.profile))
  ) {
    return false;
  }

  if (data.theme !== "light" && data.theme !== "dark") {
    return false;
  }

  return JSON.stringify(data).length <= 900000;
}

async function register(body, env) {
  const name = String(body.name || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const confirmPassword = String(body.confirmPassword || "");

  if (name.length < 2 || name.length > 80) {
    return json({
      error: "Please enter a name between 2 and 80 characters."
    }, 400);
  }

  if (!validEmail(email) || email.length > 254) {
    return json({
      error: "Please enter a valid email address."
    }, 400);
  }

  if (password.length < 10 || password.length > 128) {
    return json({
      error: "Password must be 10 to 128 characters long."
    }, 400);
  }

  if (confirmPassword && password !== confirmPassword) {
    return json({
      error: "Passwords do not match."
    }, 400);
  }

  const existing = await env.DB.prepare(
    "SELECT id FROM users WHERE email = ? LIMIT 1"
  ).bind(email).first();

  if (existing) {
    return json({
      error: "An account with this email already exists. Please log in."
    }, 409);
  }

  const id = randomId(18);
  const salt = randomId(24);
  const hash = await passwordHash(password, salt);

  const token = randomId(32);
  const tokenHash = await sha256(token);
  const expiresAt =
    Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;

  const workspace = JSON.stringify(EMPTY_WORKSPACE);

  try {
    await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO users
          (id, name, email, password_hash, password_salt)
        VALUES (?, ?, ?, ?, ?)
      `).bind(id, name, email, hash, salt),

      env.DB.prepare(`
        INSERT INTO workspaces (user_id, data)
        VALUES (?, ?)
      `).bind(id, workspace),

      env.DB.prepare(`
        INSERT INTO sessions (id, user_id, expires_at)
        VALUES (?, ?, ?)
      `).bind(tokenHash, id, expiresAt)
    ]);
  } catch (error) {
    console.error("Registration database error:", error);

    const duplicate = await env.DB.prepare(
      "SELECT id FROM users WHERE email = ? LIMIT 1"
    ).bind(email).first();

    if (duplicate) {
      return json({
        error: "An account with this email already exists. Please log in."
      }, 409);
    }

    throw error;
  }

  return json({
    success: true,
    user: { id, name, email }
  }, 201, {
    "Set-Cookie": sessionCookie(token)
  });
}

async function login(body, env) {
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!validEmail(email) || !password || password.length > 128) {
    return json({
      error: "Incorrect email or password."
    }, 401);
  }

  const user = await env.DB.prepare(`
    SELECT id, name, email, password_hash, password_salt
    FROM users
    WHERE email = ?
    LIMIT 1
  `).bind(email).first();

  if (!user) {
    return json({
      error: "Incorrect email or password."
    }, 401);
  }

  const hash = await passwordHash(password, user.password_salt);

  if (hash !== user.password_hash) {
    return json({
      error: "Incorrect email or password."
    }, 401);
  }

  const token = await createSession(user.id, env);

  return json({
    success: true,
    user: {
      id: user.id,
      name: user.name,
      email: user.email
    }
  }, 200, {
    "Set-Cookie": sessionCookie(token)
  });
}

async function logout(request, env) {
  const token = getCookie(request, "sp_session");

  if (token) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE id = ?"
    ).bind(await sha256(token)).run();
  }

  return json({ success: true }, 200, {
    "Set-Cookie": clearSessionCookie()
  });
}

async function getWorkspace(request, env) {
  const user = await getUser(request, env);

  if (!user) {
    return json({ error: "Please log in." }, 401);
  }

  const row = await env.DB.prepare(
    "SELECT data FROM workspaces WHERE user_id = ? LIMIT 1"
  ).bind(user.id).first();

  if (!row) {
    await env.DB.prepare(`
      INSERT INTO workspaces (user_id, data)
      VALUES (?, ?)
    `).bind(user.id, JSON.stringify(EMPTY_WORKSPACE)).run();

    return json({ data: EMPTY_WORKSPACE });
  }

  try {
    const data = JSON.parse(row.data);

    return json({
      data: {
        ...EMPTY_WORKSPACE,
        ...data
      }
    });
  } catch {
    return json({
      error: "Your saved workspace could not be read."
    }, 500);
  }
}

async function saveWorkspace(request, env) {
  const user = await getUser(request, env);

  if (!user) {
    return json({ error: "Please log in again." }, 401);
  }

  const body = await readBody(request);
  const data = body.data;

  if (!validWorkspace(data)) {
    return json({
      error: "Invalid workspace data or workspace is too large."
    }, 400);
  }

  await env.DB.prepare(`
    INSERT INTO workspaces (user_id, data, updated_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(user_id) DO UPDATE SET
      data = excluded.data,
      updated_at = CURRENT_TIMESTAMP
  `).bind(user.id, JSON.stringify(data)).run();

  return json({ success: true });
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  if (!env.DB) {
    return json({
      error: "Database is not configured. Check the DB binding."
    }, 500);
  }

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }

  if (request.method !== "GET") {
    const origin = request.headers.get("Origin");

    if (origin && origin !== url.origin) {
      return json({
        error: "Invalid request origin."
      }, 403);
    }
  }

  const endpoint = url.pathname
    .replace(/\/+$/, "")
    .split("/")
    .pop();

  try {
    if (endpoint === "register" && request.method === "POST") {
      return await register(await readBody(request), env);
    }

    if (endpoint === "login" && request.method === "POST") {
      return await login(await readBody(request), env);
    }

    if (endpoint === "logout" && request.method === "POST") {
      return await logout(request, env);
    }

    if (endpoint === "me" && request.method === "GET") {
      const user = await getUser(request, env);

      if (!user) {
        return json({ user: null }, 401);
      }

      return json({ user });
    }

    if (endpoint === "workspace" && request.method === "GET") {
      return await getWorkspace(request, env);
    }

    if (endpoint === "workspace" && request.method === "PUT") {
      return await saveWorkspace(request, env);
    }

    return json({
      error: "API endpoint not found."
    }, 404);

  } catch (error) {
    console.error("StudyPilot API error:", error);

    return json({
      error: error.message === "Invalid request data." ||
        error.message === "Request is too large." ||
        error.message === "Request is not valid JSON."
        ? error.message
        : "Something went wrong. Please try again."
    }, 500);
  }
}
