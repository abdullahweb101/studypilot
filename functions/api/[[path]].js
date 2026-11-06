const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 210000;

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
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

function cookie(token) {
  return `sp_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_DAYS * 86400}`;
}

function clearCookie() {
  return "sp_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0";
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  const item = cookies.split(";").map(x => x.trim())
    .find(x => x.startsWith(name + "="));
  return item ? item.substring(name.length + 1) : null;
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function readBody(request) {
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > 1_000_000) throw new Error("Request too large.");
  return await request.json();
}

async function getUser(request, env) {
  const token = getCookie(request, "sp_session");
  if (!token) return null;

  const tokenHash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);

  const result = await env.DB.prepare(`
    SELECT users.id, users.name, users.email
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.id = ? AND sessions.expires_at > ?
  `).bind(tokenHash, now).first();

  return result || null;
}

async function createSession(userId, env) {
  const token = randomId();
  const tokenHash = await sha256(token);
  const expiry = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;

  await env.DB.prepare(`
    INSERT INTO sessions (id, user_id, expires_at)
    VALUES (?, ?, ?)
  `).bind(tokenHash, userId, expiry).run();

  return token;
}

const emptyWorkspace = {
  profile: null,
  subjects: [],
  assignments: [],
  assessments: [],
  semesters: [],
  schedule: [],
  theme: "light"
};

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const endpoint = url.pathname.replace(/\/+$/, "").split("/").pop();

  if (!env.DB) {
    return json({ error: "Database is not configured." }, 500);
  }

  if (request.method !== "GET") {
    const origin = request.headers.get("Origin");
    if (origin && origin !== url.origin) {
      return json({ error: "Invalid request origin." }, 403);
    }
  }

  try {
    if (endpoint === "register" && request.method === "POST") {
      const body = await readBody(request);
      const name = String(body.name || "").trim();
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      if (name.length < 2 || name.length > 80) {
        return json({ error: "Please enter a name between 2 and 80 characters." }, 400);
      }

      if (!validEmail(email) || email.length > 254) {
        return json({ error: "Please enter a valid email address." }, 400);
      }

      if (password.length < 10 || password.length > 128) {
        return json({ error: "Password must be 10 to 128 characters long." }, 400);
      }

      const existing = await env.DB.prepare(
        "SELECT id FROM users WHERE email = ?"
      ).bind(email).first();

      if (existing) {
        return json({ error: "An account with this email already exists. Please log in." }, 409);
      }

      const id = randomId(18);
      const salt = randomId(24);
      const hash = await passwordHash(password, salt);

      await env.DB.prepare(`
        INSERT INTO users (id, name, email, password_hash, password_salt)
        VALUES (?, ?, ?, ?, ?)
      `).bind(id, name, email, hash, salt).run();

      await env.DB.prepare(`
        INSERT INTO workspaces (user_id, data)
        VALUES (?, ?)
      `).bind(id, JSON.stringify({
        ...emptyWorkspace,
        profile: {
          name,
          institution: "",
          program: "",
          year: "",
          semester: "",
          academicYear: "",
          level: "University"
        }
      })).run();

      const token = await createSession(id, env);

      return json({
        success: true,
        user: { id, name, email }
      }, 201, { "Set-Cookie": cookie(token) });
    }

    if (endpoint === "login" && request.method === "POST") {
      const body = await readBody(request);
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      const user = await env.DB.prepare(`
        SELECT id, name, email, password_hash, password_salt
        FROM users WHERE email = ?
      `).bind(email).first();

      if (!user) {
        return json({ error: "Incorrect email or password." }, 401);
      }

      const hash = await passwordHash(password, user.password_salt);

      if (hash !== user.password_hash) {
        return json({ error: "Incorrect email or password." }, 401);
      }

      const token = await createSession(user.id, env);

      return json({
        success: true,
        user: { id: user.id, name: user.name, email: user.email }
      }, 200, { "Set-Cookie": cookie(token) });
    }

    if (endpoint === "logout" && request.method === "POST") {
      const token = getCookie(request, "sp_session");

      if (token) {
        await env.DB.prepare(
          "DELETE FROM sessions WHERE id = ?"
        ).bind(await sha256(token)).run();
      }

      return json({ success: true }, 200, {
        "Set-Cookie": clearCookie()
      });
    }

    if (endpoint === "me" && request.method === "GET") {
      const user = await getUser(request, env);
      if (!user) return json({ user: null }, 401);
      return json({ user });
    }

    if (endpoint === "workspace" && request.method === "GET") {
      const user = await getUser(request, env);
      if (!user) return json({ error: "Please log in." }, 401);

      const row = await env.DB.prepare(
        "SELECT data FROM workspaces WHERE user_id = ?"
      ).bind(user.id).first();

      let data = emptyWorkspace;

      if (row) {
        try {
          data = JSON.parse(row.data);
        } catch {
          return json({ error: "Your saved workspace could not be read." }, 500);
        }
      }

      return json({ data });
    }

    if (endpoint === "workspace" && request.method === "PUT") {
      const user = await getUser(request, env);
      if (!user) return json({ error: "Please log in again." }, 401);

      const body = await readBody(request);
      const data = body.data;

      if (!data || typeof data !== "object" || Array.isArray(data)) {
        return json({ error: "Invalid workspace data." }, 400);
      }

      const allowedArrays = [
        "subjects", "assignments", "assessments", "semesters", "schedule"
      ];

      for (const key of allowedArrays) {
        if (!Array.isArray(data[key]) || data[key].length > 5000) {
          return json({ error: "Invalid workspace structure." }, 400);
        }
      }

      if (JSON.stringify(data).length > 900000) {
        return json({ error: "Workspace is too large." }, 413);
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

    return json({ error: "API endpoint not found." }, 404);

  } catch (error) {
    console.error("StudyPilot API error:", error);
    return json({ error: "Something went wrong. Please try again." }, 500);
  }
}
