
const crypto = require("crypto");

const OWNER = "vumc-media";
const REPO = "canva-atrium-slides";
const BRANCH = "main";

const GITHUB_API =
  `https://api.github.com/repos/${OWNER}/${REPO}`;

const ATRIUM_SESSION_SECONDS = 21600; // 6 hours
const ATRIUM_COOKIE_NAME = "vumc_atrium_session";

/* =========================================================
   RESPONSE HELPERS
========================================================= */

function response(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...extraHeaders
    },
    body:
      body === null || body === undefined
        ? ""
        : JSON.stringify(body)
  };
}

/* =========================================================
   COOKIE HELPERS
========================================================= */

function parseCookies(event) {
  const header =
    event.headers &&
    (event.headers.cookie || event.headers.Cookie)
      ? (event.headers.cookie || event.headers.Cookie)
      : "";

  const cookies = {};

  String(header)
    .split(";")
    .forEach(part => {
      const index = part.indexOf("=");

      if (index === -1) {
        return;
      }

      const name = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();

      if (name) {
        cookies[name] = value;
      }
    });

  return cookies;
}

function createSessionToken(secret) {
  const payload = {
    exp:
      Math.floor(Date.now() / 1000) +
      ATRIUM_SESSION_SECONDS,

    nonce:
      crypto.randomBytes(16).toString("hex")
  };

  const encoded = Buffer
    .from(JSON.stringify(payload))
    .toString("base64url");

  const signature = crypto
    .createHmac("sha256", secret)
    .update(encoded)
    .digest("base64url");

  return `${encoded}.${signature}`;
}

function verifySessionToken(token, secret) {
  if (!token || !secret) {
    return false;
  }

  const parts = String(token).split(".");

  if (parts.length !== 2) {
    return false;
  }

  const encoded = parts[0];
  const suppliedSignature = parts[1];

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(encoded)
    .digest("base64url");

  try {
    const suppliedBuffer = Buffer.from(
      suppliedSignature
    );

    const expectedBuffer = Buffer.from(
      expectedSignature
    );

    if (
      suppliedBuffer.length !== expectedBuffer.length
    ) {
      return false;
    }

    if (
      !crypto.timingSafeEqual(
        suppliedBuffer,
        expectedBuffer
      )
    ) {
      return false;
    }

  } catch (error) {
    return false;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(encoded, "base64url")
        .toString("utf8")
    );

    if (
      !payload.exp ||
      Number(payload.exp) <=
        Math.floor(Date.now() / 1000)
    ) {
      return false;
    }

    return true;

  } catch (error) {
    return false;
  }
}

function makeSessionCookie(sessionToken) {
  return (
    `${ATRIUM_COOKIE_NAME}=` +
    `${sessionToken}; ` +
    `Path=/; ` +
    `Max-Age=${ATRIUM_SESSION_SECONDS}; ` +
    `HttpOnly; ` +
    `Secure; ` +
    `SameSite=Strict`
  );
}

function clearSessionCookie() {
  return (
    `${ATRIUM_COOKIE_NAME}=; ` +
    `Path=/; ` +
    `Max-Age=0; ` +
    `HttpOnly; ` +
    `Secure; ` +
    `SameSite=Strict`
  );
}

/* =========================================================
   MAIN HANDLER
========================================================= */

exports.handler = async function (event) {

  const githubToken =
    process.env.ATRIUM_GITHUB_TOKEN;

  if (!githubToken) {
    return response(500, {
      success: false,
      error:
        "Atrium GitHub authorization is not configured."
    });
  }

  /* ---------------------------------------------------------
     OPTIONS
  --------------------------------------------------------- */

  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 204,
      headers: {
        "Cache-Control": "no-store",
        "Access-Control-Allow-Methods":
          "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers":
          "Content-Type"
      },
      body: ""
    };
  }

  let body = {};

  try {
    if (event.body) {
      body = JSON.parse(event.body);
    }
  } catch (error) {
    return response(400, {
      success: false,
      error:
        "The Atrium request could not be read."
    });
  }

  const action =
    event.queryStringParameters?.action ||
    body.action ||
    "";

  // Reject cross-origin browser mutations.
  if (
    event.httpMethod !== "GET" &&
    event.httpMethod !== "OPTIONS"
  ) {
    const origin =
      event.headers?.origin ||
      event.headers?.Origin;

    const host =
      event.headers?.host ||
      event.headers?.Host;

    if (origin && host) {
      try {
        if (new URL(origin).host !== host) {
          return response(403, {
            success: false,
            error: "Origin not allowed."
          });
        }
      } catch (_) {
        return response(403, {
          success: false,
          error: "Invalid origin."
        });
      }
    }
  }

  /* =========================================================
     DIRECT NETLIFY LOGIN
     NO GOOGLE APPS SCRIPT
  ========================================================= */

  const managerPassword =
    process.env.ATRIUM_MANAGER_PASSWORD;

  const sessionSecret =
    process.env.ATRIUM_SESSION_SECRET;

  if (action === "login") {

    if (event.httpMethod !== "POST") {
      return response(405, {
        success: false,
        error: "POST required."
      });
    }

    if (!managerPassword || !sessionSecret) {
      return response(503, {
        success: false,
        error:
          "Atrium login is not configured in Netlify."
      });
    }

    const supplied = String(
      body.passkey || ""
    );

    const expectedHash = crypto
      .createHash("sha256")
      .update(managerPassword, "utf8")
      .digest();

    const suppliedHash = crypto
      .createHash("sha256")
      .update(supplied, "utf8")
      .digest();

    if (
      !supplied ||
      !crypto.timingSafeEqual(
        expectedHash,
        suppliedHash
      )
    ) {
      return response(401, {
        success: false,
        error:
          "Incorrect Atrium Manager password."
      });
    }

    const sessionToken =
      createSessionToken(sessionSecret);

    return response(
      200,
      {
        success: true,
        authorized: true,
        expiresIn: ATRIUM_SESSION_SECONDS
      },
      {
        "Set-Cookie":
          makeSessionCookie(sessionToken)
      }
    );
  }

  /* =========================================================
     VERIFY ATRIUM SESSION
  ========================================================= */

  const cookies = parseCookies(event);

  const sessionToken =
    cookies[ATRIUM_COOKIE_NAME];

  const authorized = verifySessionToken(
    sessionToken,
    sessionSecret
  );

  /* ---------------------------------------------------------
     SESSION STATUS
  --------------------------------------------------------- */

  if (action === "session") {
    if (!authorized) {
      return response(401, {
        success: false,
        authorized: false,
        authRequired: true
      });
    }

    return response(200, {
      success: true,
      authorized: true
    });
  }

  /* ---------------------------------------------------------
     LOGOUT
  --------------------------------------------------------- */

  if (action === "logout") {
    return response(
      200,
      { success: true },
      {
        "Set-Cookie":
          clearSessionCookie()
      }
    );
  }

  /* ---------------------------------------------------------
     EVERYTHING BELOW REQUIRES AUTHORIZATION
  --------------------------------------------------------- */

  if (!authorized) {
    return response(401, {
      success: false,
      authRequired: true,
      error:
        "Atrium Manager authorization is required."
    });
  }

  const githubHeaders = {
    Authorization: `Bearer ${githubToken}`,
    Accept: "application/vnd.github+json",
    "Content-Type": "application/json",
    "X-GitHub-Api-Version": "2022-11-28"
  };

  try {

    /* ================================================
       LIST SLIDES
    ================================================= */

    if (action === "list") {
      const githubResponse = await fetch(
        `${GITHUB_API}/contents/slides?ref=${BRANCH}`,
        {
          headers: githubHeaders
        }
      );

      const data = await githubResponse.json();

      return response(
        githubResponse.status,
        data
      );
    }

    /* ================================================
       GET CONFIG
    ================================================= */

    if (action === "config") {
      const githubResponse = await fetch(
        `${GITHUB_API}/contents/slides-config.json?ref=${BRANCH}`,
        {
          headers: githubHeaders
        }
      );

      const data = await githubResponse.json();

      return response(
        githubResponse.status,
        data
      );
    }

    /* ================================================
       SAVE CONFIG
    ================================================= */

    if (action === "save-config") {
      if (!body.content) {
        return response(400, {
          success: false,
          error:
            "Configuration content is required."
        });
      }

      const payload = {
        message:
          body.message ||
          "Update Atrium slide configuration",

        content: body.content,
        branch: BRANCH
      };

      if (body.sha) {
        payload.sha = body.sha;
      }

      const githubResponse = await fetch(
        `${GITHUB_API}/contents/slides-config.json`,
        {
          method: "PUT",
          headers: githubHeaders,
          body: JSON.stringify(payload)
        }
      );

      const data = await githubResponse.json();

      return response(
        githubResponse.status,
        data
      );
    }

    /* ================================================
       UPLOAD / REPLACE SLIDE
    ================================================= */

    if (action === "upload") {
      if (!body.filename || !body.content) {
        return response(400, {
          success: false,
          error:
            "Filename and content are required."
        });
      }

      const payload = {
        message:
          body.message ||
          `Update Atrium slide ${body.filename}`,

        content: body.content,
        branch: BRANCH
      };

      if (body.sha) {
        payload.sha = body.sha;
      }

      const githubResponse = await fetch(
        `${GITHUB_API}/contents/slides/${encodeURIComponent(body.filename)}`,
        {
          method: "PUT",
          headers: githubHeaders,
          body: JSON.stringify(payload)
        }
      );

      const data = await githubResponse.json();

      return response(
        githubResponse.status,
        data
      );
    }

    /* ================================================
       DELETE SLIDE
    ================================================= */

    if (action === "delete") {
      if (!body.filename || !body.sha) {
        return response(400, {
          success: false,
          error:
            "Filename and SHA are required."
        });
      }

      const githubResponse = await fetch(
        `${GITHUB_API}/contents/slides/${encodeURIComponent(body.filename)}`,
        {
          method: "DELETE",
          headers: githubHeaders,
          body: JSON.stringify({
            message:
              body.message ||
              `Delete Atrium slide ${body.filename}`,

            sha: body.sha,
            branch: BRANCH
          })
        }
      );

      let data = {};

      const text = await githubResponse.text();

      if (text) {
        try {
          data = JSON.parse(text);
        } catch (error) {
          data = {
            message: text
          };
        }
      }

      return response(
        githubResponse.status,
        data
      );
    }

    /* ================================================
       UNKNOWN ACTION
    ================================================= */

    return response(400, {
      success: false,
      error: "Unknown Atrium API action."
    });

  } catch (error) {
    console.error(
      "Atrium API Error:",
      error
    );

    return response(500, {
      success: false,
      error: "Atrium API request failed.",
      detail: error.message
    });
  }
};
