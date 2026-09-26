const crypto = require("crypto");

const OWNER = "vumc-media";
const REPO = "canva-atrium-slides";
const BRANCH = "main";

const GITHUB_API =
  `https://api.github.com/repos/${OWNER}/${REPO}`;

const STAFF_TOOLS_GAS_URL =
  "https://script.google.com/macros/s/AKfycbzHpOIjWgX-jiOMGwiCBrONrmym-9kMJDOQ4DA15re8d-_MUidnpXbIGCZYTqM_gAJV/exec";

const ATRIUM_SESSION_SECONDS = 21600; // 6 hours
const ATRIUM_COOKIE_NAME = "vumc_atrium_session";


/* =========================================================
   RESPONSE HELPERS
========================================================= */

function response(
  statusCode,
  body,
  extraHeaders = {}
) {
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
    (
      event.headers.cookie ||
      event.headers.Cookie
    )
      ? (
          event.headers.cookie ||
          event.headers.Cookie
        )
      : "";

  const cookies = {};

  String(header)
    .split(";")
    .forEach(part => {
      const index =
        part.indexOf("=");

      if (index === -1) {
        return;
      }

      const name =
        part
          .slice(0, index)
          .trim();

      const value =
        part
          .slice(index + 1)
          .trim();

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
      crypto
        .randomBytes(16)
        .toString("hex")
  };

  const encoded =
    Buffer
      .from(
        JSON.stringify(payload)
      )
      .toString("base64url");

  const signature =
    crypto
      .createHmac(
        "sha256",
        secret
      )
      .update(encoded)
      .digest("base64url");

  return `${encoded}.${signature}`;
}


function verifySessionToken(
  token,
  secret
) {
  if (
    !token ||
    !secret
  ) {
    return false;
  }

  const parts =
    String(token).split(".");

  if (parts.length !== 2) {
    return false;
  }

  const encoded =
    parts[0];

  const suppliedSignature =
    parts[1];

  const expectedSignature =
    crypto
      .createHmac(
        "sha256",
        secret
      )
      .update(encoded)
      .digest("base64url");

  try {
    const suppliedBuffer =
      Buffer.from(
        suppliedSignature
      );

    const expectedBuffer =
      Buffer.from(
        expectedSignature
      );

    if (
      suppliedBuffer.length !==
      expectedBuffer.length
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
    const payload =
      JSON.parse(
        Buffer
          .from(
            encoded,
            "base64url"
          )
          .toString("utf8")
      );

    if (
      !payload.exp ||
      Number(payload.exp) <=
        Math.floor(
          Date.now() / 1000
        )
    ) {
      return false;
    }

    return true;

  } catch (error) {
    return false;
  }
}


function makeSessionCookie(
  sessionToken
) {
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
   GAS REQUEST HELPERS
========================================================= */

function makeRequestId() {
  return (
    Date.now().toString(36) +
    "-" +
    crypto
      .randomBytes(12)
      .toString("hex")
  );
}


async function gasRequest(
  action,
  payload
) {
  const requestId =
    makeRequestId();

  const form =
    new URLSearchParams();

  form.set(
    "requestId",
    requestId
  );

  form.set(
    "action",
    action
  );

  form.set(
    "payload",
    JSON.stringify(
      payload || {}
    )
  );

  const postResponse =
    await fetch(
      STAFF_TOOLS_GAS_URL,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body:
          form.toString(),

        redirect:
          "follow"
      }
    );

  if (!postResponse.ok) {
    throw new Error(
      "Staff authorization service could not be reached."
    );
  }

  const started =
    Date.now();

  const timeoutMs =
    15000;

  while (
    Date.now() - started <
    timeoutMs
  ) {
    await new Promise(
      resolve =>
        setTimeout(
          resolve,
          350
        )
    );

    const callback =
      "atriumCallback";

    const url =
      new URL(
        STAFF_TOOLS_GAS_URL
      );

    url.searchParams.set(
      "api",
      "1"
    );

    url.searchParams.set(
      "requestId",
      requestId
    );

    url.searchParams.set(
      "callback",
      callback
    );

    url.searchParams.set(
      "_",
      String(Date.now())
    );

    const pollResponse =
      await fetch(
        url.toString(),
        {
          redirect:
            "follow",

          headers: {
            "Cache-Control":
              "no-cache"
          }
        }
      );

    if (!pollResponse.ok) {
      continue;
    }

    const text =
      await pollResponse.text();

    const prefix =
      `${callback}(`;

    const suffix =
      ");";

    if (
      !text.startsWith(prefix) ||
      !text.endsWith(suffix)
    ) {
      continue;
    }

    let envelope;

    try {
      envelope =
        JSON.parse(
          text.slice(
            prefix.length,
            -suffix.length
          )
        );

    } catch (error) {
      continue;
    }

    if (
      envelope &&
      envelope.ready
    ) {
      return (
        envelope.result ||
        {
          success: false,
          error:
            "No authorization result was returned."
        }
      );
    }
  }

  throw new Error(
    "Staff authorization timed out."
  );
}


/* =========================================================
   MAIN HANDLER
========================================================= */

exports.handler =
async function (event) {

  const githubToken =
    process.env
      .ATRIUM_GITHUB_TOKEN;

  if (!githubToken) {
    return response(
      500,
      {
        success: false,
        error:
          "Atrium GitHub authorization is not configured."
      }
    );
  }


  /* ---------------------------------------------------------
     OPTIONS
  --------------------------------------------------------- */

  if (
    event.httpMethod ===
    "OPTIONS"
  ) {
    return {
      statusCode: 204,

      headers: {
        "Cache-Control":
          "no-store",

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
      body =
        JSON.parse(
          event.body
        );
    }
  } catch (error) {
    return response(
      400,
      {
        success: false,
        error:
          "The Atrium request could not be read."
      }
    );
  }


  const action =
    (
      event
        .queryStringParameters
        ?.action
    ) ||
    body.action ||
    "";


  /* =========================================================
     REDEEM STAFF TOOLS HANDOFF

     This is the ONLY route that does not require an existing
     Atrium session.
  ========================================================= */

  if (
    action ===
    "redeem-handoff"
  ) {
    const code =
      String(
        body.code ||
        event
          .queryStringParameters
          ?.code ||
        ""
      ).trim();

    if (!code) {
      return response(
        400,
        {
          success: false,
          authRequired: true,
          error:
            "Atrium authorization code is required."
        }
      );
    }

    try {
      const result =
        await gasRequest(
          "redeemAtriumHandoff",
          {
            code
          }
        );

      if (
        !result ||
        result.success !== true
      ) {
        return response(
          401,
          {
            success: false,
            authRequired: true,
            error:
              (
                result &&
                result.error
              ) ||
              "Atrium authorization was not accepted."
          }
        );
      }

      const sessionToken =
        createSessionToken(
          githubToken
        );

      return response(
        200,
        {
          success: true,
          authorized: true,
          expiresIn:
            ATRIUM_SESSION_SECONDS
        },
        {
          "Set-Cookie":
            makeSessionCookie(
              sessionToken
            )
        }
      );

    } catch (error) {
      console.error(
        "Atrium handoff redemption error:",
        error
      );

      return response(
        502,
        {
          success: false,
          error:
            "Atrium could not verify Staff Tools authorization."
        }
      );
    }
  }


  /* =========================================================
     VERIFY ATRIUM SESSION
  ========================================================= */

  const cookies =
    parseCookies(event);

  const sessionToken =
    cookies[
      ATRIUM_COOKIE_NAME
    ];

  const authorized =
    verifySessionToken(
      sessionToken,
      githubToken
    );


  /* ---------------------------------------------------------
     SESSION STATUS
  --------------------------------------------------------- */

  if (
    action ===
    "session"
  ) {
    if (!authorized) {
      return response(
        401,
        {
          success: false,
          authorized: false,
          authRequired: true
        }
      );
    }

    return response(
      200,
      {
        success: true,
        authorized: true
      }
    );
  }


  /* ---------------------------------------------------------
     LOGOUT
  --------------------------------------------------------- */

  if (
    action ===
    "logout"
  ) {
    return response(
      200,
      {
        success: true
      },
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
    return response(
      401,
      {
        success: false,
        authRequired: true,
        error:
          "Atrium Manager authorization is required."
      }
    );
  }


  const githubHeaders = {
    Authorization:
      `Bearer ${githubToken}`,

    Accept:
      "application/vnd.github+json",

    "Content-Type":
      "application/json",

    "X-GitHub-Api-Version":
      "2022-11-28"
  };


  try {

    /* ================================================
       LIST SLIDES
    ================================================= */

    if (
      action ===
      "list"
    ) {
      const githubResponse =
        await fetch(
          `${GITHUB_API}/contents/slides?ref=${BRANCH}`,
          {
            headers:
              githubHeaders
          }
        );

      const data =
        await githubResponse
          .json();

      return response(
        githubResponse.status,
        data
      );
    }


    /* ================================================
       GET CONFIG
    ================================================= */

    if (
      action ===
      "config"
    ) {
      const githubResponse =
        await fetch(
          `${GITHUB_API}/contents/slides-config.json?ref=${BRANCH}`,
          {
            headers:
              githubHeaders
          }
        );

      const data =
        await githubResponse
          .json();

      return response(
        githubResponse.status,
        data
      );
    }


    /* ================================================
       SAVE CONFIG
    ================================================= */

    if (
      action ===
      "save-config"
    ) {
      if (!body.content) {
        return response(
          400,
          {
            success: false,
            error:
              "Configuration content is required."
          }
        );
      }

      const payload = {
        message:
          body.message ||
          "Update Atrium slide configuration",

        content:
          body.content,

        branch:
          BRANCH
      };

      if (body.sha) {
        payload.sha =
          body.sha;
      }

      const githubResponse =
        await fetch(
          `${GITHUB_API}/contents/slides-config.json`,
          {
            method:
              "PUT",

            headers:
              githubHeaders,

            body:
              JSON.stringify(
                payload
              )
          }
        );

      const data =
        await githubResponse
          .json();

      return response(
        githubResponse.status,
        data
      );
    }


    /* ================================================
       UPLOAD / REPLACE SLIDE
    ================================================= */

    if (
      action ===
      "upload"
    ) {
      if (
        !body.filename ||
        !body.content
      ) {
        return response(
          400,
          {
            success: false,
            error:
              "Filename and content are required."
          }
        );
      }

      const payload = {
        message:
          body.message ||
          `Update Atrium slide ${body.filename}`,

        content:
          body.content,

        branch:
          BRANCH
      };

      if (body.sha) {
        payload.sha =
          body.sha;
      }

      const githubResponse =
        await fetch(
          `${GITHUB_API}/contents/slides/${encodeURIComponent(body.filename)}`,
          {
            method:
              "PUT",

            headers:
              githubHeaders,

            body:
              JSON.stringify(
                payload
              )
          }
        );

      const data =
        await githubResponse
          .json();

      return response(
        githubResponse.status,
        data
      );
    }


    /* ================================================
       DELETE SLIDE
    ================================================= */

    if (
      action ===
      "delete"
    ) {
      if (
        !body.filename ||
        !body.sha
      ) {
        return response(
          400,
          {
            success: false,
            error:
              "Filename and SHA are required."
          }
        );
      }

      const githubResponse =
        await fetch(
          `${GITHUB_API}/contents/slides/${encodeURIComponent(body.filename)}`,
          {
            method:
              "DELETE",

            headers:
              githubHeaders,

            body:
              JSON.stringify({
                message:
                  body.message ||
                  `Delete Atrium slide ${body.filename}`,

                sha:
                  body.sha,

                branch:
                  BRANCH
              })
          }
        );

      let data = {};

      const text =
        await githubResponse
          .text();

      if (text) {
        try {
          data =
            JSON.parse(text);
        } catch (error) {
          data = {
            message:
              text
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

    return response(
      400,
      {
        success: false,
        error:
          "Unknown Atrium API action."
      }
    );

  } catch (error) {
    console.error(
      "Atrium API Error:",
      error
    );

    return response(
      500,
      {
        success: false,
        error:
          "Atrium API request failed.",
        detail:
          error.message
      }
    );
  }
};
