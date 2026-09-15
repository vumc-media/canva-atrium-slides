const OWNER = "vumc-media";
const REPO = "canva-atrium-slides";
const BRANCH = "main";

const GITHUB_API = `https://api.github.com/repos/${OWNER}/${REPO}`;

exports.handler = async function (event) {
  const token = process.env.ATRIUM_GITHUB_TOKEN;

  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"
  };

  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 204,
      headers,
      body: ""
    };
  }

  if (!token) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        error: "Atrium GitHub authorization is not configured."
      })
    };
  }

  const githubHeaders = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "Content-Type": "application/json",
    "X-GitHub-Api-Version": "2022-11-28"
  };

  try {
    const body = event.body ? JSON.parse(event.body) : {};
    const action =
      event.queryStringParameters?.action ||
      body.action;

    /* ================================================
       LIST SLIDES
    ================================================= */

    if (action === "list") {
      const response = await fetch(
        `${GITHUB_API}/contents/slides?ref=${BRANCH}`,
        {
          headers: githubHeaders
        }
      );

      const data = await response.json();

      return {
        statusCode: response.status,
        headers,
        body: JSON.stringify(data)
      };
    }

    /* ================================================
       GET CONFIG
    ================================================= */

    if (action === "config") {
      const response = await fetch(
        `${GITHUB_API}/contents/slides-config.json?ref=${BRANCH}`,
        {
          headers: githubHeaders
        }
      );

      const data = await response.json();

      return {
        statusCode: response.status,
        headers,
        body: JSON.stringify(data)
      };
    }

    /* ================================================
       SAVE CONFIG
    ================================================= */

    if (action === "save-config") {
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

      const response = await fetch(
        `${GITHUB_API}/contents/slides-config.json`,
        {
          method: "PUT",
          headers: githubHeaders,
          body: JSON.stringify(payload)
        }
      );

      const data = await response.json();

      return {
        statusCode: response.status,
        headers,
        body: JSON.stringify(data)
      };
    }

    /* ================================================
       UPLOAD / REPLACE SLIDE
    ================================================= */

    if (action === "upload") {
      if (!body.filename || !body.content) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({
            error: "Filename and content are required."
          })
        };
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

      const response = await fetch(
        `${GITHUB_API}/contents/slides/${encodeURIComponent(body.filename)}`,
        {
          method: "PUT",
          headers: githubHeaders,
          body: JSON.stringify(payload)
        }
      );

      const data = await response.json();

      return {
        statusCode: response.status,
        headers,
        body: JSON.stringify(data)
      };
    }

    /* ================================================
       DELETE SLIDE
    ================================================= */

    if (action === "delete") {
      if (!body.filename || !body.sha) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({
            error: "Filename and SHA are required."
          })
        };
      }

      const response = await fetch(
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

      const text = await response.text();

      if (text) {
        data = JSON.parse(text);
      }

      return {
        statusCode: response.status,
        headers,
        body: JSON.stringify(data)
      };
    }

    /* ================================================
       UNKNOWN ACTION
    ================================================= */

    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({
        error: "Unknown Atrium API action."
      })
    };

  } catch (error) {
    console.error("Atrium API Error:", error);

    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        error: "Atrium API request failed.",
        detail: error.message
      })
    };
  }
};
