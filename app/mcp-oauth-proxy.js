import express from 'express';
import bodyParser from 'body-parser';
import fs from 'fs';
import bcrypt from 'bcrypt';
import { URL } from 'url';
import { request } from 'undici';
import dns from 'dns';
import YAML from 'yaml';

const dnsPromises = dns.promises;

const config = YAML.parse(fs.readFileSync('./config/local.yaml', 'utf-8'));
const HYDRA_HOSTNAME = config.hydra.hostname;
const HYDRA_PUBLIC_PORT = config.hydra.public_port;
const HYDRA_ADMIN_PORT = config.hydra.admin_port;
const HYDRA_ADMIN_URL = config.hydra.admin_url;
const HYDRA_PUBLIC_URL = config.hydra.public_url;
const ALLOWED_REDIRECT_DOMAINS = config.oauth.allowed_redirect_domains;
const ALLOWED_SCOPES = config.oauth.allowed_scopes;
const users = config.users;

const app = express();
const port = config.services.oauth_proxy.port;

app.use(bodyParser.urlencoded({
  extended: false
}));
app.use(express.static('public'));

// Templates
function loadTemplate(templateName) {
  return fs.readFileSync(`./templates/${templateName}.html`, 'utf-8');
}

function renderTemplate(template, replacements) {
  return Object.entries(replacements).reduce(
    (html, [key, val]) => html.replace(new RegExp(`{{${key}}}`, 'g'), val),
    template
  );
}

// Helper function to get client from Hydra
const getClient = async (client_id) => {
    try {
        console.log('Calling Hydra at:', `${HYDRA_ADMIN_URL}/admin/clients/${client_id}`);
        const response = await request(`http://${HYDRA_HOSTNAME}:${HYDRA_ADMIN_PORT}/admin/clients/${client_id}`, {
            headers: {
                Host: HYDRA_HOSTNAME
            }
        });

        return response;

    } catch (err) {
        err.response = err.response || {};
        err.response.statusCode = err.response.statusCode || 500;
        err.response.data = err.response.data || 'Internal error';
        console.error('Error checking client:', err.response.data);
        return err.response;
    }
}

// Dynamic Registration Endpoint
app.get('/oauth/oauth2/auth', async (req, res) => {
    const {
        client_id,
        redirect_uri,
        scope
    } = req.query;

    if (!client_id || !redirect_uri) {
        return res.status(400).send('Missing client_id or redirect_uri');
    }

    try {
        const uriHost = new URL(redirect_uri).host;
        const domainAllowed = ALLOWED_REDIRECT_DOMAINS.some(domain =>
            uriHost === domain || uriHost.endsWith(`.${domain}`)
        );

        if (!domainAllowed) {
            return res.status(403).send('Untrusted redirect_uri domain');
        }
    } catch (e) {
        return res.status(400).send('Invalid redirect_uri');
    }

    let response;
    let data;

    await getClient(client_id).then(async (response) => {

        data = await response.body.text();
        console.log("Check if client already exist, response: ", data, " status code: ", response.statusCode);

        if (response.statusCode === 404) {
            const safeScope = (scope || 'openid')
                .split(/\s+/)
                .filter(s => ALLOWED_SCOPES.includes(s))
                .join(' ') || 'openid';

            await request(`http://${HYDRA_HOSTNAME}:${HYDRA_ADMIN_PORT}/admin/clients`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Host': HYDRA_HOSTNAME
                },
                body: JSON.stringify({
                    client_id,
                    redirect_uris: [redirect_uri],
                    scope: safeScope,
                    grant_types: ['authorization_code'],
                    response_types: ['code'],
                    token_endpoint_auth_method: 'none'
                })
            });

            console.log('Client registered successfully:', client_id);

        } else if (response.statusCode >= 500) {
            console.error('Hydra server error:', data);
            return res.status(500).send('Hydra server error');  
        }
    });

    let queryString = new URLSearchParams(req.query);
    queryString.append("validate", "1");

    return res.redirect(302, `${HYDRA_PUBLIC_URL}/oauth/oauth2/auth?${queryString.toString()}`);
});

// Login GET
app.get('/login', async (req, res) => {
  const challenge = req.query.login_challenge;
  if (!challenge) return res.status(400).send('Missing login_challenge');

  const html = renderTemplate(loadTemplate('login'), {
    CHALLENGE: challenge,
    ERROR_MESSAGE: ''
  });
  res.send(html);
});

// Login POST
app.post('/login', async (req, res) => {
  const challenge = req.query.login_challenge;
  if (!challenge) return res.status(400).send('Missing login_challenge');

  const {
    email,
    password
  } = req.body;
  const user = users.find(u => u.email === email);

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    const html = renderTemplate(loadTemplate('login'), {
      CHALLENGE: challenge,
      ERROR_MESSAGE: '<div class="error-message">Invalid email or password. Please try again.</div>'
    });
    return res.status(401).send(html);
  }

  try {
    const response = await request(`${HYDRA_ADMIN_URL}/oauth2/auth/requests/login/accept?login_challenge=${challenge}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        subject: email,
        remember: true,
        remember_for: 3600
      }),
      maxRedirects: 0
    });

    const data = await response.body.text();

    console.log('Login accept response httpcode: ', response.statusCode);

    if (response.statusCode >= 300 && response.statusCode < 400) {
      const redirectUrl = Array.isArray(response.headers.location) ? response.headers.location[0] : response.headers.location;
      console.log(`Redirect ${redirectCount}: ${redirectUrl}`);
      return res.redirect(response.statusCode, redirectUrl);
    } else {

      try {
        const jsonData = JSON.parse(data);
        console.log('Login accept response JSON:', jsonData);
        if (jsonData.redirect_to) {
          return res.redirect(jsonData.redirect_to);
        }
      } catch (e) {
        console.error('Login accept response is not JSON:', data);
        return res.status(500).send('Login accept response is not valid JSON.');
      }
      return res.status(response.statusCode).send(data);
    }
  } catch (err) {
    console.error('Login accept failed:', err.message);
    res.status(500).send('Login failed.');
  }
});

// Consent GET
app.get('/consent', async (req, res) => {
  const challenge = req.query.consent_challenge;
  if (!challenge) return res.status(400).send('Missing consent_challenge');

  try {
    const {
      body
    } = await request(`${HYDRA_ADMIN_URL}/oauth2/auth/requests/consent?consent_challenge=${challenge}`, {
      method: 'GET'
    });
    const data = await body.json();
    const scopesList = data.requested_scope.map(scope => `<li>${scope}</li>`).join('');

    const html = renderTemplate(loadTemplate('consent'), {
      CHALLENGE: challenge,
      CLIENT_NAME: data.client.client_name || data.client.client_id,
      SCOPE_LIST: scopesList
    });

    res.send(html);
  } catch (err) {
    console.error('Consent get failed:', err.message);
    res.status(500).send('Consent error.');
  }
});

// Consent POST
app.post('/consent', async (req, res) => {
  const challenge = req.query.consent_challenge;
  if (!challenge) return res.status(400).send('Missing consent_challenge');

  try {
    const {
      body: consentBody
    } = await request(`${HYDRA_ADMIN_URL}/oauth2/auth/requests/consent?consent_challenge=${challenge}`, {
      method: 'GET'
    });
    const consentRequest = await consentBody.json();

    const {
      body: acceptBody
    } = await request(`${HYDRA_ADMIN_URL}/oauth2/auth/requests/consent/accept?consent_challenge=${challenge}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        grant_scope: consentRequest.requested_scope,
        remember: true,
        remember_for: 3600,
        session: {
          id_token: {
            email: consentRequest.subject
          }
        }
      })
    });
    const accept = await acceptBody.json();

    res.redirect(accept.redirect_to);
  } catch (err) {
    console.error('Consent accept failed:', err.message);
    res.status(500).send('Consent failed.');
  }
});

app.listen(port, '0.0.0.0', () => {
  console.log(`✅ OAuth Proxy (Login/Consent + Dynamic Registration) listening on port ${port}`);
});