
# MCP Launcher: Your All-in-One Application & OAuth2 Server

**MCP Launcher** is a powerful, containerized solution that simplifies application delivery and security. It combines a dynamic configuration dashboard with a robust, built-in OAuth2 provider, giving you a centralized hub for managing and protecting your services.

Whether you're deploying a suite of microservices or a single application, MCP Launcher provides the tools you need to streamline configuration, manage user access, and secure your endpoints with modern authentication standards.

---

## ✨ Key Features

*   **Dynamic Configuration Dashboard:** Easily manage your application's configuration files through a secure, user-friendly web interface. No more manual edits and container restarts.
*   **Built-in OAuth2 Provider:** Secure your applications with a fully-featured OAuth2 and OpenID Connect (OIDC) server, powered by ORY Hydra.
*   **Container-First Design:** Built with Docker, for easy, repeatable deployments in any environment.
*   **Extensible & Customizable:** Designed to be the backbone of your application ecosystem, with a flexible configuration system that can adapt to your needs.
*   **Developer Friendly:** Clear API documentation and a straightforward setup process to get you up and running in minutes.

---

## ⚙️ Requirements

*   **Docker & Docker Compose:** To build and run the MCP Launcher container.
*   **Reverse Proxy (Recommended):** A separate reverse proxy like **Nginx** or **Traefik** is recommended for handling HTTPS offloading and providing an additional layer of security.

---

## 🚀 Installation & Setup

Getting started with MCP Launcher is simple. The included `docker-compose.yml` file handles the setup of the main application and its Redis dependency.

**1. Build and Run the Container:**

```bash
docker-compose up --build -d
```

This command will build the `mcp-launcher` image and start the necessary containers in the background.

**2. Access the Dashboard:**

Once the container is running, you can access the configuration dashboard at:

*   **URL:** `http://localhost:3000/dashboard`
*   **Default Username:** `admin@email.com`
*   **Default Password:** `mcp-admin`

**3. Initial Configuration:**

Upon your first login, you will be prompted to configure the necessary settings for your environment. The dashboard provides a user-friendly interface for managing the various configuration files used by MCP Launcher and its integrated services.

---

## 🔧 Configuration

MCP Launcher's configuration is managed through a set of YAML files, which can be edited directly or through the web dashboard.

### User Management

Users for the dashboard are managed in the `app/config/dashboard.yaml` file. You can add new users and manage existing ones by editing this file. Passwords are automatically hashed when updated through the dashboard.

### Scopes and Password Changes

*   **OAuth2 Scopes:** The available OAuth2 scopes are defined in `app/config/local.yaml`. You can customize these to fit the needs of your applications.
*   **Password Changes:** User passwords for the dashboard can be changed by logging in and using the provided form. The application will handle the necessary hashing and update the configuration file.

### API and OAuth2 Endpoints

MCP Launcher exposes several important endpoints for authentication and API documentation:

*   **API Documentation:** `http://localhost:3000/docs`
*   **OAuth2 Authorization Endpoint:** `/oauth/oauth2/auth`
*   **OAuth2 Token Endpoint:** `/oauth/oauth2/token`
*   **OpenID Connect Discovery:** `/.well-known/openid-configuration`

For a full list of endpoints and their usage, please refer to the API documentation available at the `/docs` endpoint.

---

## <footer>

<p align="center">
  Built with human ingenuity & a dash of AI wizardry.<br>
  This project emerged from late-night coding sessions, unexpected inspiration, and the occasional debugging dance. Every line of code has a story behind it.
</p>

<p align="center">
  Found a bug? Have a wild idea? The <a href="https://github.com/[your-github-username]/[your-repo-name]/issues">issues tab</a> is your canvas.
</p>

<p align="center">
  Authored By: ‍ Jurgen Mahn with some help from AI code monkies Claude code & codex
</p>

<p align="center">
  <em>"Sometimes the code writes itself. Other times, we collaborate with the machines."</em>
</p>

<p align="center">
  ⚡ Happy hacking, fellow explorer ⚡
</p>
