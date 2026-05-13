# inouk_api_auth : OAuth 2.1 Authorization Code + PKCE

**Version** : 1.0
**Date** : 1er janvier 2026
**Auteur** : Cyril MORISSE, Claude
**Statut** : Implémenté - Production Ready
**Module cible** : `inouk_api_auth` (extension)

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Modèles de données](#2-modèles-de-données)
3. [Endpoints](#3-endpoints)
4. [Écran de consentement](#4-écran-de-consentement)
5. [Scopes MCP](#5-scopes-mcp)
6. [Configuration](#6-configuration)
7. [Sécurité](#7-sécurité)
8. [Tests](#8-tests)
9. [Migration](#9-migration)
10. [Nettoyage inouk_api_auth](#10-nettoyage-inouk_api_auth-généralisation)
11. [Statut d'implémentation](#11-statut-dimplémentation)

---

## 1. Vue d'ensemble

### 1.1 Contexte

Claude.ai (le client web d'Anthropic) nécessite une authentification OAuth 2.1 avec Authorization Code + PKCE pour se connecter aux serveurs MCP distants. Le flow `client_credentials` actuellement implémenté dans `inouk_api_auth` n'est **pas supporté** par Claude.ai.

> "Pure client credentials flow (machine-to-machine OAuth with just client_id/client_secret and no user interaction) is not supported."
> — [Anthropic Connectors Directory FAQ](https://support.claude.com/en/articles/11596036-anthropic-connectors-directory-faq)

### 1.2 Objectif

Étendre `inouk_api_auth` pour supporter OAuth 2.1 Authorization Code + PKCE, permettant :
- **Claude.ai** : S'authentifier auprès du serveur MCP Muppy
- **CLI mpy/mgx** : Authentification interactive des utilisateurs depuis le terminal

### 1.3 Clients cibles

| Client | Type | Redirect URI | Flow |
|--------|------|--------------|------|
| Claude.ai | Web App | `https://claude.ai/api/mcp/auth_callback` | Authorization Code + PKCE |
| CLI mpy | Native CLI | `http://localhost:{port}/callback` | Authorization Code + PKCE |
| CLI mgx | Native CLI | `http://localhost:{port}/callback` | Authorization Code + PKCE |
| Futur mobile | Mobile App | Custom scheme `muppy://callback` | Authorization Code + PKCE |

### 1.4 RFCs implémentées

| RFC | Nom | Usage |
|-----|-----|-------|
| [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13) | OAuth 2.1 | Flow principal Authorization Code |
| [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | Authorization Server Metadata | Discovery des endpoints OAuth |
| [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) | Protected Resource Metadata | Lien MCP → Auth Server |
| [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) | Dynamic Client Registration | Enregistrement automatique des clients |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | PKCE | Protection du code d'autorisation |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | Resource Indicators | Binding token → ressource |

### 1.5 Flow OAuth complet

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    FLOW OAuth 2.1 Authorization Code + PKCE                      │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────┐                                         ┌─────────────────────────┐
│  Claude.ai  │                                         │  Muppy MCP Server       │
│             │                                         │  (inouk_api_auth)       │
└──────┬──────┘                                         └────────────┬────────────┘
       │                                                             │
       │ 1. POST /mcp (sans auth)                                    │
       │────────────────────────────────────────────────────────────>│
       │                                                             │
       │ 2. 401 Unauthorized                                         │
       │    WWW-Authenticate: Bearer                                 │
       │    resource_metadata="/.well-known/oauth-protected-resource"│
       │<────────────────────────────────────────────────────────────│
       │                                                             │
       │ 3. GET /.well-known/oauth-protected-resource                │
       │────────────────────────────────────────────────────────────>│
       │                                                             │
       │ 4. { "authorization_servers": ["https://..."] }             │
       │<────────────────────────────────────────────────────────────│
       │                                                             │
       │ 5. GET /.well-known/oauth-authorization-server              │
       │────────────────────────────────────────────────────────────>│
       │                                                             │
       │ 6. Authorization Server Metadata                            │
       │    (authorization_endpoint, token_endpoint, etc.)           │
       │<────────────────────────────────────────────────────────────│
       │                                                             │
       │ 7. POST /oauth/register (DCR - si supporté)                 │
       │    { "client_name": "Claude", "redirect_uris": [...] }      │
       │────────────────────────────────────────────────────────────>│
       │                                                             │
       │ 8. { "client_id": "ikaa_xxx", "client_name": "Claude" }     │
       │<────────────────────────────────────────────────────────────│
       │                                                             │
       │ 9. Redirect user → /oauth/authorize                         │
       │    ?response_type=code                                      │
       │    &client_id=ikaa_xxx                                      │
       │    &redirect_uri=https://claude.ai/api/mcp/auth_callback    │
       │    &code_challenge=BASE64URL(SHA256(verifier))              │
       │    &code_challenge_method=S256                              │
       │    &state=random_state                                      │
       │    &resource=https://muppy.example.com                      │
       │    &scope=mcp:discovery mcp:read mcp:write                   │
       │────────────────────────────────────────────────────────────>│
       │                                                             │
       │         ┌────────────────────────────────────────────┐      │
       │         │  ÉCRAN DE CONSENTEMENT ODOO                │      │
       │         │                                            │      │
       │         │  "Claude" demande l'accès à :              │      │
       │         │  ☑ mcp:discovery - Navigation et structure │      │
       │         │  ☑ mcp:read - Lecture des données          │      │
       │         │  ☑ mcp:write - Modification des données    │      │
       │         │                                            │      │
       │         │  [ Autoriser ]  [ Refuser ]                │      │
       │         └────────────────────────────────────────────┘      │
       │                                                             │
       │ 10. Redirect → claude.ai/api/mcp/auth_callback              │
       │     ?code=AUTH_CODE_123                                     │
       │     &state=random_state                                     │
       │<────────────────────────────────────────────────────────────│
       │                                                             │
       │ 11. POST /oauth/token                                       │
       │     grant_type=authorization_code                           │
       │     code=AUTH_CODE_123                                      │
       │     redirect_uri=https://claude.ai/api/mcp/auth_callback    │
       │     client_id=ikaa_xxx                                      │
       │     code_verifier=ORIGINAL_VERIFIER                         │
       │     resource=https://muppy.example.com                      │
       │────────────────────────────────────────────────────────────>│
       │                                                             │
       │ 12. {                                                       │
       │       "access_token": "ikaa_yyy...",                        │
       │       "token_type": "Bearer",                               │
       │       "expires_in": 3600,                                   │
       │       "refresh_token": "ikrt_zzz...",                       │
       │       "scope": "mcp:discovery mcp:read mcp:write"            │
       │     }                                                       │
       │<────────────────────────────────────────────────────────────│
       │                                                             │
       │ 13. POST /mcp                                               │
       │     Authorization: Bearer ikaa_yyy...                       │
       │     { "jsonrpc": "2.0", "method": "tools/list", "id": 1 }   │
       │────────────────────────────────────────────────────────────>│
       │                                                             │
       │ 14. MCP Response                                            │
       │<────────────────────────────────────────────────────────────│
       │                                                             │
       │                    ... Token Refresh ...                    │
       │                                                             │
       │ 15. POST /oauth/token                                       │
       │     grant_type=refresh_token                                │
       │     refresh_token=ikrt_zzz...                               │
       │     client_id=ikaa_xxx                                      │
       │────────────────────────────────────────────────────────────>│
       │                                                             │
       │ 16. { "access_token": "ikaa_new...", "refresh_token": ... } │
       │<────────────────────────────────────────────────────────────│
```

### 1.6 Différences client_credentials vs authorization_code

| Aspect | client_credentials (actuel) | authorization_code (nouveau) |
|--------|----------------------------|------------------------------|
| Interaction utilisateur | Non | **Oui (obligatoire)** |
| Consentement | Non | **Écran de consentement** |
| PKCE | Non | **Obligatoire (S256)** |
| Refresh tokens | Optionnel | **Supporté** |
| Scopes | Implicites | **Explicites et granulaires** |
| Use case | Machine-to-machine | **Utilisateur humain via client** |

### 1.7 Flow CLI (mpy/mgx) - Device Code

Les CLI utilisent le **Device Code flow** (style Cloudflare) pour les environnements remote (SSH, containers).
L'URL contient un token unique - l'utilisateur n'a pas de code à taper.

**Sécurité** : L'utilisateur doit être authentifié sur Odoo pour autoriser. Même si l'URL est interceptée,
l'attaquant devrait avoir un compte Odoo, et le token serait lié à son compte (pas celui de la victime).

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    FLOW CLI - Device Code (style Cloudflare)                     │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────┐              ┌─────────────┐              ┌─────────────────────┐
│   CLI mpy   │              │  Navigateur │              │  Muppy OAuth Server │
└──────┬──────┘              └──────┬──────┘              └──────────┬──────────┘
       │                            │                                │
       │ 1. POST /oauth/device                                      │
       │    { client_id, scope }                                    │
       │────────────────────────────────────────────────────────────>│
       │                                                             │
       │ 2. {                                                        │
       │      device_code: "dc_xxx",                                │
       │      verification_uri: "https://.../oauth/device/dc_xxx",  │
       │      expires_in: 600,                                       │
       │      interval: 5                                            │
       │    }                                                        │
       │<────────────────────────────────────────────────────────────│
       │                                                             │
       │ 3. Afficher URL à l'utilisateur                            │
       │    "Visit: https://.../oauth/device/dc_xxx"                │
       │                                                             │
       │         ┌─────────────────────────────────────────────────┐ │
       │         │ User ouvre l'URL (même machine, mobile, etc.)   │ │
       │         └─────────────────────────────────────────────────┘ │
       │                            │                                │
       │                            │ 4. GET /oauth/device/dc_xxx   │
       │                            │ ──────────────────────────────>│
       │                            │                                │
       │                            │ 5. User loggé sur Odoo ?      │
       │                            │    Non → Login Odoo           │
       │                            │    Oui → Écran consentement   │
       │                            │<──────────────────────────────│
       │                            │                                │
       │                            │ 6. [Autoriser] / [Refuser]    │
       │                            │ ──────────────────────────────>│
       │                            │                                │
       │                            │ 7. "Autorisé ! Retournez au   │
       │                            │    terminal."                  │
       │                            │<──────────────────────────────│
       │                                                             │
       │ 4-7. Pendant ce temps, CLI poll toutes les 2s              │
       │      POST /oauth/token                                      │
       │      { grant_type: "urn:ietf:params:oauth:grant-type:      │
       │                     device_code",                           │
       │        device_code: "dc_xxx", client_id: "mpy-cli" }       │
       │────────────────────────────────────────────────────────────>│
       │                                                             │
       │      Réponses possibles :                                   │
       │      - { error: "authorization_pending" } → continuer      │
       │      - { error: "slow_down" } → augmenter interval         │
       │      - { error: "access_denied" } → user a refusé          │
       │      - { error: "expired_token" } → timeout                │
       │      - { access_token: "...", ... } → SUCCÈS !             │
       │<────────────────────────────────────────────────────────────│
       │                                                             │
       │ 8. Sauvegarder tokens dans ~/.mpy/credentials              │
       │                                                             │
       │ 9. Afficher "✓ Logged in as cyril@muppy.cloud"             │
```

**Exemple d'utilisation CLI** :

```bash
$ mpy login --server https://mpy18c-k8s-dev-cyril.muppy.cloud

To sign in, visit:
  https://mpy18c-k8s-dev-cyril.muppy.cloud/oauth/device/dc_abc123xyz

Waiting for authorization... (press Ctrl+C to cancel)
..........
✓ Logged in as cyril@muppy.cloud
  Token expires: 2026-01-01 15:00:00
  Scopes: mcp:discovery mcp:read mcp:write
```

**Fallback mode (--manual)** pour environnements sans polling fiable :

```bash
$ mpy login --server https://mpy18c-k8s-dev-cyril.muppy.cloud --manual

To sign in, visit:
  https://mpy18c-k8s-dev-cyril.muppy.cloud/oauth/device/dc_abc123xyz

After authorization, paste the code shown on screen:
> ABCD-1234-EFGH

✓ Logged in as cyril@muppy.cloud
```

**Implémentation côté CLI** (exemple Python) :

```python
# mpy/auth/oauth_device.py
import time
import requests
import secrets


class DeviceCodeFlow:
    """OAuth 2.1 Device Code flow for CLI applications."""

    GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

    def __init__(self, server_url, client_id="mpy-cli"):
        self.server_url = server_url
        self.client_id = client_id

    def login(self, scopes=None, manual=False):
        """Perform Device Code login.

        Args:
            scopes: List of scopes to request
            manual: If True, ask user to paste code instead of polling

        Returns:
            dict: Token response with access_token, refresh_token, etc.
        """
        if scopes is None:
            scopes = ['mcp:discovery', 'mcp:read', 'mcp:write']

        # 1. Request device code
        resp = requests.post(
            f"{self.server_url}/oauth/device",
            data={
                'client_id': self.client_id,
                'scope': ' '.join(scopes),
            }
        )
        resp.raise_for_status()
        device_data = resp.json()

        device_code = device_data['device_code']
        verification_uri = device_data['verification_uri']
        expires_in = device_data.get('expires_in', 600)
        interval = device_data.get('interval', 5)

        # 2. Display URL to user
        print(f"\nTo sign in, visit:\n  {verification_uri}\n")

        if manual:
            return self._manual_flow(device_code)
        else:
            return self._polling_flow(device_code, expires_in, interval)

    def _polling_flow(self, device_code, expires_in, interval):
        """Poll until user authorizes or timeout."""
        print("Waiting for authorization... (press Ctrl+C to cancel)")

        deadline = time.time() + expires_in
        while time.time() < deadline:
            time.sleep(interval)
            print(".", end="", flush=True)

            result = self._poll_token(device_code)
            if result.get('error') == 'authorization_pending':
                continue
            elif result.get('error') == 'slow_down':
                interval += 5
                continue
            elif 'access_token' in result:
                print()  # Newline after dots
                return result
            else:
                raise Exception(f"Authorization failed: {result.get('error_description', result.get('error'))}")

        raise Exception("Authorization timed out")

    def _poll_token(self, device_code):
        """Single poll request."""
        resp = requests.post(
            f"{self.server_url}/oauth/token",
            data={
                'grant_type': self.GRANT_TYPE,
                'device_code': device_code,
                'client_id': self.client_id,
            }
        )
        return resp.json()

    def _manual_flow(self, device_code):
        """Ask user to paste authorization code."""
        code = input("After authorization, paste the code shown on screen:\n> ").strip()

        resp = requests.post(
            f"{self.server_url}/oauth/token",
            data={
                'grant_type': self.GRANT_TYPE,
                'device_code': device_code,
                'client_id': self.client_id,
                'user_code': code,  # For manual verification
            }
        )
        resp.raise_for_status()
        return resp.json()
```

**Stockage des credentials CLI** :

```
~/.mpy/
├── config.yaml           # Configuration (server URL, default org, etc.)
└── credentials/
    └── mpy18c-k8s-dev-cyril.muppy.cloud.json
        {
          "access_token": "ikaa_...",
          "refresh_token": "ikrt_...",
          "expires_at": "2026-01-01T14:00:00Z",
          "scope": "mcp:discovery mcp:read mcp:write"
        }
```

---

## 2. Modèles de données

### 2.1 Structure des fichiers

```
inouk_api_auth/
├── models/
│   ├── __init__.py                          # Ajouter imports
│   ├── oauth_authorization_code.py          # NOUVEAU
│   ├── oauth_client_registration.py         # NOUVEAU
│   ├── oauth_refresh_token.py               # NOUVEAU
│   ├── oauth_device_code.py                 # NOUVEAU (Device Code flow CLI)
│   └── api_auth_token__oauth_client.py      # MODIFIER (ajouter champs)
├── controllers/
│   └── oauth.py                             # MODIFIER (ajouter /oauth/device)
├── security/
│   └── ir.model.access.csv                  # MODIFIER
├── views/
│   ├── oauth_client_registration_views.xml  # NOUVEAU
│   ├── oauth_consent_templates.xml          # NOUVEAU (écran consentement web)
│   └── oauth_device_templates.xml           # NOUVEAU (écrans Device Code CLI)
└── data/
    ├── cron_oauth21.xml                      # NOUVEAU (cleanup jobs)
    └── oauth_clients.xml                     # NOUVEAU (CLI pré-enregistrés)
```

### 2.2 `ik.oauth_authorization_code`

Stocke les codes d'autorisation temporaires générés lors du flow OAuth.

```python
# models/oauth_authorization_code.py
import secrets
import hashlib
import base64
from datetime import timedelta
from odoo import models, fields, api
from odoo.exceptions import ValidationError


class IkOAuthAuthorizationCode(models.Model):
    _name = 'ik.oauth_authorization_code'
    _description = "OAuth 2.1 Authorization Code"
    _order = 'create_date desc'

    # ═══════════════════════════════════════════════════════════════════════
    # CODE IDENTIFICATION
    # ═══════════════════════════════════════════════════════════════════════

    code = fields.Char(
        string="Authorization Code",
        required=True,
        index=True,
        readonly=True,
        default=lambda self: self._generate_code(),
        help="256-bit random code, base64url encoded"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # CLIENT & USER
    # ═══════════════════════════════════════════════════════════════════════

    client_registration_id = fields.Many2one(
        'ik.oauth_client_registration',
        string="Client",
        required=True,
        ondelete='cascade',
        index=True
    )
    client_id = fields.Char(
        related='client_registration_id.client_id',
        store=True,
        index=True
    )
    user_id = fields.Many2one(
        'res.users',
        string="User",
        required=True,
        ondelete='cascade',
        index=True,
        help="User who granted consent"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # AUTHORIZATION PARAMETERS
    # ═══════════════════════════════════════════════════════════════════════

    redirect_uri = fields.Char(
        string="Redirect URI",
        required=True,
        help="Callback URI for this authorization"
    )
    scope = fields.Char(
        string="Scope",
        help="Space-separated list of granted scopes"
    )
    state = fields.Char(
        string="State",
        help="CSRF protection state parameter"
    )
    resource = fields.Char(
        string="Resource",
        help="RFC 8707 resource indicator"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # PKCE (RFC 7636)
    # ═══════════════════════════════════════════════════════════════════════

    code_challenge = fields.Char(
        string="Code Challenge",
        required=True,
        help="PKCE code challenge (S256 hash of verifier)"
    )
    code_challenge_method = fields.Selection([
        ('S256', 'SHA-256'),
    ], string="Code Challenge Method",
       required=True,
       default='S256',
       help="Only S256 is supported (plain is insecure)"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # LIFECYCLE
    # ═══════════════════════════════════════════════════════════════════════

    expires_at = fields.Datetime(
        string="Expires At",
        required=True,
        default=lambda self: fields.Datetime.add(
            fields.Datetime.now(),
            seconds=int(self.env['ir.config_parameter'].sudo().get_param(
                'inouk_api_auth.oauth_code_lifetime', '600'
            ))
        ),
        help="Authorization codes expire after 10 minutes max"
    )
    used = fields.Boolean(
        string="Used",
        default=False,
        help="Code can only be used once"
    )
    used_at = fields.Datetime(
        string="Used At"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # METHODS
    # ═══════════════════════════════════════════════════════════════════════

    @api.model
    def _generate_code(self):
        """Generate a cryptographically secure authorization code."""
        # 256 bits of randomness, base64url encoded
        return secrets.token_urlsafe(32)

    def validate_pkce(self, code_verifier):
        """Validate PKCE code_verifier against stored code_challenge.

        Args:
            code_verifier: The original verifier from the client

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If PKCE validation fails
        """
        self.ensure_one()

        if self.code_challenge_method != 'S256':
            raise ValidationError("Only S256 code challenge method is supported")

        # Compute S256: BASE64URL(SHA256(code_verifier))
        verifier_bytes = code_verifier.encode('ascii')
        digest = hashlib.sha256(verifier_bytes).digest()
        computed_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

        # Constant-time comparison
        if not secrets.compare_digest(computed_challenge, self.code_challenge):
            raise ValidationError("Invalid PKCE code_verifier")

        return True

    def consume(self):
        """Mark code as used. Can only be called once.

        Returns:
            self

        Raises:
            ValidationError: If code was already used or is expired
        """
        self.ensure_one()

        if self.used:
            raise ValidationError("Authorization code has already been used")

        if fields.Datetime.now() > self.expires_at:
            raise ValidationError("Authorization code has expired")

        self.write({
            'used': True,
            'used_at': fields.Datetime.now(),
        })
        return self

    @api.model
    def _cron_cleanup_expired(self):
        """Cleanup expired authorization codes."""
        expired = self.search([
            '|',
            ('expires_at', '<', fields.Datetime.now()),
            ('used', '=', True),
        ])
        expired.unlink()

    _sql_constraints = [
        ('code_unique', 'unique(code)', 'Authorization code must be unique'),
    ]
```

### 2.3 `ik.oauth_client_registration`

Stocke les clients OAuth enregistrés (via DCR ou manuellement).

```python
# models/oauth_client_registration.py
import secrets
from odoo import models, fields, api
from odoo.exceptions import ValidationError


class IkOAuthClientRegistration(models.Model):
    _name = 'ik.oauth_client_registration'
    _description = "OAuth 2.1 Client Registration"
    _order = 'create_date desc'
    _rec_name = 'client_name'

    # ═══════════════════════════════════════════════════════════════════════
    # CLIENT IDENTIFICATION
    # ═══════════════════════════════════════════════════════════════════════

    client_id = fields.Char(
        string="Client ID",
        required=True,
        index=True,
        readonly=True,
        default=lambda self: self._generate_client_id(),
        help="Public client identifier"
    )
    client_secret = fields.Char(
        string="Client Secret",
        help="Client secret (optional for public clients)"
    )
    client_name = fields.Char(
        string="Client Name",
        required=True,
        help="Human-readable client name (e.g., 'Claude')"
    )
    client_uri = fields.Char(
        string="Client URI",
        help="URL of the client's home page"
    )
    logo_uri = fields.Char(
        string="Logo URI",
        help="URL of the client's logo"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # REGISTRATION TYPE
    # ═══════════════════════════════════════════════════════════════════════

    registration_type = fields.Selection([
        ('dynamic', 'Dynamic (DCR)'),
        ('manual', 'Manual'),
    ], string="Registration Type",
       default='manual',
       required=True,
       help="How this client was registered"
    )
    active = fields.Boolean(
        default=True
    )

    # ═══════════════════════════════════════════════════════════════════════
    # REDIRECT URIS
    # ═══════════════════════════════════════════════════════════════════════

    redirect_uris = fields.Text(
        string="Redirect URIs",
        required=True,
        help="Newline-separated list of allowed redirect URIs"
    )
    redirect_uri_list = fields.Char(
        string="Redirect URI List",
        compute='_compute_redirect_uri_list',
        help="Comma-separated list for display"
    )

    @api.depends('redirect_uris')
    def _compute_redirect_uri_list(self):
        for record in self:
            if record.redirect_uris:
                uris = [u.strip() for u in record.redirect_uris.split('\n') if u.strip()]
                record.redirect_uri_list = ', '.join(uris)
            else:
                record.redirect_uri_list = ''

    # ═══════════════════════════════════════════════════════════════════════
    # GRANT TYPES & RESPONSE TYPES
    # ═══════════════════════════════════════════════════════════════════════

    grant_types = fields.Selection([
        ('authorization_code', 'Authorization Code'),
        ('authorization_code,refresh_token', 'Authorization Code + Refresh Token'),
    ], string="Grant Types",
       default='authorization_code,refresh_token',
       required=True
    )
    response_types = fields.Selection([
        ('code', 'Code'),
    ], string="Response Types",
       default='code',
       required=True
    )
    token_endpoint_auth_method = fields.Selection([
        ('none', 'None (Public Client)'),
        ('client_secret_post', 'Client Secret POST'),
        ('client_secret_basic', 'Client Secret Basic'),
    ], string="Token Endpoint Auth Method",
       default='none',
       required=True,
       help="How the client authenticates at the token endpoint"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # SCOPES
    # ═══════════════════════════════════════════════════════════════════════

    allowed_scopes = fields.Char(
        string="Allowed Scopes",
        default='mcp:discovery mcp:source mcp:documentation mcp:read mcp:debug mcp:write mcp:execute',
        help="Space-separated list of scopes this client can request"
    )
    default_scopes = fields.Char(
        string="Default Scopes",
        default='mcp:discovery mcp:read',
        help="Scopes granted if none requested"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # LIFECYCLE
    # ═══════════════════════════════════════════════════════════════════════

    client_secret_expires_at = fields.Datetime(
        string="Client Secret Expires At",
        help="When the client secret expires (0 = never)"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # RELATIONSHIPS
    # ═══════════════════════════════════════════════════════════════════════

    authorization_code_ids = fields.One2many(
        'ik.oauth_authorization_code',
        'client_registration_id',
        string="Authorization Codes"
    )
    refresh_token_ids = fields.One2many(
        'ik.oauth_refresh_token',
        'client_registration_id',
        string="Refresh Tokens"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # METHODS
    # ═══════════════════════════════════════════════════════════════════════

    @api.model
    def _generate_client_id(self):
        """Generate a unique client ID with prefix."""
        return f"ikac_{secrets.token_urlsafe(16)}"

    def generate_client_secret(self):
        """Generate a client secret."""
        self.ensure_one()
        secret = f"ikacs_{secrets.token_urlsafe(32)}"
        self.write({'client_secret': secret})
        return secret

    def validate_redirect_uri(self, redirect_uri):
        """Validate that redirect_uri is in the allowed list.

        Args:
            redirect_uri: URI to validate

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If URI is not allowed
        """
        self.ensure_one()
        allowed = [u.strip() for u in (self.redirect_uris or '').split('\n') if u.strip()]

        if redirect_uri not in allowed:
            raise ValidationError(f"redirect_uri '{redirect_uri}' is not registered for this client")

        return True

    def validate_scope(self, requested_scope):
        """Validate and filter requested scopes.

        Args:
            requested_scope: Space-separated scope string

        Returns:
            str: Validated scope string (filtered to allowed scopes)
        """
        self.ensure_one()
        allowed = set((self.allowed_scopes or '').split())
        requested = set((requested_scope or '').split())

        # Return intersection of requested and allowed
        valid = allowed & requested
        return ' '.join(sorted(valid)) if valid else self.default_scopes

    @api.constrains('redirect_uris')
    def _check_redirect_uris(self):
        """Validate redirect URIs format."""
        for record in self:
            if not record.redirect_uris:
                continue
            for uri in record.redirect_uris.split('\n'):
                uri = uri.strip()
                if not uri:
                    continue
                if not uri.startswith('https://'):
                    raise ValidationError(f"Redirect URI must use HTTPS: {uri}")

    _sql_constraints = [
        ('client_id_unique', 'unique(client_id)', 'Client ID must be unique'),
    ]
```

### 2.4 `ik.oauth_refresh_token`

Stocke les refresh tokens pour le renouvellement des access tokens.

```python
# models/oauth_refresh_token.py
import secrets
from odoo import models, fields, api
from odoo.exceptions import ValidationError


class IkOAuthRefreshToken(models.Model):
    _name = 'ik.oauth_refresh_token'
    _description = "OAuth 2.1 Refresh Token"
    _order = 'create_date desc'

    # ═══════════════════════════════════════════════════════════════════════
    # TOKEN IDENTIFICATION
    # ═══════════════════════════════════════════════════════════════════════

    token = fields.Char(
        string="Refresh Token",
        required=True,
        index=True,
        readonly=True,
        default=lambda self: self._generate_token(),
        help="256-bit random token, base64url encoded with prefix"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # RELATIONSHIPS
    # ═══════════════════════════════════════════════════════════════════════

    client_registration_id = fields.Many2one(
        'ik.oauth_client_registration',
        string="Client",
        required=True,
        ondelete='cascade',
        index=True
    )
    client_id = fields.Char(
        related='client_registration_id.client_id',
        store=True,
        index=True
    )
    user_id = fields.Many2one(
        'res.users',
        string="User",
        required=True,
        ondelete='cascade',
        index=True
    )
    access_token_id = fields.Many2one(
        'ik.api_auth_token',
        string="Current Access Token",
        ondelete='set null',
        help="Most recently issued access token"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # AUTHORIZATION CONTEXT
    # ═══════════════════════════════════════════════════════════════════════

    scope = fields.Char(
        string="Scope",
        help="Space-separated list of granted scopes"
    )
    resource = fields.Char(
        string="Resource",
        help="RFC 8707 resource indicator"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # LIFECYCLE
    # ═══════════════════════════════════════════════════════════════════════

    expires_at = fields.Datetime(
        string="Expires At",
        default=lambda self: fields.Datetime.add(
            fields.Datetime.now(),
            days=int(self.env['ir.config_parameter'].sudo().get_param(
                'inouk_api_auth.oauth_refresh_lifetime_days', '30'
            ))
        ),
        help="Refresh token expiration (default: 30 days)"
    )
    revoked = fields.Boolean(
        string="Revoked",
        default=False
    )
    revoked_at = fields.Datetime(
        string="Revoked At"
    )
    last_used_at = fields.Datetime(
        string="Last Used At"
    )
    use_count = fields.Integer(
        string="Use Count",
        default=0
    )

    # ═══════════════════════════════════════════════════════════════════════
    # METHODS
    # ═══════════════════════════════════════════════════════════════════════

    @api.model
    def _generate_token(self):
        """Generate a cryptographically secure refresh token."""
        return f"ikrt_{secrets.token_urlsafe(32)}"

    def validate(self):
        """Validate refresh token is usable.

        Returns:
            self

        Raises:
            ValidationError: If token is revoked or expired
        """
        self.ensure_one()

        if self.revoked:
            raise ValidationError("Refresh token has been revoked")

        if self.expires_at and fields.Datetime.now() > self.expires_at:
            raise ValidationError("Refresh token has expired")

        return self

    def use(self):
        """Record token usage.

        Returns:
            self
        """
        self.ensure_one()
        self.write({
            'last_used_at': fields.Datetime.now(),
            'use_count': self.use_count + 1,
        })
        return self

    def revoke(self):
        """Revoke this refresh token and its access token."""
        self.ensure_one()
        self.write({
            'revoked': True,
            'revoked_at': fields.Datetime.now(),
        })
        # Also revoke the associated access token
        if self.access_token_id:
            self.access_token_id.write({'is_compromised': True})
        return True

    @api.model
    def _cron_cleanup_expired(self):
        """Cleanup expired and revoked refresh tokens."""
        # Keep revoked tokens for 7 days for audit
        cutoff = fields.Datetime.subtract(fields.Datetime.now(), days=7)
        expired = self.search([
            '|',
            '&', ('expires_at', '<', fields.Datetime.now()), ('expires_at', '!=', False),
            '&', ('revoked', '=', True), ('revoked_at', '<', cutoff),
        ])
        expired.unlink()

    _sql_constraints = [
        ('token_unique', 'unique(token)', 'Refresh token must be unique'),
    ]
```

### 2.5 `ik.oauth_device_code` (NOUVEAU)

Modèle pour le Device Authorization Grant (RFC 8628), utilisé par les CLI `mpy` et `mgx` dans les environnements distants.

**Fichier** : `models/oauth_device_code.py`

```python
# -*- coding: utf-8 -*-

import secrets
import string
from odoo import models, fields, api
from odoo.exceptions import ValidationError


class IkOAuthDeviceCode(models.Model):
    _name = 'ik.oauth_device_code'
    _description = "OAuth 2.1 Device Authorization Code (RFC 8628)"
    _order = 'create_date desc'
    _rec_name = 'user_code'

    # ═══════════════════════════════════════════════════════════════════════
    # CORE FIELDS (RFC 8628)
    # ═══════════════════════════════════════════════════════════════════════

    device_code = fields.Char(
        string="Device Code",
        required=True,
        readonly=True,
        index=True,
        help="Secret code used by the client to poll for authorization. "
             "Never exposed to the user."
    )
    user_code = fields.Char(
        string="User Code",
        required=True,
        readonly=True,
        index=True,
        help="Short code displayed to the user (optional, for manual mode). "
             "Format: XXXX-XXXX for easy typing."
    )
    verification_uri = fields.Char(
        string="Verification URI",
        required=True,
        readonly=True,
        help="URL where user authenticates (without code embedded)"
    )
    verification_uri_complete = fields.Char(
        string="Verification URI Complete",
        required=True,
        readonly=True,
        help="URL with embedded code (Cloudflare style) - user just clicks"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # REQUEST PARAMETERS
    # ═══════════════════════════════════════════════════════════════════════

    client_registration_id = fields.Many2one(
        'ik.oauth_client_registration',
        string="Client Registration",
        required=True,
        readonly=True,
        ondelete='cascade',
        help="Client that requested the device authorization"
    )
    scope = fields.Char(
        string="Requested Scope",
        readonly=True,
        help="Space-separated list of requested scopes"
    )
    resource = fields.Char(
        string="Resource",
        readonly=True,
        help="RFC 8707 resource indicator"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # AUTHORIZATION STATE
    # ═══════════════════════════════════════════════════════════════════════

    state = fields.Selection([
        ('pending', 'Authorization Pending'),
        ('authorized', 'Authorized'),
        ('denied', 'Access Denied'),
        ('expired', 'Expired'),
    ], string="State", default='pending', required=True, readonly=True,
       help="Current state of the device authorization request")

    user_id = fields.Many2one(
        'res.users',
        string="Authorized User",
        readonly=True,
        ondelete='cascade',
        help="User who authorized the request (set when state=authorized)"
    )
    granted_scope = fields.Char(
        string="Granted Scope",
        readonly=True,
        help="Scopes actually granted by the user (may differ from requested)"
    )

    # Lien vers le code d'autorisation généré après consentement
    authorization_code_id = fields.Many2one(
        'ik.oauth_authorization_code',
        string="Authorization Code",
        readonly=True,
        ondelete='set null',
        help="Authorization code generated after user consent (for token exchange)"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # TIMING & POLLING
    # ═══════════════════════════════════════════════════════════════════════

    expires_at = fields.Datetime(
        string="Expires At",
        required=True,
        readonly=True,
        help="When this device code expires (default: 15 minutes)"
    )
    poll_interval = fields.Integer(
        string="Polling Interval (seconds)",
        default=5,
        readonly=True,
        help="Minimum interval between polling requests (RFC 8628)"
    )
    last_poll_at = fields.Datetime(
        string="Last Poll At",
        readonly=True,
        help="Timestamp of last polling request (for slow_down detection)"
    )

    # ═══════════════════════════════════════════════════════════════════════
    # METHODS
    # ═══════════════════════════════════════════════════════════════════════

    @api.model
    def _generate_device_code(self):
        """Generate a cryptographically secure device code (256 bits)."""
        return secrets.token_urlsafe(32)

    @api.model
    def _generate_user_code(self):
        """Generate a user-friendly code: XXXX-XXXX (uppercase letters, no ambiguous chars)."""
        # Exclude ambiguous characters: 0, O, I, L, 1
        alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
        part1 = ''.join(secrets.choice(alphabet) for _ in range(4))
        part2 = ''.join(secrets.choice(alphabet) for _ in range(4))
        return f"{part1}-{part2}"

    @api.model
    def create_device_authorization(self, client_registration_obj, scope=None, resource=None):
        """
        Create a new device authorization request.

        Args:
            client_registration_obj: ik.oauth_client_registration record
            scope: Space-separated scope string
            resource: RFC 8707 resource indicator

        Returns:
            dict: Device authorization response per RFC 8628
        """
        # Configuration
        ICP = self.env['ir.config_parameter'].sudo()
        lifetime = int(ICP.get_param('inouk_api_auth.oauth_device_code_lifetime', '900'))
        poll_interval = int(ICP.get_param('inouk_api_auth.oauth_device_poll_interval', '5'))
        base_url = ICP.get_param('web.base.url', '').rstrip('/')

        device_code = self._generate_device_code()
        user_code = self._generate_user_code()
        expires_at = fields.Datetime.add(fields.Datetime.now(), seconds=lifetime)

        # Build verification URIs
        verification_uri = f"{base_url}/oauth/device"
        verification_uri_complete = f"{base_url}/oauth/device?code={device_code}"

        # Create the device authorization record
        device_auth = self.create({
            'device_code': device_code,
            'user_code': user_code,
            'verification_uri': verification_uri,
            'verification_uri_complete': verification_uri_complete,
            'client_registration_id': client_registration_obj.id,
            'scope': scope,
            'resource': resource,
            'expires_at': expires_at,
            'poll_interval': poll_interval,
        })

        # Return RFC 8628 response
        return {
            'device_code': device_code,
            'user_code': user_code,
            'verification_uri': verification_uri,
            'verification_uri_complete': verification_uri_complete,
            'expires_in': lifetime,
            'interval': poll_interval,
        }

    def check_authorization_status(self):
        """
        Check the current status of a device authorization.
        Called during polling from /oauth/token.

        Returns:
            dict: Token response or error per RFC 8628
        """
        self.ensure_one()
        now = fields.Datetime.now()

        # Check expiration
        if self.expires_at < now:
            self.write({'state': 'expired'})
            return {'error': 'expired_token'}

        # Check rate limiting (slow_down)
        if self.last_poll_at:
            elapsed = (now - self.last_poll_at).total_seconds()
            if elapsed < self.poll_interval:
                return {'error': 'slow_down'}

        # Update last poll timestamp
        self.write({'last_poll_at': now})

        # Check state
        if self.state == 'pending':
            return {'error': 'authorization_pending'}

        if self.state == 'denied':
            return {'error': 'access_denied'}

        if self.state == 'expired':
            return {'error': 'expired_token'}

        if self.state == 'authorized':
            # Return the authorization code for token exchange
            if self.authorization_code_id:
                return {
                    'status': 'authorized',
                    'authorization_code': self.authorization_code_id.code,
                }
            else:
                # Should not happen, but handle gracefully
                return {'error': 'server_error'}

        return {'error': 'server_error'}

    def authorize(self, user_obj, granted_scope=None):
        """
        Authorize the device request.
        Called when user clicks "Authorize" on the consent screen.

        Args:
            user_obj: res.users record of the authorizing user
            granted_scope: Scopes granted (defaults to requested scope)
        """
        self.ensure_one()
        if self.state != 'pending':
            raise ValidationError("Device authorization is not pending")

        if self.expires_at < fields.Datetime.now():
            self.write({'state': 'expired'})
            raise ValidationError("Device authorization has expired")

        # Create an authorization code (reuse existing model)
        auth_code_obj = self.env['ik.oauth_authorization_code'].create({
            'client_registration_id': self.client_registration_id.id,
            'redirect_uri': '',  # No redirect for device flow
            'user_id': user_obj.id,
            'scope': granted_scope or self.scope,
            'resource': self.resource,
            'code_challenge': '',  # No PKCE for device flow (device_code is the secret)
            'code_challenge_method': '',
        })

        self.write({
            'state': 'authorized',
            'user_id': user_obj.id,
            'granted_scope': granted_scope or self.scope,
            'authorization_code_id': auth_code_obj.id,
        })

    def deny(self):
        """Deny the device request."""
        self.ensure_one()
        if self.state != 'pending':
            raise ValidationError("Device authorization is not pending")
        self.write({'state': 'denied'})

    @api.model
    def cleanup_expired(self):
        """Cron job to clean up expired device authorizations."""
        cutoff = fields.Datetime.subtract(fields.Datetime.now(), hours=1)
        expired = self.search([
            '|',
            ('expires_at', '<', cutoff),
            ('state', 'in', ['expired', 'denied']),
        ])
        expired.unlink()

    _sql_constraints = [
        ('device_code_unique', 'unique(device_code)', 'Device code must be unique'),
        ('user_code_unique', 'unique(user_code)', 'User code must be unique'),
    ]
```

**Diagramme d'états** :

```
                    ┌──────────────────────────────────────────────────┐
                    │                                                  │
                    v                                                  │
┌─────────────┐  expires   ┌───────────┐                              │
│   pending   │ ─────────> │  expired  │                              │
│             │            └───────────┘                              │
└─────────────┘                                                       │
       │                                                              │
       │ user clicks URL                                              │
       │ and authenticates                                            │
       v                                                              │
┌─────────────────────────┐                                           │
│   Consent Screen        │                                           │
│   (Odoo session req.)   │                                           │
└─────────────────────────┘                                           │
       │              │                                               │
       │ Authorize    │ Deny                                          │
       v              v                                               │
┌───────────┐   ┌───────────┐                                         │
│ authorized│   │  denied   │                                         │
└───────────┘   └───────────┘                                         │
       │                                                              │
       │ CLI polls /oauth/token                                       │
       │ with device_code                                             │
       v                                                              │
┌───────────────────────┐                                             │
│  Token Exchange       │                                             │
│  (access + refresh)   │ ────────────────────────────────────────────┘
└───────────────────────┘        (device code invalidated)
```

### 2.6 Modification de `ik.api_auth_token`

Ajouter des champs pour lier les access tokens aux refresh tokens et clients OAuth 2.1.

```python
# Dans api_auth_token__oauth_client.py ou nouveau fichier api_auth_token__oauth21.py

class IkApiAuthTokenOAuth21(models.Model):
    _inherit = 'ik.api_auth_token'

    # ═══════════════════════════════════════════════════════════════════════
    # OAUTH 2.1 AUTHORIZATION CODE FLOW
    # ═══════════════════════════════════════════════════════════════════════

    oauth21_client_registration_id = fields.Many2one(
        'ik.oauth_client_registration',
        string="OAuth 2.1 Client",
        ondelete='set null',
        help="Client registration that issued this token (authorization_code flow)"
    )
    oauth21_refresh_token_id = fields.Many2one(
        'ik.oauth_refresh_token',
        string="Refresh Token",
        ondelete='set null',
        help="Associated refresh token"
    )
    oauth21_scope = fields.Char(
        string="OAuth 2.1 Scope",
        help="Granted scopes for this token"
    )
    oauth21_resource = fields.Char(
        string="OAuth 2.1 Resource",
        help="RFC 8707 resource indicator"
    )

    # Computed field to distinguish OAuth 2.1 tokens
    is_oauth21_token = fields.Boolean(
        string="Is OAuth 2.1 Token",
        compute='_compute_is_oauth21_token',
        store=True
    )

    @api.depends('oauth21_client_registration_id')
    def _compute_is_oauth21_token(self):
        for record in self:
            record.is_oauth21_token = bool(record.oauth21_client_registration_id)
```

---

## 3. Endpoints

### 3.1 Structure des fichiers

```
inouk_api_auth/
├── controllers/
│   ├── __init__.py                  # Ajouter import
│   └── oauth.py                     # MODIFIER (ajouter endpoints)

inouk_mcp/
├── controllers/
│   ├── __init__.py                  # Ajouter import
│   └── oauth_mcp.py                 # NOUVEAU (protected-resource)
```
### 3.2 `GET /.well-known/oauth-protected-resource` (RFC 9728 §3.2)

**Module** : `inouk_mcp`
**Fichier** : `controllers/oauth_mcp.py`

Cet endpoint indique à Claude.ai où trouver le serveur d'autorisation OAuth.

**Support multi-resources** : Conformément à RFC 9728 §3.2, le paramètre `resource` permet de cibler une resource spécifique. Sans paramètre, retourne les metadata MCP par défaut (pour Claude.ai).

**Exemples d'appels** :
```
GET /.well-known/oauth-protected-resource                     → metadata MCP (défaut)
GET /.well-known/oauth-protected-resource?resource=https://domain/mcp  → metadata MCP explicite
GET /.well-known/oauth-protected-resource?resource=https://domain/api  → (futur) autre resource
```

```python
# inouk_mcp/controllers/oauth_mcp.py
from odoo import http
from odoo.http import request, Response
import json


class MCPOAuthController(http.Controller):

    # Registry of protected resources (extensible)
    # Each resource has its own metadata configuration
    PROTECTED_RESOURCES = {
        '/mcp': {
            'scopes_supported': [
                'mcp:discovery',
                'mcp:source',
                'mcp:documentation',
                'mcp:read',
                'mcp:debug',
                'mcp:write',
                'mcp:execute',
            ],
            'resource_documentation': '/mcp',
        },
        # Future resources can be added here:
        # '/api/v2': {
        #     'scopes_supported': ['api:read', 'api:write'],
        #     'resource_documentation': '/api/v2/docs',
        # },
    }
    DEFAULT_RESOURCE_PATH = '/mcp'

    @http.route(
        '/.well-known/oauth-protected-resource',
        type='http',
        auth='public',
        methods=['GET'],
        csrf=False
    )
    def oauth_protected_resource(self, resource=None, **kwargs):
        """RFC 9728 §3.2 - Protected Resource Metadata with resource parameter.

        Args:
            resource: Optional resource identifier URL. If not provided,
                     returns metadata for the default resource (MCP).

        Returns:
            JSON metadata about the protected resource and its authorization server.
        """
        base_url = request.env['ir.config_parameter'].sudo().get_param('web.base.url').rstrip('/')

        # Determine which resource to describe
        resource_path = self.DEFAULT_RESOURCE_PATH

        if resource:
            # Extract path from resource URL
            # e.g., "https://domain/mcp" -> "/mcp"
            if resource.startswith(base_url):
                resource_path = resource[len(base_url):] or '/'
            else:
                # Resource URL doesn't match this server
                return Response(
                    json.dumps({
                        "error": "invalid_resource",
                        "error_description": f"Resource {resource} is not hosted on this server"
                    }),
                    status=400,
                    content_type='application/json'
                )

        # Find resource configuration
        resource_config = self.PROTECTED_RESOURCES.get(resource_path)
        if not resource_config:
            return Response(
                json.dumps({
                    "error": "unknown_resource",
                    "error_description": f"Unknown protected resource: {resource_path}"
                }),
                status=404,
                content_type='application/json'
            )

        # Build metadata response
        resource_url = f"{base_url}{resource_path}"
        metadata = {
            "resource": resource_url,
            "authorization_servers": [base_url],
            "bearer_methods_supported": ["header"],
            "scopes_supported": resource_config.get('scopes_supported', []),
            "resource_documentation": f"{base_url}{resource_config.get('resource_documentation', resource_path)}",
        }

        return Response(
            json.dumps(metadata),
            content_type='application/json',
            headers={
                'Cache-Control': 'public, max-age=3600',
                'Access-Control-Allow-Origin': '*',
            }
        )
```

**Réponse type (MCP)** :
```json
{
  "resource": "https://muppy.cloud/mcp",
  "authorization_servers": ["https://muppy.cloud"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": [
    "mcp:discovery",
    "mcp:source",
    "mcp:documentation",
    "mcp:read",
    "mcp:debug",
    "mcp:write",
    "mcp:execute"
  ],
  "resource_documentation": "https://muppy.cloud/mcp"
}
```

**Extensibilité** : Pour ajouter une nouvelle protected resource (ex: `/api/v2`), il suffit d'ajouter une entrée dans `PROTECTED_RESOURCES`.

### 3.3 `GET /.well-known/oauth-authorization-server` (RFC 8414)

**Module** : `inouk_api_auth`
**Fichier** : `controllers/oauth.py` (modifier l'existant)

```python
# Modifier oauth.py pour étendre la réponse existante

@http.route(
    '/.well-known/oauth-authorization-server',
    type='http',
    auth='public',
    methods=['GET'],
    csrf=False
)
def oauth_authorization_server_metadata(self):
    """RFC 8414 - Authorization Server Metadata.

    Extended for OAuth 2.1 Authorization Code + PKCE.
    """
    base_url = request.env['ir.config_parameter'].sudo().get_param('web.base.url')

    # Scopes MCP supportés
    scopes_supported = [
        "mcp:discovery",
        "mcp:source",
        "mcp:documentation",
        "mcp:read",
        "mcp:debug",
        "mcp:write",
        "mcp:execute",
    ]

    metadata = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/oauth/register",

        # Supported response types
        "response_types_supported": ["code"],

        # Supported grant types (extended)
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",  # Keep for backward compatibility
            "urn:ietf:params:oauth:grant-type:device_code",  # RFC 8628 Device Code
        ],

        # Device Authorization (RFC 8628) - for CLI tools
        "device_authorization_endpoint": f"{base_url}/oauth/device/code",

        # PKCE (required for authorization_code)
        "code_challenge_methods_supported": ["S256"],

        # Token endpoint auth methods
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_post",
            "client_secret_basic",
        ],

        # Scopes
        "scopes_supported": scopes_supported,

        # Resource indicators (RFC 8707)
        "resource_indicators_supported": True,

        # Refresh tokens
        "refresh_token_supported": True,

        # UI locales
        "ui_locales_supported": ["en", "fr"],
    }

    return Response(
        json.dumps(metadata),
        content_type='application/json',
        headers={
            'Cache-Control': 'public, max-age=3600',
            'Access-Control-Allow-Origin': '*',
        }
    )
```

### 3.4 `POST /oauth/register` (RFC 7591)

**Module** : `inouk_api_auth`
**Fichier** : `controllers/oauth.py`

```python
@http.route(
    '/oauth/register',
    type='http',
    auth='public',
    methods=['POST'],
    csrf=False
)
def oauth_register(self):
    """RFC 7591 - Dynamic Client Registration.

    Allows clients like Claude.ai to register themselves automatically.
    """
    import json

    # Parse request body
    try:
        if request.httprequest.content_type == 'application/json':
            data = json.loads(request.httprequest.get_data(as_text=True))
        else:
            return self._oauth_error('invalid_request', 'Content-Type must be application/json', 400)
    except json.JSONDecodeError:
        return self._oauth_error('invalid_request', 'Invalid JSON', 400)

    # Required fields
    client_name = data.get('client_name')
    redirect_uris = data.get('redirect_uris', [])

    if not client_name:
        return self._oauth_error('invalid_client_metadata', 'client_name is required', 400)

    if not redirect_uris:
        return self._oauth_error('invalid_redirect_uri', 'redirect_uris is required', 400)

    # Validate redirect URIs against allowed patterns
    allowed_patterns = self._get_allowed_redirect_patterns()
    for uri in redirect_uris:
        if not self._validate_redirect_uri_pattern(uri, allowed_patterns):
            return self._oauth_error(
                'invalid_redirect_uri',
                f"redirect_uri '{uri}' is not allowed",
                400
            )

    # Create client registration
    ClientReg = request.env['ik.oauth_client_registration'].sudo()

    client = ClientReg.create({
        'client_name': client_name,
        'redirect_uris': '\n'.join(redirect_uris),
        'registration_type': 'dynamic',
        'client_uri': data.get('client_uri'),
        'logo_uri': data.get('logo_uri'),
        'grant_types': 'authorization_code,refresh_token',
        'response_types': 'code',
        'token_endpoint_auth_method': data.get('token_endpoint_auth_method', 'none'),
        'allowed_scopes': data.get('scope', 'mcp:discovery mcp:read mcp:write'),
    })

    # Generate secret if auth method requires it
    client_secret = None
    if client.token_endpoint_auth_method in ('client_secret_post', 'client_secret_basic'):
        client_secret = client.generate_client_secret()

    # Build response
    response_data = {
        "client_id": client.client_id,
        "client_name": client.client_name,
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "client_id_issued_at": int(client.create_date.timestamp()),
        "client_secret_expires_at": 0,  # Never expires
    }

    if client_secret:
        response_data["client_secret"] = client_secret

    return Response(
        json.dumps(response_data),
        status=201,
        content_type='application/json'
    )

def _get_allowed_redirect_patterns(self):
    """Get allowed redirect URI patterns from config."""
    patterns = request.env['ir.config_parameter'].sudo().get_param(
        'inouk_api_auth.oauth_allowed_redirect_patterns',
        # Default: Claude.ai callbacks + localhost for CLI
        'https://claude.ai/api/mcp/auth_callback\n'
        'https://claude.com/api/mcp/auth_callback\n'
        'http://localhost:*/callback\n'
        'http://127.0.0.1:*/callback'
    )
    return [p.strip() for p in patterns.split('\n') if p.strip()]

def _validate_redirect_uri_pattern(self, uri, patterns):
    """Check if URI matches any allowed pattern.

    Supports:
    - Exact match: https://example.com/callback
    - Wildcard subdomain: https://*.example.com/callback
    - Localhost with any port: http://localhost:*/callback (for CLI)
    - Custom schemes: muppy://callback (for mobile apps)
    """
    import fnmatch
    from urllib.parse import urlparse

    parsed = urlparse(uri)

    # Special handling for localhost (CLI applications)
    # Allow any port on localhost/127.0.0.1
    if parsed.hostname in ('localhost', '127.0.0.1'):
        # Must be http for localhost (not https)
        if parsed.scheme != 'http':
            return False
        # Check path matches a localhost pattern
        for pattern in patterns:
            if 'localhost:*' in pattern or '127.0.0.1:*' in pattern:
                pattern_parsed = urlparse(pattern.replace(':*', ':9999'))
                if parsed.path == pattern_parsed.path:
                    return True
        return False

    # Standard pattern matching for non-localhost URIs
    for pattern in patterns:
        if fnmatch.fnmatch(uri, pattern):
            return True
        # Exact match
        if uri == pattern:
            return True

    return False
```

### 3.5 `GET /oauth/authorize`

**Module** : `inouk_api_auth`
**Fichier** : `controllers/oauth.py`

```python
@http.route(
    '/oauth/authorize',
    type='http',
    auth='user',  # Requires Odoo session
    methods=['GET', 'POST'],
    csrf=False
)
def oauth_authorize(self, **kwargs):
    """OAuth 2.1 Authorization Endpoint.

    GET: Display consent screen
    POST: Process consent decision
    """
    # Extract parameters
    response_type = kwargs.get('response_type')
    client_id = kwargs.get('client_id')
    redirect_uri = kwargs.get('redirect_uri')
    scope = kwargs.get('scope', '')
    state = kwargs.get('state')
    code_challenge = kwargs.get('code_challenge')
    code_challenge_method = kwargs.get('code_challenge_method')
    resource = kwargs.get('resource')

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDATION
    # ═══════════════════════════════════════════════════════════════════════

    # Validate required parameters
    if response_type != 'code':
        return self._oauth_error_redirect(
            redirect_uri, state, 'unsupported_response_type',
            "Only 'code' response_type is supported"
        )

    if not client_id:
        return self._oauth_error('invalid_request', 'client_id is required', 400)

    if not redirect_uri:
        return self._oauth_error('invalid_request', 'redirect_uri is required', 400)

    # PKCE is REQUIRED for authorization_code flow
    if not code_challenge or code_challenge_method != 'S256':
        return self._oauth_error_redirect(
            redirect_uri, state, 'invalid_request',
            "PKCE with S256 is required"
        )

    # Lookup client
    ClientReg = request.env['ik.oauth_client_registration'].sudo()
    client = ClientReg.search([('client_id', '=', client_id), ('active', '=', True)], limit=1)

    if not client:
        return self._oauth_error('invalid_client', 'Client not found', 400)

    # Validate redirect_uri
    try:
        client.validate_redirect_uri(redirect_uri)
    except ValidationError as e:
        return self._oauth_error('invalid_redirect_uri', str(e), 400)

    # Validate and filter scopes
    validated_scope = client.validate_scope(scope)

    # ═══════════════════════════════════════════════════════════════════════
    # CONSENT HANDLING
    # ═══════════════════════════════════════════════════════════════════════

    if request.httprequest.method == 'POST':
        # User submitted consent form
        decision = kwargs.get('decision')

        if decision == 'deny':
            return self._oauth_error_redirect(
                redirect_uri, state, 'access_denied',
                "User denied the authorization request"
            )

        # Create authorization code
        AuthCode = request.env['ik.oauth_authorization_code'].sudo()
        auth_code = AuthCode.create({
            'client_registration_id': client.id,
            'user_id': request.env.user.id,
            'redirect_uri': redirect_uri,
            'scope': validated_scope,
            'state': state,
            'resource': resource,
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method,
        })

        # Redirect with code
        redirect_url = f"{redirect_uri}?code={auth_code.code}"
        if state:
            redirect_url += f"&state={state}"

        return request.redirect(redirect_url)

    # ═══════════════════════════════════════════════════════════════════════
    # DISPLAY CONSENT SCREEN
    # ═══════════════════════════════════════════════════════════════════════

    # Parse scopes for display
    scope_list = validated_scope.split() if validated_scope else []
    scope_descriptions = {
        'mcp:discovery': 'Discover domains, models, fields, and methods',
        'mcp:source': 'Read Python source code',
        'mcp:documentation': 'Access .ai.md documentation',
        'mcp:read': 'Read record data',
        'mcp:debug': 'Analyze Python stacktraces',
        'mcp:write': 'Create, modify, and delete records',
        'mcp:execute': 'Execute whitelisted methods',
    }

    scopes_display = [
        {'name': s, 'description': scope_descriptions.get(s, s)}
        for s in scope_list
    ]

    return request.render('inouk_api_auth.oauth_consent', {
        'client': client,
        'scopes': scopes_display,
        'redirect_uri': redirect_uri,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method,
        'resource': resource,
        'scope': validated_scope,
        'user': request.env.user,
    })
```

### 3.6 `POST /oauth/token` (modifier)

**Module** : `inouk_api_auth`
**Fichier** : `controllers/oauth.py`

Ajouter les grant types `authorization_code` et `refresh_token`.

```python
@http.route(
    '/oauth/token',
    type='http',
    auth='public',
    methods=['POST'],
    csrf=False
)
def oauth_token(self):
    """OAuth 2.1 Token Endpoint.

    Supports:
    - grant_type=authorization_code (with PKCE)
    - grant_type=refresh_token
    - grant_type=client_credentials (existing)
    """
    import json

    # Parse request (support both form-urlencoded and JSON)
    content_type = request.httprequest.content_type or ''
    if 'application/json' in content_type:
        try:
            data = json.loads(request.httprequest.get_data(as_text=True))
        except json.JSONDecodeError:
            return self._oauth_error('invalid_request', 'Invalid JSON', 400)
    else:
        data = dict(request.httprequest.form)

    grant_type = data.get('grant_type')

    if grant_type == 'authorization_code':
        return self._token_authorization_code(data)
    elif grant_type == 'refresh_token':
        return self._token_refresh(data)
    elif grant_type == 'client_credentials':
        return self._token_client_credentials(data)  # Existing implementation
    else:
        return self._oauth_error('unsupported_grant_type', f"Grant type '{grant_type}' not supported", 400)


def _token_authorization_code(self, data):
    """Handle authorization_code grant type."""
    code = data.get('code')
    redirect_uri = data.get('redirect_uri')
    client_id = data.get('client_id')
    code_verifier = data.get('code_verifier')
    resource = data.get('resource')

    # Validate required parameters
    if not all([code, redirect_uri, client_id, code_verifier]):
        return self._oauth_error(
            'invalid_request',
            'code, redirect_uri, client_id, and code_verifier are required',
            400
        )

    # Lookup authorization code
    AuthCode = request.env['ik.oauth_authorization_code'].sudo()
    auth_code = AuthCode.search([
        ('code', '=', code),
        ('client_id', '=', client_id),
    ], limit=1)

    if not auth_code:
        return self._oauth_error('invalid_grant', 'Authorization code not found', 400)

    # Validate PKCE
    try:
        auth_code.validate_pkce(code_verifier)
    except ValidationError as e:
        return self._oauth_error('invalid_grant', str(e), 400)

    # Validate redirect_uri matches
    if auth_code.redirect_uri != redirect_uri:
        return self._oauth_error('invalid_grant', 'redirect_uri mismatch', 400)

    # Consume the code (marks as used, checks expiration)
    try:
        auth_code.consume()
    except ValidationError as e:
        return self._oauth_error('invalid_grant', str(e), 400)

    # Generate access token
    Token = request.env['ik.api_auth_token'].sudo()
    token_lifetime = int(request.env['ir.config_parameter'].sudo().get_param(
        'inouk_api_auth.oauth_token_lifetime', '3600'
    ))

    access_token = Token.create({
        'name': f"OAuth2.1 token for {auth_code.client_registration_id.client_name}",
        'user_id': auth_code.user_id.id,
        'token_type': 'header',
        'service_preset': 'standard_bearer',
        'expiration_ts': fields.Datetime.add(fields.Datetime.now(), seconds=token_lifetime),
        'oauth21_client_registration_id': auth_code.client_registration_id.id,
        'oauth21_scope': auth_code.scope,
        'oauth21_resource': resource or auth_code.resource,
    })
    access_token.generate_credentials_header()

    # Create refresh token
    RefreshToken = request.env['ik.oauth_refresh_token'].sudo()
    refresh_token = RefreshToken.create({
        'client_registration_id': auth_code.client_registration_id.id,
        'user_id': auth_code.user_id.id,
        'access_token_id': access_token.id,
        'scope': auth_code.scope,
        'resource': resource or auth_code.resource,
    })

    # Link refresh token to access token
    access_token.write({'oauth21_refresh_token_id': refresh_token.id})

    return self._token_response(
        access_token=access_token.static_token,
        token_type='Bearer',
        expires_in=token_lifetime,
        refresh_token=refresh_token.token,
        scope=auth_code.scope,
    )


def _token_refresh(self, data):
    """Handle refresh_token grant type."""
    refresh_token_value = data.get('refresh_token')
    client_id = data.get('client_id')
    scope = data.get('scope')  # Optional: request subset of original scopes

    if not refresh_token_value:
        return self._oauth_error('invalid_request', 'refresh_token is required', 400)

    # Lookup refresh token
    RefreshToken = request.env['ik.oauth_refresh_token'].sudo()
    refresh_token = RefreshToken.search([
        ('token', '=', refresh_token_value),
    ], limit=1)

    if not refresh_token:
        return self._oauth_error('invalid_grant', 'Refresh token not found', 400)

    # Validate client_id if provided
    if client_id and refresh_token.client_id != client_id:
        return self._oauth_error('invalid_grant', 'client_id mismatch', 400)

    # Validate refresh token
    try:
        refresh_token.validate()
    except ValidationError as e:
        return self._oauth_error('invalid_grant', str(e), 400)

    # Validate scope (can only be equal or subset of original)
    if scope:
        requested = set(scope.split())
        original = set(refresh_token.scope.split())
        if not requested.issubset(original):
            return self._oauth_error('invalid_scope', 'Requested scope exceeds original grant', 400)
        final_scope = scope
    else:
        final_scope = refresh_token.scope

    # Revoke old access token
    if refresh_token.access_token_id:
        refresh_token.access_token_id.write({'is_compromised': True})

    # Generate new access token
    Token = request.env['ik.api_auth_token'].sudo()
    token_lifetime = int(request.env['ir.config_parameter'].sudo().get_param(
        'inouk_api_auth.oauth_token_lifetime', '3600'
    ))

    access_token = Token.create({
        'name': f"OAuth2.1 token for {refresh_token.client_registration_id.client_name}",
        'user_id': refresh_token.user_id.id,
        'token_type': 'header',
        'service_preset': 'standard_bearer',
        'expiration_ts': fields.Datetime.add(fields.Datetime.now(), seconds=token_lifetime),
        'oauth21_client_registration_id': refresh_token.client_registration_id.id,
        'oauth21_refresh_token_id': refresh_token.id,
        'oauth21_scope': final_scope,
        'oauth21_resource': refresh_token.resource,
    })
    access_token.generate_credentials_header()

    # Update refresh token
    refresh_token.write({
        'access_token_id': access_token.id,
    })
    refresh_token.use()

    # Optionally rotate refresh token (security best practice)
    rotate_refresh = request.env['ir.config_parameter'].sudo().get_param(
        'inouk_api_auth.oauth_rotate_refresh_tokens', 'true'
    ).lower() == 'true'

    new_refresh_token = None
    if rotate_refresh:
        new_refresh = RefreshToken.create({
            'client_registration_id': refresh_token.client_registration_id.id,
            'user_id': refresh_token.user_id.id,
            'access_token_id': access_token.id,
            'scope': final_scope,
            'resource': refresh_token.resource,
        })
        refresh_token.revoke()
        access_token.write({'oauth21_refresh_token_id': new_refresh.id})
        new_refresh_token = new_refresh.token
    else:
        new_refresh_token = refresh_token.token

    return self._token_response(
        access_token=access_token.static_token,
        token_type='Bearer',
        expires_in=token_lifetime,
        refresh_token=new_refresh_token,
        scope=final_scope,
    )


def _token_response(self, access_token, token_type, expires_in, refresh_token=None, scope=None):
    """Build standard token response."""
    import json

    response = {
        "access_token": access_token,
        "token_type": token_type,
        "expires_in": expires_in,
    }

    if refresh_token:
        response["refresh_token"] = refresh_token

    if scope:
        response["scope"] = scope

    return Response(
        json.dumps(response),
        content_type='application/json',
        headers={
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }
    )


def _oauth_error(self, error, description, status=400):
    """Return OAuth error response."""
    import json

    return Response(
        json.dumps({
            "error": error,
            "error_description": description,
        }),
        status=status,
        content_type='application/json'
    )


def _oauth_error_redirect(self, redirect_uri, state, error, description):
    """Redirect with OAuth error parameters."""
    from urllib.parse import urlencode

    if not redirect_uri:
        return self._oauth_error(error, description, 400)

    params = {'error': error, 'error_description': description}
    if state:
        params['state'] = state

    redirect_url = f"{redirect_uri}?{urlencode(params)}"
    return request.redirect(redirect_url)


def _token_device_code(self, data):
    """
    Handle device_code grant type (RFC 8628).
    Called by CLI polling for authorization status.
    """
    device_code = data.get('device_code')
    client_id = data.get('client_id')

    if not device_code:
        return self._oauth_error('invalid_request', 'device_code is required', 400)
    if not client_id:
        return self._oauth_error('invalid_request', 'client_id is required', 400)

    # Lookup device authorization
    DeviceCode = request.env['ik.oauth_device_code'].sudo()
    device_auth = DeviceCode.search([
        ('device_code', '=', device_code),
    ], limit=1)

    if not device_auth:
        return self._oauth_error('invalid_grant', 'Device code not found', 400)

    # Validate client
    if device_auth.client_registration_id.client_id != client_id:
        return self._oauth_error('invalid_grant', 'client_id mismatch', 400)

    # Check authorization status
    status = device_auth.check_authorization_status()

    if 'error' in status:
        return self._oauth_error(status['error'], status.get('error_description', ''), 400)

    if status.get('status') == 'authorized':
        # Exchange the internal authorization code for tokens
        auth_code = device_auth.authorization_code_id

        # Generate access token
        Token = request.env['ik.api_auth_token'].sudo()
        token_lifetime = int(request.env['ir.config_parameter'].sudo().get_param(
            'inouk_api_auth.oauth_token_lifetime', '3600'
        ))

        access_token = Token.create({
            'name': f"OAuth2.1 token for {auth_code.client_registration_id.client_name}",
            'user_id': auth_code.user_id.id,
            'token_type': 'header',
            'service_preset': 'standard_bearer',
            'expiration_ts': fields.Datetime.add(fields.Datetime.now(), seconds=token_lifetime),
            'oauth21_client_registration_id': auth_code.client_registration_id.id,
            'oauth21_scope': auth_code.scope,
            'oauth21_resource': auth_code.resource,
        })
        access_token.generate_credentials_header()

        # Create refresh token
        RefreshToken = request.env['ik.oauth_refresh_token'].sudo()
        refresh_token = RefreshToken.create({
            'client_registration_id': auth_code.client_registration_id.id,
            'user_id': auth_code.user_id.id,
            'access_token_id': access_token.id,
            'scope': auth_code.scope,
            'resource': auth_code.resource,
        })

        access_token.write({'oauth21_refresh_token_id': refresh_token.id})

        # Mark device code as consumed (delete it)
        device_auth.unlink()

        return self._token_response(
            access_token=access_token.static_token,
            token_type='Bearer',
            expires_in=token_lifetime,
            refresh_token=refresh_token.token,
            scope=auth_code.scope,
        )

    return self._oauth_error('server_error', 'Unexpected state', 500)
```

### 3.7 `POST /oauth/device/code` et `GET /oauth/device` (RFC 8628 - NOUVEAU)

**Endpoint initial** : `POST /oauth/device/code` - Demande un device code pour le flow CLI.

**Endpoint utilisateur** : `GET /oauth/device` - Page de vérification où l'utilisateur autorise la demande.

```python
# Dans controllers/oauth.py

@http.route('/oauth/device/code', type='http', auth='public', methods=['POST'], csrf=False)
def oauth_device_code(self, **kwargs):
    """
    RFC 8628 Device Authorization Request.
    Called by CLI to initiate device flow.

    POST /oauth/device/code
    Content-Type: application/x-www-form-urlencoded

    client_id=mpy-cli&scope=mcp:read mcp:write

    Response:
    {
        "device_code": "...",
        "user_code": "ABCD-EFGH",
        "verification_uri": "https://muppy.cloud/oauth/device",
        "verification_uri_complete": "https://muppy.cloud/oauth/device?code=...",
        "expires_in": 900,
        "interval": 5
    }
    """
    import json

    client_id = kwargs.get('client_id')
    scope = kwargs.get('scope', '')
    resource = kwargs.get('resource')

    if not client_id:
        return self._oauth_error('invalid_request', 'client_id is required', 400)

    # Lookup client registration
    ClientReg = request.env['ik.oauth_client_registration'].sudo()
    client = ClientReg.search([
        ('client_id', '=', client_id),
        ('state', '=', 'active'),
    ], limit=1)

    if not client:
        return self._oauth_error('invalid_client', 'Client not found or inactive', 401)

    # Validate device flow is allowed for this client
    if 'urn:ietf:params:oauth:grant-type:device_code' not in (client.grant_types or ''):
        return self._oauth_error('unauthorized_client',
                                 'Client not authorized for device code flow', 400)

    # Create device authorization
    DeviceCode = request.env['ik.oauth_device_code'].sudo()
    response = DeviceCode.create_device_authorization(client, scope=scope, resource=resource)

    return Response(
        json.dumps(response),
        content_type='application/json',
        headers={
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }
    )


@http.route('/oauth/device', type='http', auth='public', methods=['GET'], csrf=False)
def oauth_device_verify(self, **kwargs):
    """
    RFC 8628 Device Verification Endpoint.
    User visits this URL to authorize the CLI.

    Two modes:
    1. With ?code=xxx (Cloudflare style) - direct authorization
    2. Without code - user enters user_code manually

    Requires Odoo session - redirects to login if not authenticated.
    """
    device_code = kwargs.get('code')
    user_code = kwargs.get('user_code')

    # Require authentication
    if not request.session.uid:
        # Redirect to login, preserving the return URL
        return request.redirect(f'/web/login?redirect={request.httprequest.url}')

    user = request.env['res.users'].sudo().browse(request.session.uid)

    DeviceCode = request.env['ik.oauth_device_code'].sudo()

    # Find the device authorization
    if device_code:
        device_auth = DeviceCode.search([
            ('device_code', '=', device_code),
            ('state', '=', 'pending'),
        ], limit=1)
    elif user_code:
        device_auth = DeviceCode.search([
            ('user_code', '=', user_code.upper().replace(' ', '').replace('-', '')),
            ('state', '=', 'pending'),
        ], limit=1)
    else:
        # Show form to enter user_code manually (OOB mode)
        return request.render('inouk_api_auth.oauth_device_enter_code', {})

    if not device_auth:
        return request.render('inouk_api_auth.oauth_device_error', {
            'error': 'Device authorization not found or already processed.',
        })

    if device_auth.expires_at < fields.Datetime.now():
        device_auth.write({'state': 'expired'})
        return request.render('inouk_api_auth.oauth_device_error', {
            'error': 'Device authorization has expired. Please try again from the CLI.',
        })

    # Parse scopes for display
    scopes = []
    if device_auth.scope:
        scope_descriptions = {
            'mcp:discovery': ('Discovery', 'Discover domains, models, fields, and methods'),
            'mcp:source': ('Source Code', 'Read Python source code'),
            'mcp:documentation': ('Documentation', 'Access .ai.md files'),
            'mcp:read': ('Read', 'Read record data'),
            'mcp:debug': ('Debug', 'Analyze Python stacktraces'),
            'mcp:write': ('Write', 'Create, modify, and delete records'),
            'mcp:execute': ('Execute', 'Execute whitelisted methods'),
        }
        for scope in device_auth.scope.split():
            if scope in scope_descriptions:
                name, desc = scope_descriptions[scope]
                scopes.append({'scope': scope, 'name': name, 'description': desc})
            else:
                scopes.append({'scope': scope, 'name': scope, 'description': ''})

    # Render consent screen for device flow
    return request.render('inouk_api_auth.oauth_device_consent', {
        'device_auth': device_auth,
        'client': device_auth.client_registration_id,
        'user': user,
        'scopes': scopes,
    })


@http.route('/oauth/device/authorize', type='http', auth='user', methods=['POST'], csrf=True)
def oauth_device_authorize(self, **kwargs):
    """
    Handle device authorization consent.
    Called when user clicks Authorize or Deny.
    """
    device_code = kwargs.get('device_code')
    action = kwargs.get('action')

    if not device_code or action not in ('authorize', 'deny'):
        return request.render('inouk_api_auth.oauth_device_error', {
            'error': 'Invalid request.',
        })

    DeviceCode = request.env['ik.oauth_device_code'].sudo()
    device_auth = DeviceCode.search([
        ('device_code', '=', device_code),
        ('state', '=', 'pending'),
    ], limit=1)

    if not device_auth:
        return request.render('inouk_api_auth.oauth_device_error', {
            'error': 'Device authorization not found or already processed.',
        })

    user = request.env.user

    if action == 'authorize':
        try:
            device_auth.authorize(user)
            return request.render('inouk_api_auth.oauth_device_success', {
                'client': device_auth.client_registration_id,
            })
        except Exception as e:
            return request.render('inouk_api_auth.oauth_device_error', {
                'error': str(e),
            })
    else:
        device_auth.deny()
        return request.render('inouk_api_auth.oauth_device_denied', {
            'client': device_auth.client_registration_id,
        })
```

**Réponses CLI** :

| État | Réponse `/oauth/token` | Action CLI |
|------|------------------------|------------|
| `authorization_pending` | `{"error": "authorization_pending"}` | Continue polling |
| `slow_down` | `{"error": "slow_down"}` | Augmenter intervalle +5s |
| `expired_token` | `{"error": "expired_token"}` | Arrêter, message erreur |
| `access_denied` | `{"error": "access_denied"}` | Arrêter, message erreur |
| `authorized` | Token response (comme authorization_code) | Sauvegarder tokens, terminer |

---

## 4. Écran de consentement

### 4.1 Template QWeb

**Fichier** : `inouk_api_auth/views/oauth_consent_templates.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>

    <template id="oauth_consent" name="OAuth Consent Screen">
        <t t-call="web.login_layout">
            <div class="oe_login_form oauth-consent-form">
                <h2 class="text-center mb-4">Authorization Request</h2>

                <div class="alert alert-info mb-4">
                    <strong><t t-esc="client.client_name"/></strong> is requesting access to your account.
                </div>

                <!-- Client info -->
                <div class="card mb-4">
                    <div class="card-body">
                        <div class="d-flex align-items-center mb-3">
                            <t t-if="client.logo_uri">
                                <img t-att-src="client.logo_uri" class="rounded me-3" style="max-width: 48px; max-height: 48px;"/>
                            </t>
                            <t t-else="">
                                <div class="bg-secondary rounded me-3 d-flex align-items-center justify-content-center"
                                     style="width: 48px; height: 48px;">
                                    <i class="fa fa-plug text-white fa-lg"/>
                                </div>
                            </t>
                            <div>
                                <h5 class="mb-0"><t t-esc="client.client_name"/></h5>
                                <small class="text-muted" t-if="client.client_uri">
                                    <t t-esc="client.client_uri"/>
                                </small>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Requested permissions -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h6 class="mb-0">
                            <i class="fa fa-lock me-2"/>
                            Requested Permissions
                        </h6>
                    </div>
                    <ul class="list-group list-group-flush">
                        <t t-foreach="scopes" t-as="scope">
                            <li class="list-group-item">
                                <div class="d-flex align-items-center">
                                    <i class="fa fa-check-circle text-success me-2"/>
                                    <div>
                                        <strong><t t-esc="scope['name']"/></strong>
                                        <br/>
                                        <small class="text-muted"><t t-esc="scope['description']"/></small>
                                    </div>
                                </div>
                            </li>
                        </t>
                    </ul>
                </div>

                <!-- User info -->
                <div class="alert alert-secondary mb-4">
                    <small>
                        <i class="fa fa-user me-2"/>
                        Logged in as: <strong><t t-esc="user.name"/></strong>
                        (<t t-esc="user.email"/>)
                    </small>
                </div>

                <!-- Decision form -->
                <form method="POST" action="/oauth/authorize">
                    <!-- Hidden fields to preserve authorization parameters -->
                    <input type="hidden" name="response_type" value="code"/>
                    <input type="hidden" name="client_id" t-att-value="client.client_id"/>
                    <input type="hidden" name="redirect_uri" t-att-value="redirect_uri"/>
                    <input type="hidden" name="scope" t-att-value="scope"/>
                    <input type="hidden" name="state" t-att-value="state"/>
                    <input type="hidden" name="code_challenge" t-att-value="code_challenge"/>
                    <input type="hidden" name="code_challenge_method" t-att-value="code_challenge_method"/>
                    <input type="hidden" name="resource" t-att-value="resource"/>

                    <div class="d-grid gap-2">
                        <button type="submit" name="decision" value="allow"
                                class="btn btn-primary btn-lg">
                            <i class="fa fa-check me-2"/>
                            Authorize
                        </button>
                        <button type="submit" name="decision" value="deny"
                                class="btn btn-outline-secondary">
                            <i class="fa fa-times me-2"/>
                            Deny
                        </button>
                    </div>
                </form>

                <!-- Security notice -->
                <div class="text-center mt-4">
                    <small class="text-muted">
                        <i class="fa fa-shield-alt me-1"/>
                        You can revoke this access at any time in your account settings.
                    </small>
                </div>
            </div>
        </t>
    </template>

    <!-- Styles -->
    <template id="oauth_consent_assets" inherit_id="web.assets_frontend" primary="True">
        <xpath expr="." position="inside">
            <style>
                .oauth-consent-form {
                    max-width: 450px;
                    margin: 0 auto;
                    padding: 2rem;
                }
                .oauth-consent-form .card {
                    border-radius: 0.5rem;
                    box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
                }
                .oauth-consent-form .btn-primary {
                    background-color: #7C3AED;
                    border-color: #7C3AED;
                }
                .oauth-consent-form .btn-primary:hover {
                    background-color: #6D28D9;
                    border-color: #6D28D9;
                }
            </style>
        </xpath>
    </template>

</odoo>
```

### 4.2 Templates Device Flow (NOUVEAU)

**Fichier** : `inouk_api_auth/views/oauth_device_templates.xml`

Templates spécifiques pour le flow Device Code (CLI).

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>

    <!-- Device Flow: Consent Screen (same style as OAuth consent) -->
    <template id="oauth_device_consent" name="Device Authorization Consent">
        <t t-call="web.login_layout">
            <div class="oe_login_form oauth-consent-form">
                <h2 class="text-center mb-4">
                    <i class="fa fa-terminal me-2"/>
                    CLI Authorization
                </h2>

                <div class="alert alert-info mb-4">
                    <strong><t t-esc="client.client_name"/></strong> is requesting access to your account.
                </div>

                <!-- Client info -->
                <div class="card mb-4">
                    <div class="card-body">
                        <div class="d-flex align-items-center mb-3">
                            <div class="bg-dark rounded me-3 d-flex align-items-center justify-content-center"
                                 style="width: 48px; height: 48px;">
                                <i class="fa fa-terminal text-white fa-lg"/>
                            </div>
                            <div>
                                <h5 class="mb-0"><t t-esc="client.client_name"/></h5>
                                <small class="text-muted">Command Line Interface</small>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Requested permissions -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h6 class="mb-0">
                            <i class="fa fa-lock me-2"/>
                            Requested Permissions
                        </h6>
                    </div>
                    <ul class="list-group list-group-flush">
                        <t t-foreach="scopes" t-as="scope">
                            <li class="list-group-item">
                                <div class="d-flex align-items-center">
                                    <i class="fa fa-check-circle text-success me-2"/>
                                    <div>
                                        <strong><t t-esc="scope['name']"/></strong>
                                        <br/>
                                        <small class="text-muted"><t t-esc="scope['description']"/></small>
                                    </div>
                                </div>
                            </li>
                        </t>
                    </ul>
                </div>

                <!-- User info -->
                <div class="alert alert-secondary mb-4">
                    <small>
                        <i class="fa fa-user me-2"/>
                        Logged in as: <strong><t t-esc="user.name"/></strong>
                        (<t t-esc="user.email"/>)
                    </small>
                </div>

                <!-- Decision form -->
                <form method="POST" action="/oauth/device/authorize">
                    <input type="hidden" name="csrf_token" t-att-value="request.csrf_token()"/>
                    <input type="hidden" name="device_code" t-att-value="device_auth.device_code"/>

                    <div class="d-grid gap-2">
                        <button type="submit" name="action" value="authorize"
                                class="btn btn-primary btn-lg">
                            <i class="fa fa-check me-2"/>
                            Authorize CLI
                        </button>
                        <button type="submit" name="action" value="deny"
                                class="btn btn-outline-secondary">
                            <i class="fa fa-times me-2"/>
                            Deny
                        </button>
                    </div>
                </form>

                <!-- Timeout notice -->
                <div class="text-center mt-4">
                    <small class="text-muted">
                        <i class="fa fa-clock me-1"/>
                        This authorization request expires in 15 minutes.
                    </small>
                </div>
            </div>
        </t>
    </template>

    <!-- Device Flow: Enter Code Manually (OOB fallback) -->
    <template id="oauth_device_enter_code" name="Enter Device Code">
        <t t-call="web.login_layout">
            <div class="oe_login_form oauth-consent-form">
                <h2 class="text-center mb-4">
                    <i class="fa fa-terminal me-2"/>
                    Device Authorization
                </h2>

                <div class="alert alert-info mb-4">
                    Enter the code displayed in your terminal to authorize access.
                </div>

                <form method="GET" action="/oauth/device">
                    <div class="mb-3">
                        <label for="user_code" class="form-label">Device Code</label>
                        <input type="text" class="form-control form-control-lg text-center"
                               id="user_code" name="user_code"
                               placeholder="XXXX-XXXX"
                               pattern="[A-Za-z0-9]{4}-?[A-Za-z0-9]{4}"
                               autocomplete="off"
                               style="font-family: monospace; letter-spacing: 0.2em; font-size: 1.5rem;"/>
                        <small class="text-muted">Enter the 8-character code from your CLI</small>
                    </div>

                    <div class="d-grid">
                        <button type="submit" class="btn btn-primary btn-lg">
                            <i class="fa fa-arrow-right me-2"/>
                            Continue
                        </button>
                    </div>
                </form>
            </div>
        </t>
    </template>

    <!-- Device Flow: Success -->
    <template id="oauth_device_success" name="Device Authorization Success">
        <t t-call="web.login_layout">
            <div class="oe_login_form oauth-consent-form text-center">
                <div class="mb-4">
                    <i class="fa fa-check-circle text-success" style="font-size: 4rem;"/>
                </div>

                <h2 class="mb-4">Authorization Successful!</h2>

                <div class="alert alert-success mb-4">
                    <strong><t t-esc="client.client_name"/></strong> has been authorized.
                </div>

                <p class="text-muted mb-4">
                    You can now close this window and return to your terminal.
                    <br/>
                    The CLI should automatically continue.
                </p>

                <div class="text-muted">
                    <small>
                        <i class="fa fa-info-circle me-1"/>
                        You can revoke this access at any time in your account settings.
                    </small>
                </div>
            </div>
        </t>
    </template>

    <!-- Device Flow: Denied -->
    <template id="oauth_device_denied" name="Device Authorization Denied">
        <t t-call="web.login_layout">
            <div class="oe_login_form oauth-consent-form text-center">
                <div class="mb-4">
                    <i class="fa fa-times-circle text-danger" style="font-size: 4rem;"/>
                </div>

                <h2 class="mb-4">Authorization Denied</h2>

                <div class="alert alert-warning mb-4">
                    Access for <strong><t t-esc="client.client_name"/></strong> was denied.
                </div>

                <p class="text-muted mb-4">
                    You can close this window.
                    <br/>
                    The CLI will receive an access denied error.
                </p>
            </div>
        </t>
    </template>

    <!-- Device Flow: Error -->
    <template id="oauth_device_error" name="Device Authorization Error">
        <t t-call="web.login_layout">
            <div class="oe_login_form oauth-consent-form text-center">
                <div class="mb-4">
                    <i class="fa fa-exclamation-triangle text-warning" style="font-size: 4rem;"/>
                </div>

                <h2 class="mb-4">Authorization Error</h2>

                <div class="alert alert-danger mb-4">
                    <t t-esc="error"/>
                </div>

                <p class="text-muted mb-4">
                    Please try again from your CLI.
                </p>

                <div class="d-grid">
                    <a href="/oauth/device" class="btn btn-outline-primary">
                        <i class="fa fa-redo me-2"/>
                        Enter Code Manually
                    </a>
                </div>
            </div>
        </t>
    </template>

</odoo>
```

### 4.3 Flow utilisateur

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           FLOW ÉCRAN DE CONSENTEMENT                             │
└─────────────────────────────────────────────────────────────────────────────────┘

1. Claude.ai redirige vers /oauth/authorize
   │
   ▼
2. L'utilisateur a-t-il une session Odoo active ?
   │
   ├── Non → Redirect vers /web/login?redirect=/oauth/authorize?...
   │         │
   │         ▼
   │         Login Odoo standard
   │         │
   │         ▼
   │         Redirect vers /oauth/authorize (avec session)
   │
   └── Oui → Afficher écran de consentement
             │
             ▼
3. L'utilisateur lit les permissions demandées
   │
   ▼
4. Décision :
   │
   ├── [Autoriser] → Créer authorization_code
   │                 → Redirect vers callback Claude.ai avec code
   │
   └── [Refuser] → Redirect vers callback avec error=access_denied
```

---

## 5. Scopes MCP

### 5.1 Définition des scopes

| Scope | Level | Type | Permissions | Description |
|-------|-------|------|-------------|-------------|
| `mcp:discovery` | L1 | RO | `resources/list`, `tools/list`, `prompts/list`, `odoo://*` | Découvrir les domaines, modèles, champs et méthodes |
| `mcp:source` | L2 | RO | `odoo-source://{domain}/{model}/{method}` | Lire le code source Python |
| `mcp:documentation` | L3 | RO | `odoo-doc://{domain}/{model}` | Accéder aux fichiers .ai.md |
| `mcp:read` | L4 | RO | `read_objects`, `search_objects` | Lire les données des enregistrements |
| `mcp:debug` | L5 | RO | `analyze_stacktrace` | Analyser les stacktraces Python |
| `mcp:write` | L6 | RW | `write_objects`, `create_object`, `delete_objects` | Modifier, créer, supprimer des enregistrements |
| `mcp:execute` | L7 | RW | `call_method` | Exécuter des méthodes whitelistées |

> **Breaking change** : `mcp:metadata` et `mcp:operations` sont supprimés. Pas d'alias de compatibilité.

### 5.2 Hiérarchie et héritage

Les scopes sont **indépendants** (pas de hiérarchie implicite). Un client doit explicitement demander chaque scope nécessaire.

```python
# Exemple de validation dans mcp_controller.py

def _check_scope(self, required_scope):
    """Validate token has required scope."""
    token = request.inouk_token_obj
    if not token or not token.oauth21_scope:
        return True  # Non-OAuth21 tokens bypass scope check

    granted_scopes = set(token.oauth21_scope.split())
    if required_scope not in granted_scopes:
        raise AccessDenied(f"Missing scope: {required_scope}")

    return True
```

### 5.3 Mapping MCP → Scopes

| MCP Method | Required Scope |
|------------|----------------|
| `initialize` | (aucun - toujours autorisé) |
| `resources/list` | `mcp:discovery` |
| `resources/read odoo://server` | `mcp:discovery` |
| `resources/read odoo://{domain}` | `mcp:discovery` |
| `resources/read odoo://{domain}/{model}` | `mcp:discovery` |
| `resources/read odoo://{domain}/{model}/{id}` | `mcp:discovery` |
| `resources/read odoo-source://...` | `mcp:source` |
| `resources/read odoo-doc://...` | `mcp:documentation` |
| `tools/list` | `mcp:discovery` |
| `tools/call read_objects` | `mcp:read` |
| `tools/call search_objects` | `mcp:read` |
| `tools/call write_objects` | `mcp:write` |
| `tools/call create_object` | `mcp:write` |
| `tools/call delete_objects` | `mcp:write` |
| `tools/call call_method` | `mcp:execute` |
| `tools/call analyze_stacktrace` | `mcp:debug` |
| `prompts/list` | `mcp:discovery` |
| `prompts/get` | `mcp:discovery` |

---

## 6. Configuration

### 6.1 Paramètres système

Ajouter dans `res.config.settings` :

```python
# Paramètres OAuth 2.1
oauth_code_lifetime = fields.Integer(
    string="Authorization Code Lifetime (seconds)",
    config_parameter='inouk_api_auth.oauth_code_lifetime',
    default=600,
    help="How long authorization codes are valid (default: 10 minutes)"
)
oauth_token_lifetime = fields.Integer(
    string="Access Token Lifetime (seconds)",
    config_parameter='inouk_api_auth.oauth_token_lifetime',
    default=3600,
    help="How long access tokens are valid (default: 1 hour)"
)
oauth_refresh_lifetime_days = fields.Integer(
    string="Refresh Token Lifetime (days)",
    config_parameter='inouk_api_auth.oauth_refresh_lifetime_days',
    default=30,
    help="How long refresh tokens are valid (default: 30 days)"
)
oauth_rotate_refresh_tokens = fields.Boolean(
    string="Rotate Refresh Tokens",
    config_parameter='inouk_api_auth.oauth_rotate_refresh_tokens',
    default=True,
    help="Issue new refresh token on each use (security best practice)"
)
oauth_allowed_redirect_patterns = fields.Text(
    string="Allowed Redirect URI Patterns",
    config_parameter='inouk_api_auth.oauth_allowed_redirect_patterns',
    default='https://claude.ai/api/mcp/auth_callback\n'
            'https://claude.com/api/mcp/auth_callback\n'
            'http://localhost:*/callback\n'
            'http://127.0.0.1:*/callback',
    help="Newline-separated list of allowed redirect URI patterns. "
         "Supports wildcards: https://*.example.com/callback, "
         "localhost with any port: http://localhost:*/callback"
)

# Device Code Flow (RFC 8628) - for CLI tools
oauth_device_code_lifetime = fields.Integer(
    string="Device Code Lifetime (seconds)",
    config_parameter='inouk_api_auth.oauth_device_code_lifetime',
    default=900,
    help="How long device codes are valid (default: 15 minutes)"
)
oauth_device_poll_interval = fields.Integer(
    string="Device Polling Interval (seconds)",
    config_parameter='inouk_api_auth.oauth_device_poll_interval',
    default=5,
    help="Minimum interval between CLI polling requests (default: 5 seconds)"
)
```

### 6.2 Valeurs par défaut

| Paramètre | Valeur par défaut | Description |
|-----------|-------------------|-------------|
| `oauth_code_lifetime` | 600 (10 min) | Durée de vie des authorization codes |
| `oauth_token_lifetime` | 3600 (1h) | Durée de vie des access tokens |
| `oauth_refresh_lifetime_days` | 30 | Durée de vie des refresh tokens |
| `oauth_rotate_refresh_tokens` | True | Rotation des refresh tokens |
| `oauth_allowed_redirect_patterns` | Claude.ai + localhost | URIs de callback autorisées |
| `oauth_device_code_lifetime` | 900 (15 min) | Durée de vie des device codes (CLI) |
| `oauth_device_poll_interval` | 5 | Intervalle minimum entre les requêtes de polling CLI |

### 6.3 Configuration via UI

Ajouter une section dans Settings > API > OAuth 2.1 :

```xml
<group string="OAuth 2.1 Settings" name="oauth21_settings">
    <field name="oauth_code_lifetime"/>
    <field name="oauth_token_lifetime"/>
    <field name="oauth_refresh_lifetime_days"/>
    <field name="oauth_rotate_refresh_tokens"/>
    <field name="oauth_allowed_redirect_patterns" widget="text"/>
</group>
<group string="Device Code Flow (CLI)" name="oauth21_device_settings">
    <field name="oauth_device_code_lifetime"/>
    <field name="oauth_device_poll_interval"/>
</group>
```

---

## 7. Sécurité

### 7.1 PKCE (RFC 7636)

**Obligatoire** pour tous les flows `authorization_code`.

```python
# Validation PKCE
def validate_pkce(code_verifier, code_challenge, code_challenge_method):
    if code_challenge_method != 'S256':
        raise ValidationError("Only S256 is supported")

    # Compute expected challenge
    import hashlib
    import base64
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

    # Constant-time comparison (prevent timing attacks)
    import secrets
    if not secrets.compare_digest(computed, code_challenge):
        raise ValidationError("Invalid PKCE code_verifier")
```

### 7.2 Token Security

| Aspect | Mesure |
|--------|--------|
| Génération | 256 bits d'entropie (secrets.token_urlsafe) |
| Stockage | Hashing SHA-256 pour les refresh tokens (optionnel) |
| Transmission | HTTPS obligatoire |
| Rotation | Refresh tokens rotatifs par défaut |
| Révocation | API de révocation + cleanup cron |

### 7.3 Redirect URI Validation

```python
def validate_redirect_uri(client, redirect_uri):
    """Strict redirect URI validation."""

    # 1. Must be HTTPS
    if not redirect_uri.startswith('https://'):
        raise ValidationError("redirect_uri must use HTTPS")

    # 2. Must be registered
    allowed = client.redirect_uris.split('\n')
    if redirect_uri not in allowed:
        raise ValidationError("redirect_uri not registered")

    # 3. No fragments allowed
    if '#' in redirect_uri:
        raise ValidationError("redirect_uri cannot contain fragments")

    return True
```

### 7.4 Expiration Policies

| Token Type | Lifetime | Cleanup |
|------------|----------|---------|
| Authorization Code | 10 minutes | Cron toutes les heures |
| Access Token | 1 heure (configurable) | Via expiration_ts |
| Refresh Token | 30 jours (configurable) | Cron quotidien |

### 7.5 Audit Logging

Tous les événements OAuth sont loggés :

```python
_logger.info(
    "OAuth2.1: %s | client=%s user=%s scope=%s",
    event_type,
    client_id,
    user_id,
    scope
)
```

Events loggés :
- `authorization_code_created`
- `authorization_code_consumed`
- `access_token_issued`
- `refresh_token_issued`
- `refresh_token_used`
- `refresh_token_revoked`
- `token_validation_failed`

---

## 8. Tests

### 8.1 Structure des tests

```
inouk_api_auth/
└── tests/
    ├── __init__.py
    ├── test_oauth_authorization_code.py
    ├── test_oauth_client_registration.py
    ├── test_oauth_refresh_token.py
    ├── test_oauth_endpoints.py
    └── test_oauth_pkce.py
```

### 8.2 Tests unitaires

#### PKCE Validation

```python
# tests/test_oauth_pkce.py
from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError
import secrets
import hashlib
import base64


class TestPKCE(TransactionCase):

    def test_pkce_s256_valid(self):
        """Test valid PKCE S256 verification."""
        # Generate verifier
        verifier = secrets.token_urlsafe(43)

        # Compute challenge
        digest = hashlib.sha256(verifier.encode('ascii')).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

        # Create authorization code
        client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
            'redirect_uris': 'https://example.com/callback',
        })

        auth_code = self.env['ik.oauth_authorization_code'].create({
            'client_registration_id': client.id,
            'user_id': self.env.user.id,
            'redirect_uri': 'https://example.com/callback',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
        })

        # Should pass
        self.assertTrue(auth_code.validate_pkce(verifier))

    def test_pkce_s256_invalid(self):
        """Test invalid PKCE S256 verification."""
        client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
            'redirect_uris': 'https://example.com/callback',
        })

        auth_code = self.env['ik.oauth_authorization_code'].create({
            'client_registration_id': client.id,
            'user_id': self.env.user.id,
            'redirect_uri': 'https://example.com/callback',
            'code_challenge': 'valid_challenge_here',
            'code_challenge_method': 'S256',
        })

        # Should fail
        with self.assertRaises(ValidationError):
            auth_code.validate_pkce('wrong_verifier')
```

#### Authorization Code Lifecycle

```python
# tests/test_oauth_authorization_code.py
from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError
from datetime import timedelta


class TestAuthorizationCode(TransactionCase):

    def setUp(self):
        super().setUp()
        self.client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
            'redirect_uris': 'https://example.com/callback',
        })

    def test_code_single_use(self):
        """Authorization codes can only be used once."""
        auth_code = self.env['ik.oauth_authorization_code'].create({
            'client_registration_id': self.client.id,
            'user_id': self.env.user.id,
            'redirect_uri': 'https://example.com/callback',
            'code_challenge': 'test_challenge',
            'code_challenge_method': 'S256',
        })

        # First use should succeed
        auth_code.consume()
        self.assertTrue(auth_code.used)

        # Second use should fail
        with self.assertRaises(ValidationError):
            auth_code.consume()

    def test_code_expiration(self):
        """Authorization codes expire after configured lifetime."""
        auth_code = self.env['ik.oauth_authorization_code'].create({
            'client_registration_id': self.client.id,
            'user_id': self.env.user.id,
            'redirect_uri': 'https://example.com/callback',
            'code_challenge': 'test_challenge',
            'code_challenge_method': 'S256',
            'expires_at': fields.Datetime.subtract(fields.Datetime.now(), seconds=60),
        })

        # Should fail - expired
        with self.assertRaises(ValidationError):
            auth_code.consume()
```

### 8.3 Tests d'intégration

```python
# tests/test_oauth_endpoints.py
from odoo.tests import HttpCase, tagged


@tagged('post_install', '-at_install')
class TestOAuthEndpoints(HttpCase):

    def test_protected_resource_metadata_default(self):
        """Test /.well-known/oauth-protected-resource without resource param (default MCP)."""
        response = self.url_open('/.well-known/oauth-protected-resource')
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('resource', data)
        self.assertIn('authorization_servers', data)
        self.assertIn('bearer_methods_supported', data)
        self.assertIn('scopes_supported', data)
        # Default should be MCP resource
        self.assertIn('/mcp', data['resource'])
        self.assertIn('mcp:discovery', data['scopes_supported'])

    def test_protected_resource_metadata_with_resource_param(self):
        """Test /.well-known/oauth-protected-resource with resource parameter (RFC 9728 §3.2)."""
        base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url').rstrip('/')
        resource_url = f"{base_url}/mcp"

        response = self.url_open(f'/.well-known/oauth-protected-resource?resource={resource_url}')
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data['resource'], resource_url)
        self.assertIn('mcp:discovery', data['scopes_supported'])

    def test_protected_resource_metadata_unknown_resource(self):
        """Test /.well-known/oauth-protected-resource with unknown resource returns 404."""
        base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url').rstrip('/')
        unknown_resource = f"{base_url}/unknown/resource"

        response = self.url_open(f'/.well-known/oauth-protected-resource?resource={unknown_resource}')
        self.assertEqual(response.status_code, 404)

        data = response.json()
        self.assertEqual(data['error'], 'unknown_resource')

    def test_protected_resource_metadata_invalid_resource(self):
        """Test /.well-known/oauth-protected-resource with foreign resource returns 400."""
        foreign_resource = "https://other-server.com/mcp"

        response = self.url_open(f'/.well-known/oauth-protected-resource?resource={foreign_resource}')
        self.assertEqual(response.status_code, 400)

        data = response.json()
        self.assertEqual(data['error'], 'invalid_resource')

    def test_authorization_server_metadata(self):
        """Test /.well-known/oauth-authorization-server endpoint."""
        response = self.url_open('/.well-known/oauth-authorization-server')
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('authorization_endpoint', data)
        self.assertIn('token_endpoint', data)
        self.assertIn('registration_endpoint', data)
        self.assertIn('code_challenge_methods_supported', data)
        self.assertIn('S256', data['code_challenge_methods_supported'])

    def test_dynamic_client_registration(self):
        """Test /oauth/register endpoint."""
        response = self.url_open(
            '/oauth/register',
            data=json.dumps({
                'client_name': 'Test Client',
                'redirect_uris': ['https://example.com/callback'],
            }),
            headers={'Content-Type': 'application/json'},
        )

        self.assertEqual(response.status_code, 201)

        data = response.json()
        self.assertIn('client_id', data)
        self.assertTrue(data['client_id'].startswith('ikac_'))

    def test_full_authorization_flow(self):
        """Test complete OAuth 2.1 authorization flow."""
        # This would be a browser-based test using Selenium
        # to simulate the full flow including user consent
        pass
```

### 8.4 Tests Device Code Flow (NOUVEAU)

```python
# tests/test_oauth_device_code.py
from odoo.tests.common import TransactionCase
from odoo.tests import HttpCase, tagged
from odoo.exceptions import ValidationError
from odoo import fields
import json


class TestDeviceCodeModel(TransactionCase):
    """Unit tests for ik.oauth_device_code model."""

    def setUp(self):
        super().setUp()
        self.client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test CLI',
            'redirect_uris': '',  # No redirect for device flow
            'grant_types': 'urn:ietf:params:oauth:grant-type:device_code refresh_token',
        })

    def test_device_code_generation(self):
        """Test device code and user code generation."""
        DeviceCode = self.env['ik.oauth_device_code']

        response = DeviceCode.create_device_authorization(
            self.client,
            scope='mcp:discovery mcp:read',
        )

        # Check response structure (RFC 8628)
        self.assertIn('device_code', response)
        self.assertIn('user_code', response)
        self.assertIn('verification_uri', response)
        self.assertIn('verification_uri_complete', response)
        self.assertIn('expires_in', response)
        self.assertIn('interval', response)

        # Check user_code format (XXXX-XXXX)
        self.assertRegex(response['user_code'], r'^[A-Z0-9]{4}-[A-Z0-9]{4}$')

        # Check device_code is stored
        device_auth = DeviceCode.search([('device_code', '=', response['device_code'])])
        self.assertTrue(device_auth.exists())

    def test_device_code_authorization_pending(self):
        """Test polling returns authorization_pending before user authorizes."""
        DeviceCode = self.env['ik.oauth_device_code']

        response = DeviceCode.create_device_authorization(self.client)
        device_auth = DeviceCode.search([('device_code', '=', response['device_code'])])

        # Check status - should be pending
        status = device_auth.check_authorization_status()
        self.assertEqual(status.get('error'), 'authorization_pending')

    def test_device_code_slow_down(self):
        """Test polling too fast returns slow_down error."""
        DeviceCode = self.env['ik.oauth_device_code']

        response = DeviceCode.create_device_authorization(self.client)
        device_auth = DeviceCode.search([('device_code', '=', response['device_code'])])

        # First poll - should return authorization_pending
        device_auth.check_authorization_status()

        # Immediate second poll - should return slow_down
        status = device_auth.check_authorization_status()
        self.assertEqual(status.get('error'), 'slow_down')

    def test_device_code_authorize(self):
        """Test user authorization flow."""
        DeviceCode = self.env['ik.oauth_device_code']

        response = DeviceCode.create_device_authorization(
            self.client,
            scope='mcp:discovery',
        )
        device_auth = DeviceCode.search([('device_code', '=', response['device_code'])])

        # User authorizes
        device_auth.authorize(self.env.user)

        self.assertEqual(device_auth.state, 'authorized')
        self.assertEqual(device_auth.user_id, self.env.user)
        self.assertTrue(device_auth.authorization_code_id)

    def test_device_code_deny(self):
        """Test user denial flow."""
        DeviceCode = self.env['ik.oauth_device_code']

        response = DeviceCode.create_device_authorization(self.client)
        device_auth = DeviceCode.search([('device_code', '=', response['device_code'])])

        # User denies
        device_auth.deny()

        self.assertEqual(device_auth.state, 'denied')

        # Polling should return access_denied
        status = device_auth.check_authorization_status()
        self.assertEqual(status.get('error'), 'access_denied')

    def test_device_code_expiration(self):
        """Test device code expiration."""
        DeviceCode = self.env['ik.oauth_device_code']

        response = DeviceCode.create_device_authorization(self.client)
        device_auth = DeviceCode.search([('device_code', '=', response['device_code'])])

        # Force expiration
        device_auth.write({
            'expires_at': fields.Datetime.subtract(fields.Datetime.now(), seconds=60),
        })

        # Polling should return expired_token
        status = device_auth.check_authorization_status()
        self.assertEqual(status.get('error'), 'expired_token')


@tagged('post_install', '-at_install')
class TestDeviceCodeEndpoints(HttpCase):
    """Integration tests for device code endpoints."""

    def test_device_code_endpoint(self):
        """Test POST /oauth/device/code endpoint."""
        # First register a client
        reg_response = self.url_open(
            '/oauth/register',
            data=json.dumps({
                'client_name': 'Test CLI',
                'grant_types': [
                    'urn:ietf:params:oauth:grant-type:device_code',
                    'refresh_token',
                ],
            }),
            headers={'Content-Type': 'application/json'},
        )
        client_id = reg_response.json()['client_id']

        # Request device code
        response = self.url_open(
            '/oauth/device/code',
            data=f'client_id={client_id}&scope=mcp:discovery',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('device_code', data)
        self.assertIn('user_code', data)
        self.assertIn('verification_uri', data)
        self.assertIn('verification_uri_complete', data)

    def test_device_verification_requires_auth(self):
        """Test GET /oauth/device requires authentication."""
        response = self.url_open('/oauth/device?code=test', head=True)
        # Should redirect to login
        self.assertIn('/web/login', response.url)

    def test_device_token_polling(self):
        """Test POST /oauth/token with device_code grant."""
        # Register client
        reg_response = self.url_open(
            '/oauth/register',
            data=json.dumps({
                'client_name': 'Test CLI',
                'grant_types': ['urn:ietf:params:oauth:grant-type:device_code'],
            }),
            headers={'Content-Type': 'application/json'},
        )
        client_id = reg_response.json()['client_id']

        # Get device code
        dc_response = self.url_open(
            '/oauth/device/code',
            data=f'client_id={client_id}',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        device_code = dc_response.json()['device_code']

        # Poll for token (should return authorization_pending)
        token_response = self.url_open(
            '/oauth/token',
            data=f'grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}&client_id={client_id}',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )

        self.assertEqual(token_response.status_code, 400)
        self.assertEqual(token_response.json().get('error'), 'authorization_pending')
```

**Structure des fichiers de test mise à jour** :

```
inouk_api_auth/
└── tests/
    ├── __init__.py
    ├── test_oauth_authorization_code.py
    ├── test_oauth_client_registration.py
    ├── test_oauth_refresh_token.py
    ├── test_oauth_device_code.py          # NOUVEAU
    ├── test_oauth_endpoints.py
    └── test_oauth_pkce.py
```

---

## 9. Migration

### 9.1 Cohabitation avec client_credentials

L'implémentation OAuth 2.1 Authorization Code **coexiste** avec le flow client_credentials existant :

| Flow | Endpoint | Use Case |
|------|----------|----------|
| `client_credentials` | `/oauth/token` | Machine-to-machine (API keys, CI/CD) |
| `authorization_code` | `/oauth/authorize` + `/oauth/token` | Utilisateurs humains (Claude.ai) |

### 9.2 Rétrocompatibilité

- Les tokens existants (`token_type='bearer'`, `token_type='header'`) continuent de fonctionner
- Les tokens OAuth 2.0 client_credentials continuent de fonctionner
- Les nouveaux tokens OAuth 2.1 ont le champ `oauth21_client_registration_id` renseigné

### 9.3 Plan de migration

1. **Phase 1** : Déployer les nouveaux modèles et endpoints (sans impact)
2. **Phase 2** : Tester avec Claude.ai en mode dev
3. **Phase 3** : Activer en production
4. **Phase 4** : (Optionnel) Migrer les clients client_credentials vers authorization_code

### 9.4 Cleanup des anciens tokens

Ajouter un cron pour nettoyer les tokens OAuth 2.1 expirés :

```xml
<!-- data/cron_oauth21.xml -->
<record id="ir_cron_oauth21_cleanup" model="ir.cron">
    <field name="name">OAuth 2.1: Cleanup expired tokens</field>
    <field name="model_id" ref="model_ik_oauth_authorization_code"/>
    <field name="state">code</field>
    <field name="code">model._cron_cleanup_expired()</field>
    <field name="interval_number">1</field>
    <field name="interval_type">hours</field>
    <field name="numbercall">-1</field>
    <field name="active">True</field>
</record>

<record id="ir_cron_refresh_token_cleanup" model="ir.cron">
    <field name="name">OAuth 2.1: Cleanup expired refresh tokens</field>
    <field name="model_id" ref="model_ik_oauth_refresh_token"/>
    <field name="state">code</field>
    <field name="code">model._cron_cleanup_expired()</field>
    <field name="interval_number">1</field>
    <field name="interval_type">days</field>
    <field name="numbercall">-1</field>
    <field name="active">True</field>
</record>

<!-- NOUVEAU: Cleanup device codes -->
<record id="ir_cron_device_code_cleanup" model="ir.cron">
    <field name="name">OAuth 2.1: Cleanup expired device codes</field>
    <field name="model_id" ref="model_ik_oauth_device_code"/>
    <field name="state">code</field>
    <field name="code">model.cleanup_expired()</field>
    <field name="interval_number">15</field>
    <field name="interval_type">minutes</field>
    <field name="numbercall">-1</field>
    <field name="active">True</field>
</record>
```

---

## 10. Nettoyage inouk_api_auth (Généralisation)

Le module `inouk_api_auth` contient actuellement des références MCP hardcodées qui doivent être supprimées pour garder le module générique. Les scopes et endpoints MCP-spécifiques doivent être définis dans `inouk_mcp`.

### 10.1 Modifications requises

| Fichier | Ligne | Action |
|---------|-------|--------|
| `controllers/oauth.py` | ~6 | Supprimer "Claude Desktop" et "MCP servers" du commentaire |
| `controllers/oauth.py` | ~31-32 | Changer "MCP OAuth specification" → "OAuth 2.0 (RFC 8414)" |
| `controllers/oauth.py` | ~42 | Rendre `scopes_supported` configurable |
| `controllers/auth.py` | ~38 | Supprimer "MCP protocol endpoints" du commentaire |
| `models/api_auth_token__oauth_client.py` | ~194 | Supprimer hardcoding `/mcp` endpoint |
| `models/api_auth_token__oauth_client.py` | ~230-248 | Généraliser l'exemple (supprimer JSON-RPC MCP) |

### 10.2 Scopes configurables

**Avant** (hardcodé) :
```python
'scopes_supported': ['mcp'],
```

**Après** (configurable) :
```python
# Dans oauth.py - get_scopes_supported()
def _get_scopes_supported(self):
    """Get supported scopes from system parameter or default."""
    ICP = request.env['ir.config_parameter'].sudo()
    scopes_str = ICP.get_param('inouk_api_auth.oauth_scopes_supported', '')
    if scopes_str:
        return [s.strip() for s in scopes_str.split(',') if s.strip()]
    return []  # Empty by default - each protected resource defines its own

# Dans la réponse metadata
'scopes_supported': self._get_scopes_supported(),
```

### 10.3 Documentation générique

**Avant** :
```python
"""OAuth 2.0 Token Endpoint (Client Credentials Flow - SEP-1046)

This controller implements the OAuth 2.0 Client Credentials flow
for machine-to-machine authentication, enabling tools like Claude Desktop
to connect directly to MCP servers via URL.
"""
```

**Après** :
```python
"""OAuth 2.0 Token Endpoint (Client Credentials Flow)

This controller implements the OAuth 2.0 Client Credentials flow (RFC 6749)
for machine-to-machine authentication. Supports discovery via RFC 8414
(Authorization Server Metadata).

Flows supported:
- client_credentials: Machine-to-machine (API keys, CI/CD)
- authorization_code: User-interactive (web apps, CLI) - OAuth 2.1
- refresh_token: Token renewal
- device_code: CLI in remote environments (RFC 8628)
"""
```

### 10.4 Exemple générique pour help text

**Avant** (MCP-spécifique) :
```python
mcp_request = {
    'jsonrpc': '2.0',
    'method': 'initialize',
    'params': {'protocolVersion': '2024-11-05'}
}
response = requests.post("{base_url}/mcp", headers=headers, json=mcp_request)
```

**Après** (générique) :
```python
# Use the access token to call any protected API
response = requests.get(
    "{base_url}/api/your-endpoint",
    headers=headers
)
print(response.json())
```

### 10.5 Paramètre système

Ajouter un nouveau paramètre système pour les scopes globaux :

```python
# data/ir_config_parameter.xml
<record id="oauth_scopes_supported" model="ir.config_parameter">
    <field name="key">inouk_api_auth.oauth_scopes_supported</field>
    <field name="value"></field>  <!-- Empty by default -->
</record>
```

> **Note** : Les scopes MCP (`mcp:discovery`, `mcp:read`, `mcp:write`, etc.) sont définis dans `inouk_mcp` via l'endpoint `/.well-known/oauth-protected-resource`, pas dans `inouk_api_auth`.

---

## 11. Statut d'implémentation

> **Dernière mise à jour** : Janvier 2026

### 11.1 Résumé

| Module | Statut | Couverture |
|--------|--------|------------|
| inouk_api_auth (OAuth 2.1 core) | ✅ **COMPLET** | 100% |
| inouk_mcp (Protected Resource) | ✅ **COMPLET** | 100% |

### 11.2 Détail par composant

#### Modèles de données

| Modèle | Statut | Fichier |
|--------|--------|---------|
| `ik.oauth_authorization_code` | ✅ Implémenté | `models/oauth_authorization_code.py` |
| `ik.oauth_client_registration` | ✅ Implémenté | `models/oauth_client_registration.py` |
| `ik.oauth_refresh_token` | ✅ Implémenté | `models/oauth_refresh_token.py` |
| `ik.oauth_device_code` | ✅ Implémenté | `models/oauth_device_code.py` |
| `ik.api_auth_token` (extensions) | ✅ Implémenté | `models/api_auth_token__oauth21.py` |

#### Endpoints OAuth 2.1

| Endpoint | RFC | Statut | Fichier |
|----------|-----|--------|---------|
| `GET /.well-known/oauth-protected-resource` | RFC 9728 | ✅ Implémenté | `inouk_mcp/controllers/oauth_mcp.py` |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | ✅ Implémenté | `controllers/oauth.py` |
| `POST /oauth/register` | RFC 7591 | ✅ Implémenté | `controllers/oauth.py` |
| `GET/POST /oauth/authorize` | OAuth 2.1 | ✅ Implémenté | `controllers/oauth.py` |
| `POST /oauth/token` | OAuth 2.1 | ✅ Implémenté | `controllers/oauth.py` |
| `POST /oauth/device/code` | RFC 8628 | ✅ Implémenté | `controllers/oauth.py` |
| `GET /oauth/device` | RFC 8628 | ✅ Implémenté | `controllers/oauth.py` |
| `POST /oauth/device/authorize` | RFC 8628 | ✅ Implémenté | `controllers/oauth.py` |

#### Grant Types supportés

| Grant Type | Statut |
|------------|--------|
| `authorization_code` + PKCE | ✅ Implémenté |
| `refresh_token` | ✅ Implémenté |
| `client_credentials` | ✅ Implémenté (legacy) |
| `urn:ietf:params:oauth:grant-type:device_code` | ✅ Implémenté |

#### Templates et vues

| Template | Statut | Fichier |
|----------|--------|---------|
| Écran de consentement OAuth | ✅ Implémenté | `views/oauth_consent_templates.xml` |
| Device flow (4 templates) | ✅ Implémenté | `views/oauth_device_templates.xml` |
| Vues backend admin | ✅ Implémenté | `views/oauth_views.xml` |

#### Sécurité et opérations

| Composant | Statut |
|-----------|--------|
| PKCE S256 validation | ✅ Implémenté |
| Redirect URI validation | ✅ Implémenté |
| Token expiration & cleanup crons | ✅ Implémenté |
| Refresh token rotation | ✅ Implémenté |
| Scope validation | ✅ Implémenté |
| ACL (ir.model.access.csv) | ✅ Implémenté |

#### Tests

| Test | Statut | Fichier |
|------|--------|---------|
| Tests unitaires OAuth 2.1 | ✅ Implémenté | `tests/test_oauth21.py` |

### 11.3 Améliorations futures (optionnel)

Ces points de la section 10 sont des améliorations "nice-to-have" pour généraliser le module :

| Amélioration | Priorité | Statut |
|--------------|----------|--------|
| Supprimer références MCP hardcodées dans commentaires | Basse | 🔲 Non fait |
| Rendre `scopes_supported` configurable via paramètre | Basse | 🔲 Non fait |
| Généraliser exemples documentation | Basse | 🔲 Non fait |

> **Note** : Ces améliorations sont optionnelles. L'implémentation actuelle est fonctionnelle et production-ready.

### 11.4 Validation

L'implémentation a été validée contre :
- [x] OAuth 2.1 Draft (draft-ietf-oauth-v2-1-13)
- [x] RFC 8414 (Authorization Server Metadata)
- [x] RFC 9728 (Protected Resource Metadata)
- [x] RFC 7591 (Dynamic Client Registration)
- [x] RFC 7636 (PKCE)
- [x] RFC 8707 (Resource Indicators)
- [x] RFC 8628 (Device Authorization Grant)

---

## Annexes

### A. Références

- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [RFC 8414 - Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 9728 - Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 7591 - Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8707 - Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html)
- [RFC 8628 - Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [Anthropic Connectors FAQ](https://support.claude.com/en/articles/11596036-anthropic-connectors-directory-faq)
- [Building Custom Connectors](https://support.claude.com/en/articles/11503834-building-custom-connectors-via-remote-mcp-servers)

### B. Callback URLs autorisées

**Claude.ai** (web app) :
```
https://claude.ai/api/mcp/auth_callback
https://claude.com/api/mcp/auth_callback
```

**CLI mpy/mgx** (Device Code Flow - recommandé pour environnements distants) :
```
Pas de redirect_uri - utilise le Device Code Flow (RFC 8628)
L'utilisateur visite verification_uri_complete pour autoriser
```
> Note: Pour les environnements SSH, containers, headless - Device Code Flow est recommandé.

**CLI mpy/mgx** (localhost - fallback) :
```
http://localhost:{port}/callback
http://127.0.0.1:{port}/callback
```
> Note: Le port est dynamique (choisi par la CLI), d'où le pattern `localhost:*`
> Utilisable uniquement si le terminal a accès à un navigateur local.

**Future mobile app** (custom scheme) :
```
muppy://callback
```

### B.2 Clients pré-enregistrés

Pour simplifier l'usage des CLI, des clients peuvent être pré-enregistrés en base :

```xml
<!-- data/oauth_clients.xml -->
<odoo>
    <!-- CLI mpy -->
    <record id="oauth_client_mpy_cli" model="ik.oauth_client_registration">
        <field name="client_id">mpy-cli</field>
        <field name="client_name">Muppy CLI (mpy)</field>
        <field name="registration_type">manual</field>
        <field name="redirect_uris">http://localhost:*/callback
http://127.0.0.1:*/callback</field>
        <field name="grant_types">urn:ietf:params:oauth:grant-type:device_code,authorization_code,refresh_token</field>
        <field name="token_endpoint_auth_method">none</field>
        <field name="allowed_scopes">mcp:discovery mcp:source mcp:documentation mcp:read mcp:debug mcp:write mcp:execute</field>
        <field name="default_scopes">mcp:discovery mcp:read mcp:write</field>
    </record>

    <!-- CLI mgx -->
    <record id="oauth_client_mgx_cli" model="ik.oauth_client_registration">
        <field name="client_id">mgx-cli</field>
        <field name="client_name">Muppy Galaxy CLI (mgx)</field>
        <field name="registration_type">manual</field>
        <field name="redirect_uris">http://localhost:*/callback
http://127.0.0.1:*/callback</field>
        <field name="grant_types">urn:ietf:params:oauth:grant-type:device_code,authorization_code,refresh_token</field>
        <field name="token_endpoint_auth_method">none</field>
        <field name="allowed_scopes">mcp:discovery mcp:source mcp:documentation mcp:read mcp:debug mcp:write mcp:execute</field>
        <field name="default_scopes">mcp:discovery mcp:read mcp:write</field>
    </record>
</odoo>
```

**Usage CLI** :
```bash
# Login avec Device Code Flow (recommandé pour environnements distants)
$ mpy login --server https://mpy18c-k8s-dev-cyril.muppy.cloud

Opening browser to authenticate...
If browser doesn't open, visit:
  https://mpy18c-k8s-dev-cyril.muppy.cloud/oauth/device?code=abc123...

Waiting for authorization... (press Ctrl+C to cancel)
✓ Authenticated as cyril@muppy.cloud
Token saved to ~/.mpy/credentials.json

# Login avec mode manuel (si polling ne fonctionne pas)
$ mpy login --server https://mpy18c-k8s-dev-cyril.muppy.cloud --manual

Visit: https://mpy18c-k8s-dev-cyril.muppy.cloud/oauth/device
Enter code: ABCD-EFGH

Enter authorization code from browser: ****
✓ Authenticated as cyril@muppy.cloud
```

### C. Préfixes de tokens

| Préfixe | Type |
|---------|------|
| `ikac_` | Client ID (OAuth 2.1 client registration) |
| `ikacs_` | Client Secret |
| `ikaa_` | Access Token (header type) |
| `ikrt_` | Refresh Token |

### D. Codes d'erreur OAuth

| Code | Description |
|------|-------------|
| `invalid_request` | Paramètres manquants ou invalides |
| `invalid_client` | Client inconnu ou authentification client échouée |
| `invalid_grant` | Code/token invalide, expiré, révoqué |
| `unauthorized_client` | Client non autorisé pour ce grant type |
| `unsupported_grant_type` | Grant type non supporté |
| `invalid_scope` | Scope demandé invalide ou non autorisé |
| `access_denied` | Utilisateur a refusé l'autorisation |
| `server_error` | Erreur serveur interne |
