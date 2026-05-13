# Guide : Implémenter OAuth 2.1 pour un serveur MCP compatible Claude.ai

## Contexte du problème

Notre serveur MCP Muppy utilise actuellement un flow `client_credentials` (machine-to-machine) pour l'authentification. **Claude.ai ne supporte PAS ce flow.**

> "Pure client credentials flow (machine-to-machine OAuth with just client_id/client_secret and no user interaction) is not supported."
> — [Anthropic Connectors Directory FAQ](https://support.claude.com/en/articles/11596036-anthropic-connectors-directory-faq)

## Ce que Claude.ai supporte

Claude.ai supporte :
1. **Pas d'authentification** (authless) - le plus simple
2. **OAuth 2.1 avec Authorization Code + PKCE** - avec interaction utilisateur obligatoire

Claude.ai **NE supporte PAS** :
- Client credentials flow (machine-to-machine)
- API keys statiques
- Basic Auth simple

## Architecture OAuth 2.1 requise par Claude.ai

### Spécifications à implémenter

| Spec | RFC | Usage |
|------|-----|-------|
| OAuth 2.1 | [draft-ietf-oauth-v2-1-13](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13) | Flow principal |
| Authorization Server Metadata | [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | Discovery des endpoints |
| Protected Resource Metadata | [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) | Lien MCP → Auth Server |
| Dynamic Client Registration | [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) | Registration automatique (recommandé) |
| Resource Indicators | [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | Binding token → ressource |
| PKCE | [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | Protection du code |

### Endpoints à implémenter

```
GET  /.well-known/oauth-protected-resource     → Protected Resource Metadata (RFC 9728)
GET  /.well-known/oauth-authorization-server   → Authorization Server Metadata (RFC 8414)
POST /oauth/register                           → Dynamic Client Registration (RFC 7591)
GET  /oauth/authorize                          → Authorization endpoint
POST /oauth/token                              → Token endpoint
POST /mcp                                      → MCP endpoint (protégé par Bearer token)
```

## Flow OAuth complet attendu par Claude.ai

```
┌─────────────┐                                    ┌─────────────┐
│  Claude.ai  │                                    │  MCP Server │
└──────┬──────┘                                    └──────┬──────┘
       │                                                  │
       │ 1. POST /mcp (sans auth)                        │
       │─────────────────────────────────────────────────>│
       │                                                  │
       │ 2. 401 Unauthorized                              │
       │    WWW-Authenticate: Bearer                      │
       │    resource_metadata="/.well-known/oauth-protected-resource"
       │<─────────────────────────────────────────────────│
       │                                                  │
       │ 3. GET /.well-known/oauth-protected-resource    │
       │─────────────────────────────────────────────────>│
       │                                                  │
       │ 4. { "authorization_servers": ["https://..."] } │
       │<─────────────────────────────────────────────────│
       │                                                  │
       │ 5. GET /.well-known/oauth-authorization-server  │
       │─────────────────────────────────────────────────>│
       │                                                  │
       │ 6. Authorization Server Metadata                 │
       │<─────────────────────────────────────────────────│
       │                                                  │
       │ 7. POST /oauth/register (DCR - si supporté)     │
       │─────────────────────────────────────────────────>│
       │                                                  │
       │ 8. { client_id, client_secret? }                │
       │<─────────────────────────────────────────────────│
       │                                                  │
       │ 9. Redirect user → /oauth/authorize             │
       │    ?response_type=code                           │
       │    &client_id=...                                │
       │    &redirect_uri=https://claude.ai/api/mcp/auth_callback
       │    &code_challenge=...                           │
       │    &code_challenge_method=S256                   │
       │    &state=...                                    │
       │    &resource=https://mcp-server.example.com      │
       │─────────────────────────────────────────────────>│
       │                                                  │
       │         ┌────────────────────────────┐           │
       │         │  USER CONSENT SCREEN       │           │
       │         │  (interaction obligatoire) │           │
       │         └────────────────────────────┘           │
       │                                                  │
       │ 10. Redirect → claude.ai/api/mcp/auth_callback  │
       │     ?code=...&state=...                          │
       │<─────────────────────────────────────────────────│
       │                                                  │
       │ 11. POST /oauth/token                           │
       │     grant_type=authorization_code                │
       │     code=...                                     │
       │     code_verifier=...                            │
       │     redirect_uri=...                             │
       │     resource=https://mcp-server.example.com      │
       │─────────────────────────────────────────────────>│
       │                                                  │
       │ 12. { access_token, refresh_token, expires_in } │
       │<─────────────────────────────────────────────────│
       │                                                  │
       │ 13. POST /mcp                                   │
       │     Authorization: Bearer <access_token>         │
       │─────────────────────────────────────────────────>│
       │                                                  │
       │ 14. MCP Response (tools/list, etc.)             │
       │<─────────────────────────────────────────────────│
```

## Détails d'implémentation

### 1. Protected Resource Metadata (RFC 9728)

**Endpoint:** `GET /.well-known/oauth-protected-resource`

```json
{
  "resource": "https://mpy18c-k8s-dev-cyril.muppy.cloud",
  "authorization_servers": [
    "https://mpy18c-k8s-dev-cyril.muppy.cloud"
  ],
  "bearer_methods_supported": ["header"],
  "resource_signing_alg_values_supported": ["RS256"]
}
```

### 2. Authorization Server Metadata (RFC 8414)

**Endpoint:** `GET /.well-known/oauth-authorization-server`

```json
{
  "issuer": "https://mpy18c-k8s-dev-cyril.muppy.cloud",
  "authorization_endpoint": "https://mpy18c-k8s-dev-cyril.muppy.cloud/oauth/authorize",
  "token_endpoint": "https://mpy18c-k8s-dev-cyril.muppy.cloud/oauth/token",
  "registration_endpoint": "https://mpy18c-k8s-dev-cyril.muppy.cloud/oauth/register",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
  "scopes_supported": ["mcp:read", "mcp:write"]
}
```

### 3. Dynamic Client Registration (RFC 7591)

**Endpoint:** `POST /oauth/register`

**Request:**
```json
{
  "client_name": "Claude",
  "redirect_uris": [
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

**Response:**
```json
{
  "client_id": "generated_client_id_abc123",
  "client_name": "Claude",
  "redirect_uris": [
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "client_secret_expires_at": 0
}
```

> **Note:** Si DCR n'est pas supporté, l'utilisateur peut entrer manuellement un `client_id` et `client_secret` statique dans l'UI Claude.ai (Settings > Connectors > Paramètres avancés).

### 4. Authorization Endpoint

**Endpoint:** `GET /oauth/authorize`

**Paramètres attendus:**
- `response_type=code` (obligatoire)
- `client_id` (obligatoire)
- `redirect_uri` (obligatoire, doit matcher une URI enregistrée)
- `state` (obligatoire pour sécurité)
- `code_challenge` (obligatoire, PKCE)
- `code_challenge_method=S256` (obligatoire)
- `resource` (obligatoire, RFC 8707)
- `scope` (optionnel)

**Flow:**
1. Valider tous les paramètres
2. **Afficher un écran de consentement à l'utilisateur** (OBLIGATOIRE)
3. Après consentement, générer un `authorization_code`
4. Redirect vers `redirect_uri?code=...&state=...`

### 5. Token Endpoint

**Endpoint:** `POST /oauth/token`

**Pour authorization_code:**
```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTH_CODE_HERE
&redirect_uri=https://claude.ai/api/mcp/auth_callback
&client_id=CLIENT_ID
&code_verifier=PKCE_VERIFIER
&resource=https://mpy18c-k8s-dev-cyril.muppy.cloud
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_xyz",
  "scope": "mcp:read mcp:write"
}
```

**Pour refresh_token:**
```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=REFRESH_TOKEN
&client_id=CLIENT_ID
```

### 6. Réponse 401 avec WWW-Authenticate (RFC 9728)

Quand une requête MCP arrive sans token ou avec un token invalide :

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="MCP", resource_metadata="https://mpy18c-k8s-dev-cyril.muppy.cloud/.well-known/oauth-protected-resource"
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": null,
  "error": {
    "code": -32001,
    "message": "Authentication required"
  }
}
```

### 7. Requêtes MCP authentifiées

Toutes les requêtes MCP après auth doivent inclure :

```http
POST /mcp HTTP/1.1
Host: mpy18c-k8s-dev-cyril.muppy.cloud
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
Content-Type: application/json

{"jsonrpc": "2.0", "method": "tools/list", "id": 1}
```

## Configuration Claude.ai

### Callback URLs à autoriser

```
https://claude.ai/api/mcp/auth_callback
https://claude.com/api/mcp/auth_callback
```

### Client name

Le client OAuth s'identifiera comme `"Claude"`.

### IPs Anthropic (pour allowlisting optionnel)

Voir : https://docs.claude.com/en/api/ip-addresses

## Points critiques

### ⚠️ Ce qui ne fonctionne PAS

1. **Client credentials flow** - Claude.ai ne l'implémente pas
2. **Basic Auth** - Non supporté
3. **Tokens dans query string** - Interdit par OAuth 2.1
4. **Authorization sans interaction utilisateur** - L'utilisateur DOIT voir un écran de consentement

### ✅ Ce qui est requis

1. **PKCE obligatoire** (`code_challenge_method=S256`)
2. **Paramètre `resource` obligatoire** (RFC 8707)
3. **Validation d'audience** - Le token doit être validé pour le bon serveur
4. **HTTPS obligatoire** - Tous les endpoints
5. **Token refresh** - Supporter le refresh des tokens expirés

## Alternative simple : Mode authless

Si l'authentification n'est pas critique, le plus simple est de désactiver l'auth :

1. Ne pas retourner `authInfo` dans la réponse `initialize`
2. Accepter toutes les requêtes `tools/list`, `resources/list`, `prompts/list`
3. Optionnellement, utiliser l'IP allowlisting pour restreindre aux IPs Claude

## Ressources

- [MCP Authorization Spec (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [Building Custom Connectors](https://support.claude.com/en/articles/11503834-building-custom-connectors-via-remote-mcp-servers)
- [Connectors Directory FAQ](https://support.claude.com/en/articles/11596036-anthropic-connectors-directory-faq)
- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [RFC 8414 - Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 9728 - Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 7591 - Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
- [RFC 8707 - Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html)
- [TypeScript SDK examples](https://github.com/modelcontextprotocol/typescript-sdk/tree/main/src/examples/server)
- [Python SDK examples](https://github.com/modelcontextprotocol/python-sdk/tree/main/examples/servers)

## Prochaines étapes

1. **Court terme** : Désactiver l'auth pour tester le reste du MCP
2. **Moyen terme** : Implémenter OAuth 2.1 complet avec les endpoints ci-dessus
3. **Test** : Utiliser le [MCP Inspector](https://github.com/modelcontextprotocol/inspector) pour valider le flow OAuth
