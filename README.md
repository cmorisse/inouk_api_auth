# Inouk API Auth

## Description

Ce module Odoo permet de gérer l'authentification par tokens pour les contrôleurs web utilisés comme API. Il fournit un système robuste de gestion des tokens avec des fonctionnalités de sécurité avancées.

## Fonctionnalités

### 🔐 Gestion des Tokens
- **Génération automatique** : Tokens sécurisés de 60 caractères hexadécimaux
- **Types supportés** : Bearer Token (standard), X-Gitlab-Token (webhooks GitLab), et AWS Signature V4
- **Expiration configurable** : Date/heure d'expiration optionnelle
- **Révocation** : Désactivation manuelle ou automatique des tokens

### 🛡️ Sécurité
- **Intégrité HTTPS** : Détection et désactivation automatique des tokens reçus via HTTP
- **Audit de sécurité** : Journal des compromissions dans le champ `security_log`
- **Validation temporelle** : Respect des dates d'expiration
- **Protection CSRF** : Compatible avec les protections CSRF d'Odoo

### 🔄 Trois méthodes d'authentification
1. **Bearer Token (recommandée)** : `auth='ik_bearer'` dans les routes
2. **AWS Signature V4** : `auth='ik_awssigv4'` pour compatibilité AWS
3. **Ancienne méthode (dépréciée)** : Décorateur `@ik_authorize`

## Installation

1. Placez le module dans votre répertoire `addons`
2. Mettez à jour la liste des modules : `Apps > Update Apps List`
3. Installez le module : `Apps > Search "Inouk API Auth" > Install`

## Configuration

### 1. Créer un token

1. Allez dans `Inouk > API Auth Tokens`
2. Créez un nouveau token :
   - **Nom** : Nom descriptif du token
   - **Description** : Usage prévu
   - **Utilisateur** : Utilisateur Odoo associé au token
   - **Type** : Bearer (défaut), X-Gitlab-Token, ou AWS Signature V4
   - **Expiration** : Date/heure d'expiration (optionnel)
   - **Enforce Integrity** : Désactivation automatique si reçu en HTTP

### 2. Utiliser le token de test

Le module génère automatiquement une commande `curl` de test dans l'interface :

```bash
curl --header 'Authorization: Bearer <votre_token>' https://your-odoo.com/inouk/api_auth/v2/hello
```

## Usage dans le code

### ✅ Méthode recommandée : `auth='ik_bearer'`

```python
from odoo import http
from odoo.http import request

class MonAPIController(http.Controller):

    @http.route('/mon/api/endpoint', methods=['POST'], type='http',
                auth='ik_bearer', csrf=False, save_session=False)
    def mon_endpoint(self, **kwargs):
        # Le token est disponible via request.inouk_token_obj
        token_obj = request.inouk_token_obj
        user = token_obj.user_id

        # Votre logique métier ici
        return http.request.make_response('{"status": "success"}',
                                        headers=[('Content-Type', 'application/json')])
```

### ⚠️ Ancienne méthode (dépréciée) : `@ik_authorize`

```python
from odoo import http
from odoo.addons.inouk_api_auth.api import ik_authorize

class MonAPIController(http.Controller):

    @ik_authorize  # DEPRECATED - génère un warning
    @http.route('/mon/api/legacy', methods=['POST'], type='http',
                auth='none', csrf=False, save_session=False)
    def mon_endpoint_legacy(self, token_obj=None, **kwargs):
        # token_obj est injecté par le décorateur
        user = token_obj.user_id
        return "OK"
```

## Méthodes de transmission du token

### 1. Header Authorization (recommandé)
```bash
curl -H "Authorization: Bearer <token>" https://example.com/api/endpoint
```

### 2. Header X-Gitlab-Token (webhooks GitLab)
```bash
curl -H "X-Gitlab-Token: <token>" https://example.com/api/endpoint
```

### 3. Paramètre URL (moins sécurisé)
```bash
curl "https://example.com/api/endpoint?access_token=<token>"
```

## 🔐 AWS Signature Version 4 Authentication

This module supports **AWS Signature Version 4** authentication method, allowing compatibility with AWS-style authentication for your Odoo API endpoints.

### AWS SigV4 Features

- **Standard AWS SigV4 protocol** compliance
- **Automatic key generation** with proper AWS format (AKIA prefix)
- **Signed curl command generation** for testing
- **15-minute request validity window** (configurable)
- **Region and service flexibility** (client-defined)
- **HTTPS integrity enforcement** (same as Bearer tokens)

### Setting up AWS SigV4 Authentication

#### 1. Create an AWS SigV4 Token

1. Go to `Inouk > API Auth Tokens`
2. Create a new token with:
   - **Type**: "AWS Signature V4"
   - **User**: Associated Odoo user
   - **Generate AWS Keys**: Click the "Generate AWS Keys" button

#### 2. AWS Key Format

- **Access Key ID**: 20 characters starting with `AKIA` (e.g., `AKIAIOSFODNN7EXAMPLE`)
- **Secret Access Key**: 40 characters base64-like string

#### 3. Test the Authentication

The module automatically generates a signed curl command for testing:

```bash
curl --header 'Authorization: AWS4-HMAC-SHA256 Credential=AKIA.../...' \
     --header 'X-Amz-Date: 20230101T120000Z' \
     --header 'Host: your-odoo.com' \
     'https://your-odoo.com/inouk/api_auth/v2/awssigv4_test'
```

### Using AWS SigV4 in Controllers

```python
from odoo import http
from odoo.http import request

class MyAWSAPIController(http.Controller):

    @http.route('/my/aws/api/endpoint', methods=['GET', 'POST'], type='http',
                auth='ik_awssigv4', csrf=False, save_session=False)
    def aws_api_endpoint(self, **kwargs):
        # The token object is available via request.inouk_token_obj
        token_obj = request.inouk_token_obj
        user = token_obj.user_id
        access_key_id = token_obj.awssigv4_access_key_id

        # Your business logic here
        return http.request.make_response('{"status": "authenticated"}',
                                        headers=[('Content-Type', 'application/json')])
```

### AWS SigV4 Request Format

AWS SigV4 authentication requires specific headers in your HTTP requests:

#### Required Headers

1. **Authorization**: AWS4-HMAC-SHA256 signature
   ```
   Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=<calculated_signature>
   ```

2. **X-Amz-Date**: Request timestamp (ISO 8601 format)
   ```
   X-Amz-Date: 20230101T120000Z
   ```

3. **Host**: Target host header
   ```
   Host: your-odoo.com
   ```

#### Credential Format

The credential string in the Authorization header follows AWS format:
```
AccessKeyId/Date/Region/Service/aws4_request
```

Where:
- **AccessKeyId**: Your generated access key (AKIA...)
- **Date**: Request date (YYYYMMDD)
- **Region**: AWS region (e.g., `us-east-1`) - client defined
- **Service**: AWS service name (e.g., `execute-api`) - client defined

### AWS SigV4 Security Features

- **Request signing**: Each request must be cryptographically signed
- **Timestamp validation**: Requests older than 15 minutes are rejected
- **Signature verification**: Uses HMAC-SHA256 for signature validation
- **Replay protection**: Signed requests cannot be replayed after expiration
- **HTTPS enforcement**: Same integrity checks as Bearer tokens

### Generating Signed Requests

The module provides a helper to generate properly signed curl commands. For programmatic usage, you can use the AWS SDK or botocore:

```python
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

# Create request
request = AWSRequest(method='GET', url='https://your-odoo.com/api/endpoint')

# Create credentials
credentials = Credentials(
    access_key='AKIAIOSFODNN7EXAMPLE',
    secret_key='your_secret_key'
)

# Sign request
signer = SigV4Auth(credentials, 'execute-api', 'us-east-1')
signer.add_auth(request)

# Now request.headers contains the signed headers
```

### AWS SigV4 Test Endpoint

Test your AWS SigV4 authentication using the dedicated endpoint:

```bash
# URL: /inouk/api_auth/v2/awssigv4_test
# Method: GET
# Auth: ik_awssigv4

# Use the auto-generated signed curl command from the token interface
```

### Troubleshooting AWS SigV4

#### "Missing or invalid AWS4-HMAC-SHA256 Authorization header"
- Ensure Authorization header starts with `AWS4-HMAC-SHA256`
- Check header format and signature calculation

#### "Invalid Authorization header format"
- Verify credential string format: `AccessKey/Date/Region/Service/aws4_request`
- Check date format in credential (YYYYMMDD)

#### "Invalid AWS Access Key ID"
- Access key not found in database
- Token may be expired or compromised
- Check access key format (should start with AKIA)

#### "Invalid AWS Signature"
- Signature calculation mismatch
- Check request canonical string calculation
- Verify secret access key
- Ensure request timestamp is within 15-minute window

### AWS SigV4 Implementation Notes

- Compatible with AWS SDK signature calculation
- Uses botocore library for signature validation
- Supports any region/service combination (client-defined)
- No session tokens required (IAM user style authentication)
- Proper entropy and format for generated keys

## Exemples d'endpoints de test

Le module fournit trois endpoints de test :

### V1 (décorateur déprécié)
```bash
curl -H "Authorization: Bearer <token>" https://your-odoo.com/inouk/api_auth/v1/hello
```

### V2 Bearer (nouvelle méthode)
```bash
curl -H "Authorization: Bearer <token>" https://your-odoo.com/inouk/api_auth/v2/hello
```

### V2 AWS SigV4
```bash
# Use the auto-generated signed curl command from the AWS token interface
curl --header 'Authorization: AWS4-HMAC-SHA256 Credential=...' https://your-odoo.com/inouk/api_auth/v2/awssigv4_test
```

## Migration du décorateur vers auth='ik_bearer'

### Avant (déprécié)
```python
@ik_authorize
@route('/api/endpoint', type='http', auth='none', csrf=False)
def my_endpoint(self, token_obj=None, **kwargs):
    user = token_obj.user_id
    # ...
```

### Après (recommandé)
```python
@route('/api/endpoint', type='http', auth='ik_bearer', csrf=False)
def my_endpoint(self, **kwargs):
    token_obj = request.inouk_token_obj
    user = token_obj.user_id
    # ...
```

### Changements nécessaires
1. ✅ Remplacer `@ik_authorize` par `auth='ik_bearer'`
2. ✅ Changer `auth='none'` en `auth='ik_bearer'`
3. ✅ Retirer le paramètre `token_obj=None`
4. ✅ Accéder au token via `request.inouk_token_obj`

## Sécurité

### ⚠️ Bonnes pratiques

1. **HTTPS obligatoire** : Utilisez toujours HTTPS en production
2. **Expiration des tokens** : Définissez des dates d'expiration appropriées
3. **Rotate les tokens** : Renouvelez périodiquement les tokens
4. **Monitoring** : Surveillez les logs de sécurité
5. **Permissions minimales** : Associez les tokens aux utilisateurs avec les permissions strictement nécessaires

### 🔒 Fonctionnalités de sécurité

- **Détection HTTP** : Les tokens reçus en HTTP sont automatiquement désactivés (si `enforce_integrity=True`)
- **Audit trail** : Tous les événements de sécurité sont tracés
- **Session validation** : Session tokens correctement calculés
- **Protection contre la réutilisation** : Tokens compromis immédiatement inutilisables

## Troubleshooting

### Erreur "Missing required Authorization"
- Vérifiez que le token est bien transmis dans un des headers/paramètres supportés
- Vérifiez la syntaxe : `Authorization: Bearer <token>`

### Erreur "Invalid Access Token"
- Le token n'existe pas, est expiré ou compromis
- Vérifiez dans l'interface d'administration des tokens

### Token désactivé automatiquement
- Le token a été reçu en HTTP alors qu'`enforce_integrity=True`
- Utilisez HTTPS ou désactivez `enforce_integrity` pour les tests

### Warning de dépréciation
- Vous utilisez encore `@ik_authorize`
- Migrez vers `auth='ik_bearer'` selon la section migration

## API Reference

### Modèle `ik.api_auth_token`

#### Champs principaux
- `name` (Char) : Nom du token
- `static_token` (Char) : Valeur du token (60 chars hex)
- `user_id` (Many2one) : Utilisateur associé
- `token_type` (Selection) : 'bearer', 'xgitlabtoken', ou 'awssigv4'
- `expiration_ts` (Datetime) : Date d'expiration
- `is_compromised` (Boolean) : Token compromis
- `enforce_integrity` (Boolean) : Vérification HTTPS
- `awssigv4_access_key_id` (Char) : AWS Access Key ID (pour type awssigv4)
- `awssigv4_secret_access_key` (Char) : AWS Secret Access Key (pour type awssigv4)

#### Méthodes
- `btn_regenerate_token()` : Régénère un nouveau token
- `btn_restore_token()` : Restaure un token compromis
- `btn_generate_awssigv4_keys()` : Génère des clés AWS SigV4 (pour type awssigv4)
- `compute__awssigv4_test_curl()` : Génère une commande curl signée AWS SigV4

### Méthodes d'authentification

#### `_auth_method_ik_bearer()`

Méthode d'authentification Bearer Token intégrée au système Odoo qui :
1. Extrait le token des headers/paramètres
2. Valide le token en base
3. Vérifie l'intégrité HTTPS
4. Authentifie l'utilisateur
5. Stocke le token dans `request.inouk_token_obj`

#### `_auth_method_ik_awssigv4()`

Méthode d'authentification AWS Signature V4 qui :
1. Extrait l'Access Key ID de l'en-tête Authorization
2. Recherche le token AWS SigV4 correspondant
3. Valide la signature HMAC-SHA256 avec botocore
4. Vérifie la validité temporelle (15 minutes)
5. Vérifie l'intégrité HTTPS
6. Authentifie l'utilisateur
7. Stocke le token dans `request.inouk_token_obj`

## Développement et Tests

Le module inclut des tests unitaires couvrant :
- Création et validation de tokens (Bearer, X-Gitlab-Token, AWS SigV4)
- Authentification avec différents types
- Détection de compromission HTTPS
- Expiration de tokens
- Génération de clés AWS et validation de signature
- Contrôleurs API pour tous les types d'authentification

Pour exécuter les tests :
```bash
bin/start_odoo --test-enable --stop-after-init -u inouk_api_auth
```

## Support et Contribution

### Auteur
(c) 2022 Cyril MORISSE

### License
LGPL-3.0

### Issues
Rapportez les bugs et demandes de fonctionnalités sur le dépôt Git du projet.

### Contribution
Les pull requests sont les bienvenues. Pour les changements majeurs, ouvrez d'abord une issue pour discuter des modifications proposées.