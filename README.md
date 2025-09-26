# Inouk API Auth

## Description

Ce module Odoo permet de gérer l'authentification par tokens pour les contrôleurs web utilisés comme API. Il fournit un système robuste de gestion des tokens avec des fonctionnalités de sécurité avancées.

## Fonctionnalités

### 🔐 Gestion des Tokens
- **Génération automatique** : Tokens sécurisés de 60 caractères hexadécimaux
- **Types supportés** : Bearer Token (standard) et X-Gitlab-Token (webhooks GitLab)
- **Expiration configurable** : Date/heure d'expiration optionnelle
- **Révocation** : Désactivation manuelle ou automatique des tokens

### 🛡️ Sécurité
- **Intégrité HTTPS** : Détection et désactivation automatique des tokens reçus via HTTP
- **Audit de sécurité** : Journal des compromissions dans le champ `security_log`
- **Validation temporelle** : Respect des dates d'expiration
- **Protection CSRF** : Compatible avec les protections CSRF d'Odoo

### 🔄 Deux méthodes d'authentification
1. **Nouvelle méthode (recommandée)** : `auth='ik_bearer'` dans les routes
2. **Ancienne méthode (dépréciée)** : Décorateur `@ik_authorize`

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
   - **Type** : Bearer (défaut) ou X-Gitlab-Token
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

## Exemples d'endpoints de test

Le module fournit deux endpoints de test :

### V1 (décorateur déprécié)
```bash
curl -H "Authorization: Bearer <token>" https://your-odoo.com/inouk/api_auth/v1/hello
```

### V2 (nouvelle méthode)
```bash
curl -H "Authorization: Bearer <token>" https://your-odoo.com/inouk/api_auth/v2/hello
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
- `token_type` (Selection) : 'bearer' ou 'xgitlabtoken'
- `expiration_ts` (Datetime) : Date d'expiration
- `is_compromised` (Boolean) : Token compromis
- `enforce_integrity` (Boolean) : Vérification HTTPS

#### Méthodes
- `btn_regenerate_token()` : Régénère un nouveau token
- `btn_restore_token()` : Restaure un token compromis

### Méthode d'authentification `_auth_method_ik_bearer()`

Méthode d'authentification intégrée au système Odoo qui :
1. Extrait le token des headers/paramètres
2. Valide le token en base
3. Vérifie l'intégrité HTTPS
4. Authentifie l'utilisateur
5. Stocke le token dans `request.inouk_token_obj`

## Développement et Tests

Le module inclut des tests unitaires couvrant :
- Création et validation de tokens
- Authentification avec différents types
- Détection de compromission HTTPS
- Expiration de tokens
- Contrôleurs API

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