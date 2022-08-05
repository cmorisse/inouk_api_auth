
Version courte
--------------

Cet addon Odoo permet de gérer des Tokens et de les utiliser pour authentifier des appels à des web controllers utilisés comme API.

L'addon contient:

* une table et un ensemble minimum de vues d'édition des Tokens
* un decorateur (ik_authorize) à ajouter sur les controllers web (voir controller d'exemple)

L'interêt de cet addon réside dans la gestion de l'expiration et de l'intégrité des tokens.
Un paramètre 'enforce_integrity' est présent sur les Tokens.
Lorsque ce paramètre est activé, les Tokens reçus en http sont désactivés.

L'addon permet aussi de gérer une expiration des Tokens.

Auteurs
-------

(c) 2022 Cyril MORISSE 


License
-------

LGPL-3.0