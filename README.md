
Cet addon Odoo permet de gérer des Tokens utilisés authentifier des appels API.
L'addon contient:
* une table et un ensemble de vue minimum d'édition des Tokens
* un decorateur (ik_authorize) à ajouter sur les controllers web

L'interêt de cet addon réside dans le paramètre 'enforce_integrity' des Tokens.

Lorsque ce paramètre est défini Muppy vérifie aue les Tokens ne sont pas reçus en http et si c'est le cas il les désactive.

License
-------

LGPL-3.0