# Striker

État documenté le 3 octobre 2026, à partir d'une revue statique de la copie du projet fournie. Cette documentation décrit le code présent ; elle ne constitue pas une validation de fonctionnement.

Striker est un prototype Python regroupant une API HTTP, une CLI, des utilitaires de temporisation et de traitement de tâches, ainsi qu'une interface terminal Textual orientée vers un module DoS actuellement absent. Plusieurs intégrations sont incomplètes et les différents points d'entrée n'utilisent pas tous le même chemin de traitement.

Le rapport [AUDIT.md](AUDIT.md) présente les anomalies, leurs conséquences et les corrections proposées. Aucun correctif de code n'a été appliqué dans le cadre de cette revue.

## État actuel

| Composant | Ce que contient cette copie | Limite principale |
| --- | --- | --- |
| CLI HTTP | Sous-commande `scrape` de `main.py`, avec pool de threads | Utilise `requests` et le backoff, pas le chemin CAPTCHA/navigateur/TLS de `get()` |
| API Python | Classe `ScrapingStack` dans `main.py` | Chemins HTTP distincts, garanties de temporisation et erreurs non uniformes |
| Interface terminal | `StrikerTUI` et `MainScreen` dans `ui/ui.py` | Le bouton de démarrage tente d'importer un module absent |
| Sous-commande `dos` | Déclaration du parseur et adaptateur dans `main.py` | `application.dos` n'existe pas dans cette arborescence |
| Ancien fichier DoS | `test/core/ddos.py` | Fichier syntaxiquement invalide, non assimilable à une implémentation utilisable |
| File de tâches | File en mémoire et adaptateur Redis | Redis n'est pas exposé par la CLI principale ; pas d'acquittement durable des tâches |
| Tests | Script de démonstration `test/test.py` | Simulation par défaut, sans assertions de non-régression |
| Installation | Script Bash `install.sh` et liste de dépendances | Installateur désynchronisé de l'arborescence et défectueux en mode `--no-venv` |

La restriction globale aux IP privées annoncée par l'ancien README n'est pas établie par ce code. `test/test.py` comporte des contrôles locaux dans son point d'entrée, mais ils ne constituent pas une politique de sécurité commune au projet. L'ancien fichier `test/core/ddos.py` contient une cible publique et des instructions réseau au niveau global ; il ne doit pas être traité comme un test automatisé.

## Arborescence

```text
Striker/
├── main.py
├── install.sh
├── config/
│   ├── __init__.py
│   └── settings.py               # vide
├── docs/
│   ├── README.md
│   ├── AUDIT.md
│   ├── requirements.txt
│   └── struct.txt
├── identity/
│   ├── __init__.py
│   └── user_agent_rotator.py
├── network/
│   ├── __init__.py
│   └── stealth_browser.py
├── policies/
│   ├── __init__.py
│   ├── adaptive_backoff.py
│   └── delay_jitter.py
├── protection_bypass/
│   ├── __init__.py
│   ├── captcha_solvers.py
│   ├── captcha_waf_bypass.py
│   └── protection_detector.py
├── proxy/
│   ├── __init__.py
│   └── proxy_rotator.py
├── scraping/
│   ├── __init__.py
│   └── request_fragmenter.py
├── test/
│   ├── test.py
│   └── core/
│       ├── __init__.py
│       └── ddos.py
├── ui/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── tui.tcss
│   └── ui.py
└── workers/
    ├── __init__.py
    └── distributed_bots.py
```

L'environnement local `venv/`, les caches Python et les métadonnées macOS sont omis de cet inventaire. Il n'y a pas de dossier `application/` ni de dossier `core/` à la racine dans la copie examinée.

## Dépendances et installation

L'installateur demande Python 3.10 ou supérieur. La compatibilité des versions des bibliothèques n'a pas été testée pendant cette revue.

La liste fournie se trouve dans **`docs/requirements.txt`** :

```text
textual>=0.60
requests>=2.31
aiohttp>=3.9
```

Ces bornes minimales ne constituent pas un verrouillage des versions. `requests` sert aux chemins HTTP classiques ; Textual sert à la TUI ; `aiohttp` est importé dans la méthode d'envoi asynchrone du fragmenter.

Pour préparer un environnement neuf, depuis la racine du projet :

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r docs/requirements.txt
```

Ces commandes sont fournies comme instructions de préparation et n'ont pas été exécutées lors de l'audit. Elles n'activent aucun test réseau.

Des imports optionnels existent pour `curl_cffi`, `cloudscraper`, `playwright`, `nodriver` et `redis`. Ils ne figurent pas dans `docs/requirements.txt`. L'installateur propose les trois premiers composants `curl_cffi`, `cloudscraper`, `redis`, puis demande séparément s'il faut installer Playwright et Chromium ; il ne propose pas `nodriver`. La présence du paquet Playwright ne garantit pas celle du navigateur.

**`install.sh` n'est pas une procédure fiable dans cette copie.** Il contient des constructions Bash sans shebang, vise l'ancien dossier `core/`, puis tente de créer `core/__init__.py` sans créer son parent. Son mode `--no-venv` traite une commande avec arguments comme un seul nom d'exécutable. Consulter A02 dans l'audit avant de s'y fier.

## Points d'entrée

Les commandes d'aide et d'ouverture ci-dessous décrivent les entrées présentes ; elles n'ont pas été lancées pendant l'audit :

```bash
python main.py --help
python main.py scrape --help
python -m ui.ui
```

La TUI est un écran dédié au module offensif, pas une interface générale pour les fonctions HTTP. Elle affiche une cible, un port, des paramètres de travail et un panneau d'état rafraîchi toutes les 0,5 seconde. Le démarrage échoue dans cette copie à cause de l'import de `application.dos`. La documentation ne fournit pas de procédure pour remettre cet ancien module en service.

`ui/cli.py` contient un second constructeur de parseur, non utilisé par `main.py`. Ses choix `process` et `async` ne correspondent pas à des modes pris en charge par `WorkerPool`, qui accepte uniquement `thread`.

### Options de la CLI HTTP

| Argument | Défaut | Rôle dans le code |
| --- | --- | --- |
| `urls` | liste vide | URLs positionnelles |
| `--urls-file` | aucun | Ajout d'URLs depuis un fichier texte |
| `--proxies-file` | aucun | Liste de proxies |
| `--ua-file` | aucun | Liste de User-Agent |
| `--workers` | 4 | Nombre de threads ; la CLI impose au moins 1 |
| `--min-delay` | 0.4 | Borne basse du jitter |
| `--max-delay` | 2.5 | Borne haute du jitter |
| `--verbose` | désactivé | Diagnostic et affichage complémentaire |
| `--captcha-key` | aucune | Transmis au constructeur de la pile, pas au handler HTTP par défaut |
| `--captcha-service` | `capsolver` | Le parseur accepte aussi `2captcha` et `anticaptcha` ; ce dernier n'a pas d'implémentation dédiée |
| `--no-browser` | désactivé | Configure l'objet de gestion des protections, non utilisé par le handler de `fetch_many()` |
| `--no-tls` | désactivé | Même limite de câblage pour le chemin CLI HTTP |

Le handler par défaut effectue des GET avec `requests.Session` et un timeout de 20 secondes par appel. Il renvoie l'URL, le statut, une taille calculée avec `len(resp.text)` et l'identifiant du worker. Cette taille représente des caractères, pas des octets. La CLI affiche principalement une durée et des compteurs ; elle n'enregistre pas le contenu des pages.

Les compteurs `total_done` et `total_failed` décrivent actuellement l'issue du handler Python. Ils ne garantissent pas un succès HTTP : une réponse 404 ou une dernière réponse 503 peut être comptée comme une tâche terminée.

## API et chemins de traitement

`ScrapingStack` assemble les objets suivants : rotation des User-Agent, proxy optionnel, jitter, limiteur, backoff, fragmenter et gestionnaire de protections.

| Méthode | Chemin réel | Résultat |
| --- | --- | --- |
| `fetch`, `get`, `post` | `CaptchaWafBypass.request` | Réponse du transport, réponse synthétique navigateur, exception ou `None` selon le chemin |
| `fetch_many` | `WorkerPool` → handler → `BotContext.request` → `AdaptiveBackoff.request` | Dictionnaire de statistiques, listes de `Task` en succès/échec |
| `upload_chunked` | `RequestFragmenter.upload_in_chunks` | Liste de réponses |
| `paginate` | `RequestFragmenter.paginate` | Liste de réponses ; détection de fin actuellement défectueuse |
| `split_params` | `RequestFragmenter.split_params` | Réponses à des sous-ensembles des paramètres |
| `stats` | États de backoff et de rotation | Dictionnaire ; ce n'est pas une mesure exhaustive des requêtes |
| `close` | Fermeture du gestionnaire de protections | La session du fragmenter n'est pas fermée ici |

`fetch_many()` matérialise les URLs en liste et installe des gestionnaires de signaux. Son emploi dans un thread secondaire pose donc problème. Les résultats contiennent des objets `Task`, pas directement des objets JSON sérialisables.

### Temporisation et backoff

`DelayJitter` propose `uniform`, `gaussian`, `exponential`, `lognormal` et `human`, ainsi qu'une attente asynchrone. `RateLimiter` conserve des horodatages sous verrou, mais sa réservation des appels différés ne garantit pas la limite sous concurrence.

`AdaptiveBackoff` conserve un état par `netloc`, propose `aimd`, `simple`, `pid` et `adaptive`, et comporte un circuit breaker. Il sait lire un `Retry-After` numérique ou une date HTTP, mais le délai résultant est plafonné et soumis au jitter : le minimum demandé par le serveur n'est donc pas garanti. Les attentes ne prennent pas de signal d'annulation.

### Tâches et Redis

`WorkerPool` gère des threads, des nouvelles tentatives, des callbacks et des résultats en mémoire. `shard_by` calcule une clé dans chaque tâche ; aucun ordonnancement séparé par domaine n'utilise cette clé.

`RedisTaskQueue` est utilisable par injection dans `WorkerPool`. Il utilise des listes Redis avec retrait destructif : il n'existe ni acquittement, ni réservation temporaire, ni récupération automatique d'une tâche abandonnée après retrait. Les états et résultats du pool restent locaux au processus. Ce n'est pas un service distribué durable complet.

### Fragmentation et pagination

`upload_in_chunks()` sérialise le contenu puis envoie plusieurs requêtes portant `X-Chunk-Index` et `X-Chunk-Total`. Cela nécessite un serveur sachant interpréter ce protocole applicatif. Il n'y a pas d'identifiant de transfert ni de validation globale de réassemblage.

`stream_in_chunks()` utilise un générateur pour un seul envoi ; ce générateur n'est pas recréé lors des reprises. `split_params()` produit plusieurs requêtes indépendantes et ne préserve pas nécessairement le sens d'une requête comportant tous les filtres ensemble.

L'envoi asynchrone est séquentiel et renvoie des dictionnaires contenant statut et corps. Il n'applique pas les mêmes politiques que l'envoi synchrone. Avec un backoff injecté, le chemin synchrone court-circuite notamment le timeout du fragmenter et son limiteur.

### Intégrations de protections

Les modules contiennent des heuristiques de détection, des adaptateurs de services et des chemins navigateur/TLS. Leur présence ne prouve ni leur efficacité ni leur compatibilité avec des protections ou services actuels. Aucun appel à ces services n'a été effectué ou validé.

Le chemin navigateur produit une réponse synthétique dont le statut peut être déclaré 200 sans reprendre le véritable statut HTTP. Le chemin `post()` peut aussi répéter une opération après une réponse 201 ou 204. Ces comportements interdisent de considérer cette API comme un client HTTP transparent et fiable.

## Configuration

`config/settings.py` est vide. `ui/config.py` définit des constantes, mais `ui/ui.py` ne les importe pas. La TUI utilise les variables d'environnement `APP_NAME`, `VERSION` et `GITHUB_NAME` avec ses propres valeurs par défaut ; certains affichages restent codés en dur. La version `1.0.0` du fichier de configuration et la valeur `0.0.1` de la TUI ne sont pas une source de version unifiée.

## Tests et garanties

`test/test.py` est une démonstration à sockets simulés par défaut. Elle contient des impressions et des échecs aléatoires, sans assertions ni validation des modules applicatifs. Son mode réel comporte des contrôles de boucle locale dans le bloc principal seulement.

La revue a couvert les 27 fichiers Python hors environnement virtuel, le thème, l'installateur et les fichiers de documentation. Une lecture syntaxique par `ast.parse` a signalé une erreur dans `test/core/ddos.py`. Elle ne valide ni les imports, ni les bibliothèques, ni les interactions réseau. Aucun module du projet n'a été importé ou exécuté ; aucun test réseau, installation ou lancement de navigateur n'a été effectué.

La priorité de remise en qualité est détaillée dans [AUDIT.md](AUDIT.md) : retrait des garanties non établies, isolation des anciens scripts, respect des limites et erreurs HTTP, puis tests déterministes sans réseau. Aucun fichier de licence n'a été trouvé dans le périmètre examiné ; aucune licence n'est présumée.
