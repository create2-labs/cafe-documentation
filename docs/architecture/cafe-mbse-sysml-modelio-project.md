# Projet MBSE — Modelisation SysML de CAFE pour Modelio

**Statut :** projet documentaire executable pas a pas  
**Objectif :** construire un modele SysML/MBSE de CAFE exploitable dans Modelio  
**Perimetre initial :** CAFE system-of-systems, avec focus MVP sur Discovery, CPM, Persistence, Scanners, Frontend, Edge et Deploy  
**Sorties visees :** diagrams SysML, catalogue de blocs/interfaces, matrice exigences -> composants -> tests, guide d'import/reconstruction Modelio

---

## 0. Decision de format

Modelio peut etre utilise de plusieurs facons selon les modules disponibles et le niveau d'import attendu. Le projet garde donc deux niveaux de sortie :

| Niveau | Sortie | Usage |
| --- | --- | --- |
| Canonique | Markdown + tables + Mermaid/PlantUML SysML-like | Source lisible, reviewable en PR |
| Modelio | Modele reconstruit manuellement ou import XMI/UML profile si valide | Edition MBSE dans Modelio |

**Decision par defaut :** produire d'abord le modele canonique dans ce repo, puis seulement ensuite choisir l'option Modelio la plus fiable.

---

## 1. Reperes projet

### Repositories source

| Repository | Role dans le modele |
| --- | --- |
| `cafe-documentation` | Documentation produit/technique et modele canonique |
| `cafe-discovery` | API Discovery, auth, scan orchestration, pending/read/delete, Redis/Postgres/NATS |
| `cafe-crypto-policy-mgt` | CPM API, policy decisions, drafts, persist, scan authorization |
| `cafe-persistence` | Stockage long terme des scans et evenements |
| `cafe-scanner-wallet` | Worker scan wallet/EVM |
| `cafe-scanner-tls` | Worker scan TLS/PQC |
| `cafe-frontend` | SPA utilisateur, Discovery, CPM graph workspace |
| `cafe-deploy` | Compose, edge, smokes, scripts operatoires |
| `cafe-expresso` | Kubernetes/minikube/Helm/Argo CD |
| `cafe-edge` | Reverse proxy / edge routing / PQC TLS |
| `cafe-contracts` | Types partages et contrats wire |

### Documents d'entree

| Document | Usage |
| --- | --- |
| `functional-specifications.md` | Exigences fonctionnelles, workflows, user stories |
| `technical-specifications.md` | Architecture, services, APIs, persistence, messaging |
| `03-cafe-developer-guide.md` | Routes API, contrats HTTP, smokes developpeur |
| `04-cafe-admin-guide.md` | Operations, deploiement, diagnostic |
| `docs/architecture/cpm-v1-flow.md` | Flow Discovery -> CPM |
| `docs/security/cpm-contract.md` | AuthN/AuthZ CPM, contrats securite |
| `docs/security/cp-persist-v1.md` | Persist EOA, wallet proof |

---

## 2. Arborescence cible

Les livrables MBSE seront ranges sous :

```text
docs/architecture/mbse/
  00-modeling-conventions.md
  01-system-context.md
  02-requirements.md
  03-logical-architecture.md
  04-runtime-architecture.md
  05-interfaces.md
  06-behavior-flows.md
  07-state-machines.md
  08-traceability.md
  09-modelio-guide.md
```

Cette page est le plan d'execution. Les fichiers ci-dessus seront crees progressivement.

---

## 3. Definition of Done globale

Le projet MBSE est considere comme utilisable quand :

- [ ] les frontieres systeme CAFE sont explicites ;
- [ ] les acteurs et systemes externes sont identifies ;
- [ ] les blocs principaux CAFE sont modelises ;
- [ ] les interfaces entre blocs sont decrites ;
- [ ] les flows critiques sont modelises ;
- [ ] le cycle de vie d'un scan est modelise ;
- [ ] les exigences principales sont tracees vers composants et tests ;
- [ ] le modele peut etre reconstruit dans Modelio avec une convention stable ;
- [ ] les diagrammes sont reviewables en Markdown avant saisie/import Modelio.

---

## 4. Execution pas a pas

### Phase 1 — Cadrage MBSE

**But :** definir comment on modelise CAFE avant de produire les diagrammes.

**Actions :**

- [ ] Creer `docs/architecture/mbse/00-modeling-conventions.md`
- [ ] Choisir les stereotypes utilises : `system`, `subsystem`, `service`, `external`, `database`, `message_bus`, `api`, `worker`
- [ ] Definir la convention de nommage des blocs, ports et interfaces
- [ ] Definir le mapping SysML -> Modelio

**Livrable minimal :**

```text
Block: CafeSystem
Stereotype: system
Description: Crypto-Agility Framework for Ethereum.
```

**Critere d'acceptation :**

- [ ] un reviewer peut creer les memes blocs dans Modelio sans interpretation personnelle.

---

### Phase 2 — Contexte systeme

**But :** modeliser CAFE dans son environnement.

**Actions :**

- [ ] Creer `01-system-context.md`
- [ ] Identifier acteurs humains : user, admin, operator, developer, auditor
- [ ] Identifier systemes externes : wallet provider, Ethereum RPC, TLS endpoints, browser, CI/CD, observability
- [ ] Produire un diagramme de contexte

**Blocs attendus :**

| Bloc | Type |
| --- | --- |
| `CafeSystem` | system |
| `CafeFrontend` | subsystem |
| `CafeEdge` | subsystem |
| `CafeDiscovery` | subsystem |
| `CafeCPM` | subsystem |
| `CafePersistence` | subsystem |
| `CafeScannerWallet` | worker |
| `CafeScannerTLS` | worker |
| `EthereumRPC` | external |
| `WalletProvider` | external |
| `TLSEndpoint` | external |

**Critere d'acceptation :**

- [ ] le diagramme montre clairement ce qui est dans CAFE et ce qui est externe.

---

### Phase 3 — Exigences

**But :** transformer les specs en exigences MBSE tracables.

**Actions :**

- [ ] Creer `02-requirements.md`
- [ ] Extraire les exigences depuis les specs fonctionnelles et techniques
- [ ] Classer les exigences : functional, security, operations, data, API contract, compliance
- [ ] Attribuer un identifiant stable : `REQ-CAFE-001`, `REQ-SEC-001`, etc.

**Exemples d'exigences initiales :**

| ID | Type | Exigence |
| --- | --- | --- |
| `REQ-CAFE-001` | functional | CAFE doit permettre a un utilisateur authentifie de lancer un scan wallet. |
| `REQ-CAFE-002` | functional | CAFE doit permettre a un utilisateur authentifie de lancer un scan TLS. |
| `REQ-SEC-001` | security | Les donnees de scan utilisateur doivent etre owner-scoped. |
| `REQ-API-001` | API contract | Les routes publiques v1 doivent conserver leurs status HTTP et schemas JSON. |
| `REQ-OPS-001` | operations | Les services doivent exposer des endpoints de health/version/smoke. |

**Critere d'acceptation :**

- [ ] chaque exigence importante a un ID stable et une source documentaire.

---

### Phase 4 — Architecture logique

**But :** produire le BDD principal de CAFE.

**Actions :**

- [ ] Creer `03-logical-architecture.md`
- [ ] Decrire les blocs systeme et sous-systemes
- [ ] Decrire les responsabilites de chaque bloc
- [ ] Identifier les dependances logiques

**BDD attendu :**

```text
CafeSystem
  contains CafeFrontend
  contains CafeEdge
  contains CafeDiscovery
  contains CafeCPM
  contains CafePersistence
  contains CafeScannerWallet
  contains CafeScannerTLS
  contains CafeContracts
```

**Critere d'acceptation :**

- [ ] chaque repository principal a une place explicite dans le modele.

---

### Phase 5 — Architecture runtime / deploiement

**But :** modeliser les connexions d'execution.

**Actions :**

- [ ] Creer `04-runtime-architecture.md`
- [ ] Modeliser Edge -> Discovery / CPM
- [ ] Modeliser Discovery -> NATS / Redis / Postgres / Persistence / Scanners
- [ ] Modeliser CPM -> Discovery / Persistence / Postgres
- [ ] Identifier les variantes Compose et Kubernetes

**Connexions attendues :**

| Source | Interface | Cible |
| --- | --- | --- |
| `CafeFrontend` | HTTPS API | `CafeEdge` |
| `CafeEdge` | `/api/discovery/v1` | `CafeDiscovery` |
| `CafeEdge` | `/api/cpm/v1` | `CafeCPM` |
| `CafeDiscovery` | NATS events | `NATS` |
| `CafeScannerWallet` | NATS consume/publish | `NATS` |
| `CafeScannerTLS` | NATS consume/publish | `NATS` |
| `CafePersistence` | Postgres write/read | `Postgres` |
| `CafeDiscovery` | Redis cache | `Redis` |

**Critere d'acceptation :**

- [ ] un operateur peut reconnaitre le deploiement Compose/Kubernetes dans le diagramme.

---

### Phase 6 — Interfaces

**But :** formaliser les ports et contrats entre blocs.

**Actions :**

- [ ] Creer `05-interfaces.md`
- [ ] Lister APIs HTTP publiques et internes
- [ ] Lister messages NATS
- [ ] Lister dependances storage/cache
- [ ] Associer chaque interface a un owner

**Interfaces initiales :**

| Interface | Owner | Consumers |
| --- | --- | --- |
| `DiscoveryV1API` | `CafeDiscovery` | `CafeFrontend`, `CafeCPM` |
| `CPMV1API` | `CafeCPM` | `CafeFrontend` |
| `ScanQueueEvents` | `CafeDiscovery` | `CafeScannerWallet`, `CafeScannerTLS` |
| `ScanReadyEvents` | `CafeScanner*` / `CafePersistence` | `CafeDiscovery`, `CafeCPM` |
| `PolicyDecisionAPI` | `CafeCPM` | `CafeFrontend` |

**Critere d'acceptation :**

- [ ] chaque fleche runtime a une interface nommee.

---

### Phase 7 — Comportements critiques

**But :** modeliser les flows qui portent le risque produit.

**Actions :**

- [ ] Creer `06-behavior-flows.md`
- [ ] Modeliser signup/signin
- [ ] Modeliser wallet scan
- [ ] Modeliser TLS scan
- [ ] Modeliser Discovery scan -> CPM explore
- [ ] Modeliser platform draft -> wallet challenge -> persist
- [ ] Modeliser delete scan / ownership checks

**Flows MVP :**

| Flow | Diagramme cible |
| --- | --- |
| `AuthFlow` | sequence/activity |
| `WalletScanFlow` | sequence/activity |
| `TLSScanFlow` | sequence/activity |
| `CPMExploreFlow` | sequence/activity |
| `CPPersistV1Flow` | sequence/activity |
| `ScanDeleteFlow` | sequence/activity |

**Critere d'acceptation :**

- [ ] les flows permettent de verifier les contrats d'API et les points AuthN/AuthZ.

---

### Phase 8 — Etats

**But :** modeliser le cycle de vie des objets metier importants.

**Actions :**

- [ ] Creer `07-state-machines.md`
- [ ] Modeliser cycle de vie d'un scan
- [ ] Modeliser cycle de vie d'un policy draft
- [ ] Modeliser cycle de vie d'un persisted policy

**State machine scan initiale :**

```text
Requested -> Queued -> Running -> Completed
Requested -> Queued -> Running -> Failed
Requested -> Pending -> Deleted
Completed -> Deleted
Failed -> Deleted
```

**Critere d'acceptation :**

- [ ] chaque transition a un evenement ou une API associee.

---

### Phase 9 — Tracabilite

**But :** rendre le modele utile pour les reviews et audits.

**Actions :**

- [ ] Creer `08-traceability.md`
- [ ] Relier exigences -> blocs -> interfaces -> tests
- [ ] Relier risques -> mitigations -> smokes
- [ ] Relier contrats HTTP -> routes -> repositories sources

**Matrice minimale :**

| Requirement | Blocks | Interfaces | Verification |
| --- | --- | --- | --- |
| `REQ-CAFE-001` | `CafeFrontend`, `CafeDiscovery`, `CafeScannerWallet`, `CafePersistence` | `DiscoveryV1API`, `ScanQueueEvents` | wallet scan smoke |
| `REQ-SEC-001` | `CafeDiscovery`, `CafeCPM` | `DiscoveryV1API`, `CPMV1API` | authz tests, owner-scope tests |
| `REQ-OPS-001` | `CafeDiscovery`, `CafeCPM`, `CafeEdge` | health/version endpoints | deploy smoke |

**Critere d'acceptation :**

- [ ] au moins les exigences MVP sont tracees jusqu'a une verification.

---

### Phase 10 — Guide Modelio

**But :** permettre la reconstruction/import du modele dans Modelio.

**Actions :**

- [ ] Creer `09-modelio-guide.md`
- [ ] Documenter le package tree Modelio
- [ ] Documenter les stereotypes et couleurs/conventions
- [ ] Documenter l'ordre de creation des diagrammes
- [ ] Tester une reconstruction manuelle du MVP
- [ ] Evaluer si XMI est utile ou trop fragile

**Package tree Modelio propose :**

```text
CAFE
  00_Context
  01_Requirements
  02_LogicalArchitecture
  03_RuntimeArchitecture
  04_Interfaces
  05_Behavior
  06_StateMachines
  07_Traceability
```

**Critere d'acceptation :**

- [ ] un nouveau contributeur peut reconstruire le MVP dans Modelio en suivant le guide.

---

## 5. MVP recommande

Le premier increment doit rester petit et utile.

**MVP MBSE CAFE :**

- [ ] conventions de modelisation ;
- [ ] contexte systeme ;
- [ ] BDD logique principal ;
- [ ] IBD runtime principal ;
- [ ] wallet scan flow ;
- [ ] TLS scan flow ;
- [ ] CPM explore/persist flow ;
- [ ] scan lifecycle state machine ;
- [ ] matrice de tracabilite minimale.

**Hors MVP :**

- [ ] modelisation exhaustive de toutes les routes ;
- [ ] generation XMI automatique ;
- [ ] simulation comportementale ;
- [ ] model checking formel ;
- [ ] vues detaillees de chaque package Go.

---

## 6. Ordre d'execution conseille

1. Creer `00-modeling-conventions.md`
2. Creer `01-system-context.md`
3. Creer `03-logical-architecture.md`
4. Creer `04-runtime-architecture.md`
5. Creer `05-interfaces.md`
6. Creer `06-behavior-flows.md`
7. Creer `07-state-machines.md`
8. Creer `02-requirements.md`
9. Creer `08-traceability.md`
10. Creer `09-modelio-guide.md`

Cette sequence commence par la comprehension systeme, puis stabilise les exigences et la tracabilite quand les blocs et interfaces sont deja nommes.

---

## 7. Commandes de collecte utiles

Depuis `/Users/mboleg/dev/github/create2-labs` :

```bash
rg --files cafe-* | rg 'README|docs|openapi|workplans|TODO|go.mod|docker-compose|helm|values|routes|handler|nats|contract'
```

Par repository :

```bash
rg -n "GET |POST |DELETE |PUT |/api/|NATS|Subject|scan.ready|scan.requested|version|health" cafe-discovery cafe-crypto-policy-mgt cafe-persistence cafe-deploy
```

Pour les modules Go :

```bash
find . -maxdepth 3 -name go.mod -print
```

Pour les contrats HTTP :

```bash
rg -n "app\\.|router\\.|HandleFunc|Group\\(|Post\\(|Get\\(|Delete\\(" cafe-discovery cafe-crypto-policy-mgt
```

---

## 8. Regles de review

- Chaque fichier MBSE doit etre reviewable seul.
- Un diagramme ne doit pas melanger contexte, logique, runtime et comportement.
- Chaque bloc doit avoir une responsabilite courte.
- Chaque interface doit avoir un owner.
- Chaque flow critique doit montrer les decisions AuthN/AuthZ.
- Aucun diagramme ne doit inventer une API ou un service non present dans les repos sans le marquer `proposed`.
- Les divergences entre modele et code doivent etre notees comme questions ouvertes, pas masquees.

---

## 9. Questions ouvertes

- Faut-il produire un export XMI ou rester sur une reconstruction Modelio documentee ?
- Quel module SysML exact est installe dans Modelio ?
- Souhaite-t-on modeliser CAFE comme un seul system-of-systems ou comme trois produits : Discovery, CPM, Remediation ?
- Les vues Kubernetes doivent-elles etre MVP ou phase 2 ?
- Les exigences compliance doivent-elles rester descriptives ou devenir des `requirements` SysML tracables ?

---

## 10. Prochaine action

Creer le premier livrable :

```text
docs/architecture/mbse/00-modeling-conventions.md
```

Contenu minimal attendu :

- stereotypes ;
- conventions de nommage ;
- conventions de diagrammes ;
- mapping SysML -> Modelio ;
- definition de "source canonique" ;
- definition de "proposed" vs "implemented".
