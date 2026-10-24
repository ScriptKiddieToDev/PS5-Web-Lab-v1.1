# PS5 Web Lab — rapporto aggiornamenti e avvio

**Percorso progetto:** `/tmp/ps5-test`  
**Data rapporto:** 25 ottobre 2026  
**Scopo:** inventario delle funzioni presenti e guida per ricreare una seconda repository.

> Il rapporto descrive i file e le funzioni presenti al momento dell'ispezione. La directory principale `/tmp/ps5-test` non contiene `.git`; non è quindi possibile ricostruire un diff completo o attribuire con certezza ogni file a una specifica revisione. Esiste invece una repository Git annidata in `Chiral-FTP/`.

## 1. Architettura

Il progetto contiene un laboratorio web servito dal PC, una dashboard browser, un server separato per trasferire file dal PC e un server facoltativo per le fixture cross-origin.

| Componente | File di avvio | Porta predefinita | Funzione |
|---|---|---:|---|
| Web Lab e backend | `start_server.sh` → `server.py` | 8000 | Dashboard, pagine statiche, API eventi, catalogo e dossier |
| Trasferimento locale | `tools/local-transfer-server.py` | 8765 | Pagina di trasferimento autenticata e accesso alla cartella PC selezionata |
| Fixture Canvas cross-origin (facoltativo) | `canvas-cross-origin-server.py` | 8001 | Serve solo un'immagine sintetica di test e, se configurato, un header CORS esatto |

Il browser PS5 è un client web. Il server sulla porta 8000 gira sul PC; il server sulla porta 8765 gira anch'esso sul PC e inoltra dashboard e API al primo server, mantenendo disponibili le API di trasferimento sulla stessa origine del browser.

## 2. Dashboard e pagine

`dashboard.html` è l'hub. Carica dinamicamente gli elementi HTML disponibili in `pages/`, mostra il Security Analysis Center, offre l'accesso al laboratorio e incorpora la pagina di trasferimento. Il Security Analysis Center legge gli eventi storici in sola lettura e permette filtri ed esportazione.

| Pagina | Scopo |
|---|---|
| `pages/active-vulnerability-research-lab.html` | Suite Canvas/Web IDL, bitmap, Blob URL e origin-clean; ripetizioni e fuzz deterministico limitato a 100 casi; snippet isolato; importazione manuale di JavaScript, anteprima, hash e risultati esportabili. |
| `pages/canvas-security-impact.html` | Misura impatti Canvas, opzioni del contesto, comportamento dei pixel e prove controllate su origine e sicurezza del canvas. |
| `pages/vulnerability-scanner.html` | Diagnostica di capacità/API e confronto di evidenze con un catalogo CVE; il firmware dichiarato e l'user agent non attestano il modello o la build del browser. |
| `pages/browser.html` | Pagina di navigazione semplice con barra indirizzi e pulsante **Cerca**. Supporta navigazione HTTP/HTTPS e ricerca testuale; non è un client FTP/SFTP e non esegue JavaScript trasferito in modo autonomo. |
| `pages/local-transfer.html` | Navigazione, download e upload nella sola cartella configurata per il server di trasferimento. Richiede il token generato all'avvio del server. |
| `pages/canvas-reentrancy-audit.html` | Audit focalizzato sulle opzioni Canvas e sulla rientranza dei getter. |
| `pages/bitmaprenderer-options-check.html` | Controllo mirato delle opzioni di `bitmaprenderer`. |
| `pages/context-options.html`, `pages/context-options-diagnostic.html` | Prove e diagnostica per opzioni di `getContext()`. |
| `pages/features.html`, `pages/hardware-check.html`, `pages/net-check.html`, `pages/worker-check.html` | Diagnostica delle API, dell'ambiente dichiarato, della rete locale e dei Worker. |
| `pages/p166.html`, `pages/p166-desync.html` | Prove Canvas/identity e desincronizzazione collegate ai controlli precedenti. |
| `pages/home-page-originale.html` | Pagina originale conservata nel progetto. |

La pagina `pages/browser.html` non è un browser completo e non implementa protocolli diversi da HTTP/HTTPS. Per esempio, un URL `sftp://` deve essere aperto da un client SFTP nativo; una pagina web non può creare direttamente una connessione SFTP.

## 3. Analisi, registrazione ed esportazione

- `pages/active-vulnerability-research-lab-core.js` e `pages/active-vulnerability-research-lab.js` contengono catalogo dei casi e logica della suite.
- `pages/canvas-security-impact-core.js` e `pages/canvas-security-impact.js` implementano i casi Canvas e la registrazione degli eventi.
- `pages/vulnerability-scanner-core.js` e `pages/vulnerability-scanner.js` implementano controlli, catalogo e interfaccia scanner.
- `pages/research-transfer-core.js` e `pages/research-transfer.js` condividono l'importazione manuale dal trasferimento, anteprima, hash, esecuzione esplicita ed esportazione/upload dei risultati.
- Gli snippet importati dal runner attuale vengono eseguiti in un worker isolato, con rete e DOM non disponibili. L'importazione non esegue automaticamente il file.
- I quattro strumenti JavaScript aggiunti sono in `research-payloads/`: `probe-canvas-alpha.js`, `probe-canvas-reentrancy.js`, `probe-bitmap-lifecycle.js`, `probe-canvas-origin-clean.js`.
- I primi tre payload usano API Canvas nel contesto Worker, se disponibili. `probe-canvas-origin-clean.js` richiede un'immagine fixture locale e un contesto con `document`/`Image`; nel runner Worker corrente restituisce `SKIPPED` e non effettua richieste di rete.
- `server.py` gestisce `/api/health`, `/api/scan-log`, `/api/analysis-events` e gli endpoint del catalogo. I risultati delle campagne vengono scritti in `logs/` in JSONL, JSON summary e Markdown. Il Security Analysis Center legge gli eventi storici senza riscrivere i log.
- `data/cve-catalog.json` è il catalogo locale; `data/canvas-cross-origin.png` è la fixture sintetica. L'aggiornamento NVD è un'azione esplicita dello scanner e richiede accesso Internet dal PC.
- `VULNERABILITY_SCANNER.md` documenta API, logging, catalogo e verifiche del backend.

Le osservazioni sono diagnostiche: non confermano da sole vulnerabilità, CVE, accesso a memoria nativa o escape della sandbox.

## 4. File di supporto al trasferimento

`tools/local-transfer-server.py` espone una sola cartella root selezionata con `--root`. Per impostazione predefinita è `$HOME/PS5-Transfer`; crea la cartella se manca. Il server:

- genera un token nuovo a ogni avvio;
- richiede il token nelle API di list/download/upload;
- consente scrittura se avviato senza `--read-only`;
- limita gli upload a 128 MiB e impedisce sovrascritture di file esistenti;
- rifiuta percorsi fuori dalla root condivisa;
- inoltra dashboard e pagine al backend principale sulla porta indicata da `PS5_WEB_LAB_PORT` (8000 per impostazione predefinita).

Il token viaggia su HTTP. Usa il servizio solo su una rete locale fidata e non esporlo a Internet. Non inserire il token nei report o negli URL.

## 5. Avvio dei server

### Terminale 1 — Web Lab (porta 8000)

```bash
cd /tmp/ps5-test
./start_server.sh
```

Lo script usa `PS5_WEB_LAB_HOST=0.0.0.0` e `PS5_WEB_LAB_PORT=8000` per impostazione predefinita. Controlla che la porta non sia già occupata e rifiuta di avviare una seconda istanza. Interrompi con `Ctrl+C` nel terminale che lo sta eseguendo.

URL diretti:

- PC: `http://127.0.0.1:8000/dashboard.html`
- PS5: `http://IP_LAN_DEL_PC:8000/dashboard.html`
- Pagina scanner: `http://IP_LAN_DEL_PC:8000/pages/vulnerability-scanner.html`
- Pagina browser: `http://IP_LAN_DEL_PC:8000/pages/browser.html`

Sulla PS5 non usare `localhost` o `127.0.0.1`: identificherebbero la console. Sostituisci `IP_LAN_DEL_PC` con l'indirizzo LAN effettivo del PC.

### Terminale 2 — Trasferimento file (porta 8765)

```bash
cd /tmp/ps5-test
python3 tools/local-transfer-server.py --root "$HOME/PS5-Transfer" --bind 0.0.0.0
```

Il processo stampa gli indirizzi LAN e il token temporaneo. Tienilo aperto mentre usi trasferimento o importazione dal runner. La cartella condivisa deve contenere gli snippet che si vogliono importare; per esempio:

```bash
cp /tmp/ps5-test/research-payloads/*.js "$HOME/PS5-Transfer/"
```

URL dalla PS5:

- Dashboard inoltrata: `http://IP_LAN_DEL_PC:8765/dashboard`
- Pagina trasferimento: `http://IP_LAN_DEL_PC:8765/pages/local-transfer.html`
- Pagina browser: `http://IP_LAN_DEL_PC:8765/pages/browser.html`

La pagina di trasferimento richiede il token mostrato dal processo. Nel laboratorio, usa il pannello di importazione per selezionare un file dalla cartella condivisa, controllarne contenuto e SHA-256 e avviare l'esecuzione solo dopo conferma.

### Server fixture facoltativo (porta 8001)

Solo per prove cross-origin che richiedono la fixture locale:

```bash
cd /tmp/ps5-test
python3 canvas-cross-origin-server.py --host 0.0.0.0 --port 8001
```

Il server espone esclusivamente la PNG sintetica su `/canvas-cross-origin.png`. Per un controllo CORS positivo, aggiungere `--allow-origin` con l'origine esatta aperta nel browser, ad esempio `http://IP_LAN_DEL_PC:8000` oppure `http://IP_LAN_DEL_PC:8765`, in base all'URL utilizzato. Fermare anche questo processo con `Ctrl+C` al termine.

### Cambio della porta principale

Se la porta 8000 è occupata e si sceglie deliberatamente una porta diversa, usare la stessa variabile in entrambi i terminali, per esempio `8080`:

```bash
PS5_WEB_LAB_PORT=8080 ./start_server.sh
```

```bash
PS5_WEB_LAB_PORT=8080 python3 tools/local-transfer-server.py --root "$HOME/PS5-Transfer" --bind 0.0.0.0
```

Il server di trasferimento resta sulla porta 8765; `/dashboard` inoltra al backend sulla porta 8080.

## 6. Importazione dei quattro payload

1. Copiare i file in `$HOME/PS5-Transfer/` come mostrato sopra.
2. Aprire sulla PS5 `http://IP_LAN_DEL_PC:8765/dashboard`.
3. Aprire **Active Vulnerability Research Lab**.
4. Connettere il trasferimento con il token del processo corrente.
5. Selezionare il file nel pannello di importazione, premere **Importa e mostra**, leggere il contenuto e poi premere **Esegui test importato**.
6. Ripetere per ciascun payload e scaricare/esportare i risultati desiderati.

L'importazione non legge la memoria della PS5 né esegue codice dentro Chiral-FTP. I test vengono eseguiti dal browser del Web Lab. Il payload origin-clean richiede invece una fixture e un profilo con DOM; nella modalità Worker importata corrente rimane `SKIPPED`. Per provare origin-clean nel laboratorio, usare il caso integrato D1 con il server fixture attivo.

## 7. Chiral-FTP incluso

Il checkout sorgente Chiral-FTP, inclusa la sua `.git`, è stato spostato fuori dal progetto nell'archivio `/home/IBM/ps5-test-cleanup-archive-20261025/Chiral-FTP-source/`. I suoi artefatti rigenerabili (`.build/`, `.deps/`, eseguibile Linux compilato) e il file root `chiral-ftp-1.1-x86_64.AppImage` sono conservati in `/home/IBM/ps5-test-cleanup-archive-20261025/build-artifacts/`. Chiral-FTP è un'app separata, non uno dei server Web Lab: trasferire un file con Chiral-FTP non lo esegue nel browser. La sua licenza è GPL-3.0.

Link ufficiali per installazione e download:

- [Istruzioni PS5 nel README ufficiale](https://github.com/Herbrax/Chiral-FTP#ps5)
- [Release ufficiali di Chiral-FTP](https://github.com/Herbrax/Chiral-FTP/releases)

Il README indica come prerequisiti una PS5 jailbroken, ShadowMountPlus e un ELF loader `elfldr` in ascolto sulla porta 9021 per l'accesso completo allo storage; dichiara il test su firmware 13.60. Non dà conferma di compatibilità con firmware 14.10. Consultare le istruzioni e le note della release corrente prima di procedere.

## 8. Preparazione di una seconda repository

La root del progetto non ha una cronologia Git propria. Per creare una nuova repository, copiare le sorgenti applicative e verificare separatamente gli artefatti locali. In genere includere:

- `dashboard.html`, `dashboard-security-center.js`, `server.py`, `start_server.sh`;
- `pages/` e `research-payloads/`;
- `tools/local-transfer-server.py`, `canvas-cross-origin-server.py`;
- `data/cve-catalog.json` e `data/canvas-cross-origin.png`;
- `tests/`, `VULNERABILITY_SCANNER.md` e questo rapporto.

Il file `.gitignore` esclude cache Python, bytecode, log generati, backup, eventuale checkout Chiral-FTP ripristinato e AppImage. Il checkout Chiral-FTP, le cache, i backup e gli artefatti compilati rimossi dal progetto sono stati conservati fuori dalla repository in `/home/IBM/ps5-test-cleanup-archive-20261025/`; non sono stati cancellati permanentemente. `reports/` conserva i report e le istruzioni distinti; non sono duplicati. Non copiare token di sessione o file `.env` se ne esistono fuori dall'inventario.

L'eventuale trasferimento di Chiral-FTP nella nuova repository va deciso a parte: il suo `.git` annidato è una storia distinta, e la sua licenza è GPL-3.0.

## 9. Verifiche e limiti noti

- Per i quattro payload: `node --check` è passato su tutti i file; esecuzione con API Canvas simulate ha prodotto output JSON parsabile. Non è stato eseguito alcun payload sulla PS5 in questa verifica.
- La compatibilità effettiva con il browser della console richiede l'esecuzione sul dispositivo; risultati ottenuti su Node o altri browser non dimostrano compatibilità PS5.
- Il server principale e quello di trasferimento richiedono processi/terminali distinti. Il server fixture è un terzo processo facoltativo.
- L'indirizzo IP LAN può cambiare. La porta 8765 richiede il token; la porta 8000 serve le pagine e le API Web Lab.
- `pages/browser.html` è solo un launcher web HTTP/HTTPS, non supporta `sftp://` e non è un proxy.
