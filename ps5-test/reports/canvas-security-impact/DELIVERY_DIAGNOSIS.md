# Diagnosi riproducibile della regressione di consegna

## Risultato prima della correzione

La causa riprodotta è la perdita della coda quando l'istanza JavaScript della pagina viene ricaricata o ricreata. In `pages/canvas-security-impact.js`, `pendingEvents` era inizializzato come array locale vuoto (`var pendingEvents = []`) e non veniva serializzato in storage. Gli eventi sopravvivevano solo finché restava viva quella pagina.

### Riproduzione controllata

Comando eseguito prima di modificare il controller:

```text
REPRODUCE_RELOAD=1 node tests/test_canvas_security_impact_ui.js
```

Esito osservato:

```text
REPRODUCTION: offline page had 38 pending events; after controller reload, events delivered=0; persistence=Backend verificato · nessun risultato inviato
```

Il test ha eseguito la campagna nel mock UI, mantenuto il backend offline, ricreato il controller della pagina e poi ripristinato il backend. La seconda istanza non ha ritrovato né inviato i 38 eventi. Questa è una riproduzione del lifecycle client in VM, non una prova eseguita sulla PS5.

## Verifica del protocollo e del backend

- HTML carica `/pages/canvas-security-impact-core.js` e `/pages/canvas-security-impact.js` con path assoluti; il client usa l'origin della pagina.
- Health: `GET <origin>/api/health`, `Accept: application/json`; il client richiede HTTP 200, JSON, servizio `PS5-Web-Lab`, API 1 e `postEndpoint: /api/scan-log`.
- Log: `POST <origin>/api/scan-log`, `Content-Type: application/json`, `Accept: application/json`.
- L'envelope client è `{eventId,eventType,sessionId,clientTime,payload}`. Tipi e campi del risultato prodotto da `Core.toScannerResult()` corrispondono a `EVENT_TYPES` e `validate_result()` nel backend.
- Backend: HTTP 201 per evento nuovo; HTTP 200 e `duplicate:true` per ID già persistito. Entrambe le risposte includono `ok:true` e `saved:true`. Il client rimuoveva l'evento solo dopo status 200/201, Content-Type JSON e questi campi nel corpo. 4xx/5xx, JSON malformato e rete non rimuovevano l'evento e fermavano la coda.
- I log storici successivi mostrano che il server ha persistito eventi Canvas in sette sessioni parziali: da `scan-20261024-040058-aeea8e816dd9.jsonl` a `scan-20261024-041756-9fa566fb9b66.jsonl` risultano 24–29 `test_result` per sessione, senza `scan_complete` o `session_summary`. Ciò prova che alcuni POST sono arrivati e sono stati salvati; non prova che ogni POST abbia ricevuto una risposta dal browser e non identifica il momento in cui quelle pagine sono state chiuse/ricaricate.
- Le righe accettate non superano `MAX_EVENT_BYTES` (256 KiB); la dimensione massima misurata fra gli eventi `test_result` storici è 5.268 byte. Il formato non presenta un mismatch con lo schema del backend.
- `sessionStartedAt` e `sessionFrozen` forniscono metadati coerenti durante una singola istanza. Non preservavano però la coda fra istanze. La pagina non leggeva né modificava la chiave del vecchio scanner.

## Conclusione

La causa dimostrata è una coda solo volatile, non una discrepanza di endpoint, header o schema. Se l'utente lasciava o ricaricava la pagina prima che la coda fosse confermata, gli eventi non ancora inviati venivano abbandonati; la nuova pagina mostrava una coda vuota. La correzione mantiene il protocollo esistente e aggiunge persistenza isolata per la sola coda Canvas, conservando gli ID evento fino alla conferma `saved:true`.

Gli artefatti originali in `logs/` sono stati letti soltanto. I loro hash iniziali sono stati acquisiti prima dei test di regressione e non devono essere alterati dalla correzione.

## Correzione e verifica successiva

Il controller ora salva la coda prima di inviare e la ripristina quando la pagina viene ricreata, usando esclusivamente `ps5-web-lab.canvas-impact.pending-events.v1`. La chiave del vecchio scanner non viene interrogata. HTTP 200/201 non basta da solo: il client richiede JSON con `ok:true`, `saved:true` e lo stesso `eventType`; ogni errore mantiene l'evento e mostra ID, URL, metodo, stato/errore e, per risposte JSON di errore, il messaggio backend. Un retry riusa l'ID originale, così la deduplicazione lato server copre anche la risposta persa dopo una scrittura riuscita.

La simulazione UI successiva verifica il ripristino della coda e l'invio dopo health valido, 404/413/500, offline, HTML, JSON malformato, `saved:false`, `eventType` errato, storage disabilitato e risposta di rete persa dopo persistenza. Tutti questi casi hanno esito atteso. Le verifiche non usano socket e non sostituiscono un test HTTP reale sulla LAN o la prova PS5.

## Discrepanza dell'inventario dei log

Il primo inventario read-only di questa sessione conteneva `.gitkeep`, i sei artefatti delle due sessioni iniziali e sette JSONL parziali con timestamp fra `040058` e `041756`. Alla verifica finale quei file non erano più presenti; `logs/` conteneva `.gitkeep` e la sessione completa `scan-20261024-042209-cf72fad00bda` (JSONL, riepilogo e Markdown). Non ho cancellato, spostato o ripristinato alcuno di questi file. L'ispezione del teardown mostra che `test_workspace_log_path...` crea e rimuove soltanto il proprio singolo JSONL con token casuale, e gli altri test usano directory temporanee; non spiega la scomparsa degli artefatti precedenti. La causa della variazione resta indeterminata. Pertanto non dichiaro che l'intero inventario storico osservato all'inizio sia rimasto integro: gli artefatti presenti alla verifica finale non sono stati modificati dal client Canvas.
