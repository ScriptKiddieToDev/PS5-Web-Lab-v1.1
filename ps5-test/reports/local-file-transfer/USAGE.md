# Trasferimento file locale

Il server espone una sola cartella scelta all'avvio. La pagina permette di esplorarla, scaricare file, caricare file e creare sottocartelle. Non offre cancellazione o sovrascrittura.

## Avvio sul computer

Dal progetto:

```sh
python3 tools/local-transfer-server.py --root "$HOME/PS5-Transfer"
```

La cartella viene creata se manca. Apri nel browser `http://127.0.0.1:8765/pages/local-transfer.html` e inserisci il token mostrato nel terminale.

## Dashboard e trasferimento sulla stessa porta

Lascia attivo il server principale del laboratorio sulla porta 8000 e avvia il server di trasferimento in un secondo terminale. Quest'ultimo inoltra dashboard, file statici e API del laboratorio, mentre gestisce localmente le API per i trasferimenti.

```sh
cd /tmp/ps5-test
./start_server.sh
```

In un altro terminale:

Avvia il server di trasferimento esponendo la cartella che vuoi trasferire:

```sh
python3 tools/local-transfer-server.py --root "$HOME/PS5-Transfer" --bind 0.0.0.0
```

Il server di trasferimento inoltra dashboard, pagine e API del PS5 Web Lab dal server principale sulla porta `PS5_WEB_LAB_PORT` (predefinita 8000). Il terminale stampa gli indirizzi di rete disponibili. Dal dispositivo puoi aprire `http://INDIRIZZO:8765/dashboard` per la dashboard oppure `http://INDIRIZZO:8765/pages/local-transfer.html` per i trasferimenti. Inserisci il token solo nella pagina di trasferimento. Puoi indicare un'altra cartella con `--root`, ad esempio `--root "$HOME/Downloads"`.

Il token viene richiesto una volta e ricordato solo nella sessione della scheda. Se il server viene riavviato, il token cambia e va inserito di nuovo. Per esplorare tutto il filesystem in sola lettura puoi avviare con `--root / --read-only`; il server rifiuta di esporre `/` in modalità scrittura. Il server usa HTTP, non il protocollo FTP. Usalo soltanto su una rete fidata: HTTP non cifra il token. Il token casuale di 8 caratteri cambia a ogni avvio. Il server limita l'accesso alla cartella scelta, ignora i collegamenti simbolici e rifiuta i percorsi fuori da quella cartella. Gli upload, se attivi, sono limitati a 128 MiB per file e non sovrascrivono file esistenti.

Per arrestarlo, torna al terminale e premi `Ctrl+C`.
