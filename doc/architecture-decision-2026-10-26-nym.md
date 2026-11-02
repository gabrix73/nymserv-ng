# Decisione architetturale: da YAMN/AAM a Nym Mixnet

Data: 26 ottobre 2026. Stato: decisione di prodotto; implementazione non iniziata.

## Storia e motivo

`nymserv-ng` nacque come nymserver per YAMN, con recapito ai titolari tramite
la mailbox condivisa `alt.anonymous.messages` (AAM). Questa scelta seguiva il
modello di `crooks/nymserv`, perché il formato dei pacchetti YAMN non prevede
la costruzione o l'invio di reply block. Il disegno storico è conservato in
[`design.md`](design.md); descrive quella fase, non il nuovo obiettivo.

Il 26 ottobre 2026 è stato scelto il modello concettuale di `crooks/ghionym`:
un alias email riceve posta da Internet e il server la restituisce al titolare
attraverso un percorso di risposta anonimo. Nym Mixnet è il trasporto scelto
perché offre SURB native. YAMN e AAM escono dal percorso della prima versione.
La rete Nym è attivamente sviluppata e offre API e SURB; questa scelta non
equivale a dichiarare Nym più sicura in ogni scenario.

## Flusso previsto

1. Il client del titolare invia registrazione e messaggi al servizio tramite
   Nym Mixnet, allegando SURB e chiavi applicative. Il servizio conosce
   l'alias e un riferimento opaco alle SURB, non l'indirizzo Nym del client.
2. Il server riceve dall'Internet ordinaria la posta destinata all'alias
   tramite il proprio MTA. Cifra il contenuto per il titolare, lo mette in una
   coda durevole e usa una SURB disponibile per recapitarlo via Nym.
3. Per inviare come alias, il client trasmette il messaggio autenticato al
   servizio via Nym. Il server lo passa al proprio MTA, che lo recapita ai
   destinatari Internet con le normali regole SMTP.

La comunicazione client-servizio avviene tra due client Nym e non richiede un
exit clearnet. Le connessioni SMTP del MTA verso Internet sono separate dal
trasporto Nym. I gateway Entry/Exit gestiti dall'operatore, riferiti dal
titolare del progetto, possono essere utili per affidabilità e controllo, ma
non ne è stato verificato lo stato operativo in questa decisione.

## Vincolo delle SURB e consegna

Le SURB Nym sono monouso e scadono: la documentazione Nym indica una finestra
predefinita di 24 epoch, circa 25 ore, e chiavi di risposta con durata di 24
ore. Non sono un sostituto diretto dei reply block riutilizzabili di ghionym.
Il client deve rifornirle in modo periodico; se mancano o sono scadute, il
server conserva la posta cifrata e la consegna dopo il successivo contatto del
client. Occorrono quote, scadenza della coda, retry idempotenti, gestione dei
riavvii e una definizione precisa del momento in cui il MTA riceve un ACK.
La falla attuale `Store.Accept` prima di `spoolMessage` resta un blocco.

## SMTP: submission e recapito tra server

La policy di uscita Nym pubblicata al momento della decisione (v1.12.0,
5 agosto 2026) permette TCP 465 e 587 per la submission SMTP attraverso gli
exit; non include TCP 25, usata normalmente per il recapito MTA-to-MTA.
L'autorizzazione nella policy non garantisce che un singolo exit o il suo
hosting permetta davvero la connessione. Un proprio exit non può derogare
alla policy condivisa senza una decisione di governance.

Il flusso previsto sopra **non dipende dall'SMTP via exit Nym**. Il MTA del
nymserver riceve e spedisce SMTP direttamente su Internet. Il client invia
messaggi applicativi attraverso la mixnet, non sessioni SMTP. Se in futuro si
volesse far passare la submission SMTP attraverso un exit Nym, 465/587 sono
consentite dalla policy, ma vanno verificate con test reali, TLS, autenticazione,
limiti antiabuso e consegnabilità. Il recapito MTA-to-MTA via exit Nym sulla
porta 25 non è un requisito di questa architettura.

## Conseguenze per il repository

- La documentazione YAMN/AAM è storica. Non riutilizzare wire format, hSub,
  mailbox polling, gateway mail-to-news o parametri del pool YAMN come se
  fossero la nuova specifica.
- Conservare soltanto i componenti la cui semantica sopravvive alla revisione
  del modello di minaccia, dopo test e revisione dei confini tra registro,
  client Nym, coda e MTA.
- Definire protocollo di registrazione, replenishment SURB, conferma di
  consegna, cifratura end-to-end, gestione degli alias, abuse controls e
  fallimenti prima di cambiare il daemon o distribuire il servizio.
- Non chiamare `nymserv-ng` pronto per la produzione finché questi percorsi
  e i relativi test end-to-end non esistono.

## Fonti

- [Formato del pacchetto YAMN](https://github.com/crooks/yamn/blob/master/www/yamn_packet.html)
- [Risposte anonime e durata delle SURB Nym](https://nym.com/docs/network/mixnet-mode/anonymous-replies)
- [Client Nym e invio tra due client](https://nym.com/docs/developers/what-is-a-nym-client)
- [Policy di uscita Nym v1.12.0](https://nymtech.net/.wellknown/network-requester/exit-policy.txt)
- [NIP 6: porte SMTP 465 e 587 aperte](https://nym.com/blog/nip-6)
