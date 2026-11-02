# Confronto con crooks/nymserv e crooks/ghionym

> Historical comparison from before the transport decision. On 26 October
> 2026 the project chose Nym Mixnet and SURBs instead of YAMN/AAM. See the
> [current architecture decision](architecture-decision-2026-10-26-nym.md).
> Recommendations below to finish the YAMN/AAM path are superseded.

Verifica del 26 ottobre 2026. Riferimenti: `crooks/nymserv` al tree
`ad9b04224c170c2bd7be9a0bb4350765dce162cd`, `crooks/ghionym` al tree
`6959ce3b443716d56976c0e967a5c4a4543afd82`, e checkout locale di
`nymserv-ng` con modifiche non ancora committate. Lo stato del repository
GitHub `gabrix73/nymserv-ng` non include queste modifiche locali.

## Due modelli diversi

`crooks/nymserv` è il modello più vicino al trasporto scelto qui: riceve posta
per gli pseudonimi, cifra il contenuto e lo pubblica su una mailbox Usenet
condivisa. Per l'uscita dello pseudonimo usa il mix; gestisce hSub, pool di post,
registrazione e modifica dell'account tramite chiave OpenPGP.

`crooks/ghionym` segue invece il modello storico dei reply block Mixmaster:
ogni pseudonimo registra una chiave PGP e un reply block; il server recapita la
posta tramite quel percorso. Il nuovo reply block viene attivato dopo una
conferma via cookie. Offre anche invio autenticato, limiti, scadenza account,
opzioni per account, alias locali e servizi `finger`/`list`.

YAMN è forward-only e non offre il tipo di reply block richiesto da ghionym.
Per riprodurre quel recapito occorre cambiare trasporto, oppure progettare e
verificare un nuovo meccanismo di ritorno. La mailbox condivisa non prova da
sola un grande insieme di anonimato: servono lettori reali e gateway
mail-to-news funzionanti. Entrambi sono ancora da misurare.

## Matrice delle funzioni

| Funzione | nymserv | ghionym | nymserv-ng locale | Decisione |
|---|---|---|---|---|
| Recapito al titolare | OpenPGP su Usenet condiviso | PGP su reply block Mixmaster | Mailbox condivisa specificata; cifratura, pool e pubblicazione non collegati | Completare il percorso YAMN/Usenet dopo verifica dei gateway |
| Registrazione | Importazione chiave OpenPGP | `Config:` con chiave e reply block | Solo comando operatore `add-nym`; `Config: create` non implementato | Priorità alta: registrazione autenticata e atomica, senza risposta differenziale |
| Invio come pseudonimo | Firma PGP verificata | Firma PGP verificata | Envelope autenticato e replay persistente; inoltro YAMN non implementato | Priorità alta: validare i messaggi e costruire il modulo di uscita |
| Conferma del recapito | Nessun reply block | Cookie prima di attivare il reply block | Nessuna conferma | Non aggiungere cookie al percorso Usenet; non dimostrerebbe la consegna e creerebbe correlazione temporale |
| Anti-replay | Verifica GPG | Database persistente di firme | Contatore monotono e digest persistenti nel registro | Presente sul percorso moderno; testare il percorso completo quando esisterà |
| Limite per alias | Vari contatori | 512 messaggi/giorno | 512/giorno nel registro; limite globale progettato ma assente | Tenere il limite per alias; aggiungere quota globale nel modulo di uscita |
| Nomi riservati | Lista configurabile | Lista incorporata | Prima assenti; ora controllati da `ValidAlias` e `Store.Add` | Corretto nel checkout locale; mantenere separata la grammatica dei destinatari |
| Disabilitazione | Blocco invio per account | Flag per account | Flag e comando operatore; comando `Config:` assente | Completare l'autogestione firmata dell'alias |
| Preferenze per account | hSub, cifratura simmetrica, oggetto, conferma invio | `acksend`, `cryptrecv`, `signsend`, `fixedsize`, `nobcc`, filtro spam | Nessuna preferenza esposta al titolare | Aggiungere solo preferenze che non indeboliscono cifratura, padding o anonimato; valutare conferme solo sul normale ritmo del pool |
| Intestazioni e destinatari in uscita | `From:` ricostruito dall'identità firmata | `From:` ricostruito, `Hidden-To:` e ACK opzionali | Il modulo di invio non esiste | Nel modulo di uscita fissare `From:` all'identità autenticata e validare i destinatari; non copiare l'invocazione shell di ghionym |
| Scadenza account | Scadenza chiave PGP | Avviso dopo 180 giorni, eliminazione dopo 240 | Giorni di creazione/attività registrati; nessun ciclo di scadenza | Valutare dopo la consegna: serve una politica di recupero e avvisi nel pool |
| Padding, pool, dummy | Pool di post | Opzione dimensione fissa | Selezione binomiale presente, scheduler e dummy assenti | Priorità alta prima di traffico reale |
| Client | Client OpenPGP esterno | Client PGP e reply block esterni | Stato protocollo parziale; client usabile assente | Necessario per provare l'intero sistema |
| `finger`, `list`, `used`, alias `.forward` | Non centrali al modello | Presenti | Assenti | Non portarli: enumerazione degli alias e superficie d'attacco |
| Fetch di URL | Presente | Assente | Assente | Non necessario per il servizio email; rischio SSRF e abuso |

## Ordine consigliato

1. Risolvere la semantica di presa in carico della posta: una risposta di
   successo dell'LDA deve significare che il messaggio è in stato durevole e
   recuperabile. Oggi il percorso `config` accetta soltanto identità già nel
   registro e deposita il corpo nel file di spool senza applicare il comando;
   `send` deposita il corpo senza consegnarlo. Inoltre `Store.Accept` persiste
   contatore e digest prima di `spoolMessage`: se quest'ultima fallisce, il
   messaggio resta in Postfix ma il tentativo successivo viene respinto come
   replay. Non usarli in produzione.
2. Implementare `Config: create` e i comandi successivi con parsing limitato,
   autenticazione, controllo dei nomi, mutazione atomica e test sul percorso
   reale. La creazione richiede una verifica diversa da `Store.Accept`, che
   oggi cerca necessariamente un'identità già registrata.
3. Collegare scheduler indipendente dal traffico, coda durevole, padding,
   cifratura verso il titolare e pubblicazione mail-to-news tramite YAMN.
   Misurare prima gateway e lettori effettivi della mailbox.
4. Completare il client e verificare un ciclo end-to-end: creazione,
   corrispondenza in entrata, polling, risposta, riavvio e replay.
5. Solo dopo, aggiungere scadenza, avvisi e opzioni per account che abbiano un
   caso d'uso reale. La compatibilità OpenPGP è ancora pianificata, non attiva.

La scelta se sostituire YAMN/Usenet con un trasporto a reply block è una
decisione architetturale separata. Richiederebbe un nuovo modello di minaccia,
un protocollo client diverso e una verifica della rete utilizzabile oggi.

## Fonti principali

- [crooks/nymserv, implementazione Python](https://github.com/crooks/nymserv/blob/master/nymserv/nymserv)
- [crooks/nymserv, nomi riservati](https://github.com/crooks/nymserv/blob/master/samples/reserved_nyms)
- [crooks/ghionym, implementazione Perl](https://github.com/crooks/ghionym/blob/master/nymserver.pl)
- [crooks/yamn, formato del pacchetto](https://github.com/crooks/yamn/blob/master/www/yamn_packet.html)
- [Disegno corrente di nymserv-ng](design.md)
