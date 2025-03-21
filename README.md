# SecHeadCreator: Scanner CSP & Header di Sicurezza

Questa web app, sviluppata in PHP, HTML e JavaScript (con Bootstrap 5), consente di:

- **Scansionare un dominio** (rispettando il file `robots.txt`) fino a un numero configurabile di pagine e redirect.
- **Estrarre le risorse** (script, CSS, immagini, font, iframe) presenti nelle pagine.
- **Generare una bozza di Content-Security-Policy (CSP)** basata sugli host (origin) delle risorse trovate.
- **Generare un blocco di codice `.htaccess`** con una serie di header di sicurezza configurabili:
  - X-XSS-Protection
  - X-Frame-Options
  - X-Content-Type-Options
  - Strict-Transport-Security (HSTS)
  - Referrer-Policy
  - Permissions-Policy
  - Cross-Origin-Opener-Policy (COOP)
  - Cross-Origin-Embedder-Policy (COEP)
  - Cross-Origin-Resource-Policy (CORP)

## Caratteristiche principali

- **Configurazione avanzata collassabile**:  
  La sezione di configurazione avanzata (impostazioni di scansione e header di sicurezza) è nascosta per default per facilitare l'uso agli utenti meno esperti. È possibile espanderla per modificare le impostazioni.

- **Feedback immediato**:  
  Dopo la scansione, il blocco `.htaccess` viene mostrato subito sotto il bottone "Scansiona e genera header" e può essere copiato negli appunti con un solo click.

- **Risultati di scansione collassabili**:  
  I dettagli (pagine visitate, risorse trovate, bozza di CSP) sono racchiusi in una sezione che può essere espansa se l'utente desidera visualizzare i dettagli.

## Requisiti

- **PHP 7.4+** con estensione cURL abilitata.
- Un server web (Apache, Nginx, ecc.) in grado di interpretare PHP.
- **Bootstrap 5**: la web app include via CDN il CSS e JS di Bootstrap 5 per una migliore UX.

## Istruzioni d'Uso

1. **Installazione**  
   - Scarica o clona questo repository.
   - Posiziona il file `index.php` in una directory accessibile dal tuo server web.

2. **Accesso all'App**  
   - Naviga verso l'URL corrispondente, ad esempio `http://localhost/index.php`.

3. **Utilizzo**  
   - Inserisci il dominio da scansionare (assicurati di includere lo schema `http://` o `https://`).
   - Se necessario, espandi la sezione "Configurazione Avanzata" per modificare le impostazioni:
     - Numero massimo di pagine da scansionare e redirect da seguire.
     - Seleziona e configura i vari header di sicurezza.
   - Clicca sul pulsante **"Scansiona e genera header"**.
   - Dopo la scansione, verrà visualizzato il blocco di codice da inserire nel file `.htaccess`. Usa il pulsante "Copia negli appunti" per copiarlo facilmente.
   - Se desideri visualizzare i dettagli della scansione (pagine visitate, risorse trovate, CSP generata), espandi la sezione "Mostra Dettagli Scansione".

4. **Test e Personalizzazione**  
   - La CSP generata e gli header di sicurezza sono una bozza di partenza. **Testa accuratamente** in ambiente di staging prima di adottare le impostazioni in produzione.
   - Potrebbe essere necessario aggiungere ulteriori regole (ad esempio, per gestire script/stili inline con nonce o hash).

## Avvertenze

- Questa app è pensata come strumento **dimostrativo** e non sostituisce soluzioni di sicurezza avanzate.
- La scansione è limitata per evitare loop infiniti e non gestisce casi complessi (caricamenti dinamici, AJAX, ecc.).
- Verifica sempre le impostazioni di sicurezza per assicurarti che non interferiscano con le funzionalità critiche del sito (es. integrazioni di Google Maps, sistemi di pagamento, etc.).

## Contribuire

Se desideri migliorare questa web app o segnalare problemi, sentiti libero di aprire una issue o inviare una pull request.

---

© 2025 Scanner CSP & Header di Sicurezza

