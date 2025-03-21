<?php
/**
 * Piccola Web App per:
 * - Scansionare un dominio (fino a X pagine) leggendo robots.txt
 * - Estrarre fonti (script, CSS, immagini, font, iframe)
 * - Generare una bozza di Content-Security-Policy
 * - Offrire un set completo di header di sicurezza configurabili
 * - Mostrare un blocco .htaccess pronto all'uso
 *
 * Necessita di PHP 7.4+ e cURL abilitato.
 */

// Imposta un tempo di esecuzione più alto se necessario (siti lenti o con molte pagine)
ini_set('max_execution_time', 300);

// Valori di default
$defaultMaxPages = 10;
$defaultMaxRedirects = 5;

// Se il form è inviato, leggiamo i parametri
$domain = isset($_GET['domain']) ? trim($_GET['domain']) : '';
$maxPages = isset($_GET['max_pages']) ? (int)$_GET['max_pages'] : $defaultMaxPages;
$maxRedirects = isset($_GET['max_redirects']) ? (int)$_GET['max_redirects'] : $defaultMaxRedirects;

// Header di sicurezza selezionati
// (usiamo l'operatore di coalescenza ?? e array_map per prevenire notice)
$secHeaders = $_GET['sec_headers'] ?? [];
if (!is_array($secHeaders)) {
    $secHeaders = [];
}

// Parametri specifici per i singoli header
$xFrameOption = $_GET['x_frame_option'] ?? 'SAMEORIGIN';
$referrerPolicy = $_GET['referrer_policy'] ?? 'strict-origin-when-cross-origin';
$hstsMaxAge = isset($_GET['hsts_max_age']) ? (int)$_GET['hsts_max_age'] : 31536000;
$hstsIncludeSubdomains = isset($_GET['hsts_include_subdomains']) && $_GET['hsts_include_subdomains'] === 'on';
$hstsPreload = isset($_GET['hsts_preload']) && $_GET['hsts_preload'] === 'on';

// Permissions-Policy parametri
$permGeolocation = $_GET['perm_geolocation'] ?? '()';
$permCamera = $_GET['perm_camera'] ?? '()';
$permMicrophone = $_GET['perm_microphone'] ?? '()';
$permPayment = $_GET['perm_payment'] ?? '()';
$permFullscreen = $_GET['perm_fullscreen'] ?? '()';

// Cross-Origin Policies
$coop = $_GET['coop'] ?? 'unsafe-none';
$coep = $_GET['coep'] ?? 'unsafe-none';
$corp = $_GET['corp'] ?? 'cross-origin';

/** ************************
 * Funzioni di utility
 ***************************/

// Scarica una pagina con cURL
function fetchPage($url, $maxRedirects) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_USERAGENT, 'MiniCSPScanner/2.0');
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, $maxRedirects);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);
    $data = curl_exec($ch);
    curl_close($ch);
    return $data;
}

// Normalizza un URL relativo in uno assoluto
function makeAbsoluteUrl($base, $relative) {
    if (parse_url($relative, PHP_URL_SCHEME) != '' || str_starts_with($relative, '//')) {
        return $relative;
    }
    if ($relative && $relative[0] === '#') {
        // Anchor
        return '';
    }
    // Costruisce l'URL assoluto
    return rtrim(dirname($base), '/') . '/' . ltrim($relative, '/');
}

// Estrae i link <a href="...">
function extractLinks($html, $baseUrl) {
    $links = [];
    if (preg_match_all('/<a[^>]+href=["\']?([^"\'>]+)["\']?/i', $html, $matches)) {
        foreach ($matches[1] as $link) {
            $abs = makeAbsoluteUrl($baseUrl, $link);
            if ($abs) $links[] = $abs;
        }
    }
    return array_unique($links);
}

// Estrae script, CSS, immagini, font, iframe
function extractResources($html, $baseUrl) {
    $resources = [
        'script' => [],
        'style'  => [],
        'img'    => [],
        'font'   => [],
        'frame'  => []
    ];
    // Script
    if (preg_match_all('/<script[^>]+src=["\']?([^"\'>]+)["\']?/i', $html, $matches)) {
        foreach ($matches[1] as $src) {
            $abs = makeAbsoluteUrl($baseUrl, $src);
            if ($abs) $resources['script'][] = $abs;
        }
    }
    // CSS
    if (preg_match_all('/<link[^>]+rel=["\']?stylesheet["\']?[^>]+href=["\']?([^"\'>]+)["\']?/i', $html, $matches)) {
        foreach ($matches[1] as $src) {
            $abs = makeAbsoluteUrl($baseUrl, $src);
            if ($abs) $resources['style'][] = $abs;
        }
    }
    // Immagini
    if (preg_match_all('/<img[^>]+src=["\']?([^"\'>]+)["\']?/i', $html, $matches)) {
        foreach ($matches[1] as $src) {
            $abs = makeAbsoluteUrl($baseUrl, $src);
            if ($abs) $resources['img'][] = $abs;
        }
    }
    // Iframe
    if (preg_match_all('/<iframe[^>]+src=["\']?([^"\'>]+)["\']?/i', $html, $matches)) {
        foreach ($matches[1] as $src) {
            $abs = makeAbsoluteUrl($baseUrl, $src);
            if ($abs) $resources['frame'][] = $abs;
        }
    }
    // Font (via <link as="font">) - non gestisce @font-face nei CSS
    if (preg_match_all('/<link[^>]+as=["\']?font["\']?[^>]+href=["\']?([^"\'>]+)["\']?/i', $html, $matches)) {
        foreach ($matches[1] as $src) {
            $abs = makeAbsoluteUrl($baseUrl, $src);
            if ($abs) $resources['font'][] = $abs;
        }
    }
    // Deduplicate
    foreach ($resources as $k => $arr) {
        $resources[$k] = array_unique($arr);
    }
    return $resources;
}

// Estrae le regole Disallow da robots.txt
function fetchRobotsDisallow($domain, $maxRedirects) {
    $disallowList = [];
    $robotsUrl = rtrim($domain, '/') . '/robots.txt';
    $txt = @fetchPage($robotsUrl, $maxRedirects);
    if ($txt) {
        if (preg_match_all('/Disallow:\s*(\/[^\r\n\s]*)/i', $txt, $matches)) {
            $disallowList = $matches[1];
        }
    }
    return $disallowList;
}

// Ricava lo "origin" (scheme://host:port) da un URL
function getOrigin($url) {
    $p = parse_url($url);
    if (!isset($p['scheme']) || !isset($p['host'])) return '';
    $origin = $p['scheme'] . '://' . $p['host'];
    if (isset($p['port'])) {
        $origin .= ':' . $p['port'];
    }
    return $origin;
}

// Funzione che costruisce la CSP da un array di risorse
function buildCSP($allResources) {
    // Raggruppiamo per direttiva
    $origins = [
        'script-src' => [],
        'style-src'  => [],
        'img-src'    => [],
        'font-src'   => [],
        'frame-src'  => []
    ];

    foreach ($allResources['script'] as $u) {
        $o = getOrigin($u);
        if ($o) $origins['script-src'][] = $o;
    }
    foreach ($allResources['style'] as $u) {
        $o = getOrigin($u);
        if ($o) $origins['style-src'][] = $o;
    }
    foreach ($allResources['img'] as $u) {
        $o = getOrigin($u);
        if ($o) $origins['img-src'][] = $o;
    }
    foreach ($allResources['font'] as $u) {
        $o = getOrigin($u);
        if ($o) $origins['font-src'][] = $o;
    }
    foreach ($allResources['frame'] as $u) {
        $o = getOrigin($u);
        if ($o) $origins['frame-src'][] = $o;
    }

    // Aggiunge 'self' e deduplica
    foreach ($origins as $k => &$arr) {
        $arr[] = "'self'";
        if ($k === 'img-src') {
            // data: per immagini inline base64
            $arr[] = 'data:';
        }
        $arr = array_unique($arr);
    }

    // Costruisce la stringa CSP
    $cspParts = ["default-src 'self'"];
    foreach ($origins as $directive => $arr) {
        if (!empty($arr)) {
            $cspParts[] = $directive . ' ' . implode(' ', $arr);
        }
    }
    // Nota: se usi script/stili inline, potresti dover aggiungere `'unsafe-inline'` o nonce
    return implode('; ', $cspParts);
}

/** ************************
 * Se il form è stato inviato e c'è un dominio, eseguiamo la scansione
 ***************************/
$results = [];
$cspString = '';
$visited = [];
$allResources = [
    'script' => [],
    'style'  => [],
    'img'    => [],
    'font'   => [],
    'frame'  => []
];

if ($domain) {
    // Aggiunge https:// se manca
    if (!preg_match('#^https?://#', $domain)) {
        $domain = 'https://' . $domain;
    }

    // 1) robots.txt
    $disallowList = fetchRobotsDisallow($domain, $maxRedirects);

    // 2) Scansione BFS di max $maxPages pagine
    $toVisit = [$domain];
    while (!empty($toVisit) && count($visited) < $maxPages) {
        $current = array_shift($toVisit);
        $current = rtrim($current, '/');
        if (in_array($current, $visited)) {
            continue;
        }
        // Controlla se rientra tra i Disallow
        $parsed = parse_url($current);
        $path = $parsed['path'] ?? '/';
        foreach ($disallowList as $dis) {
            if (str_starts_with($path, $dis)) {
                // Salta se è disallow
                continue 2;
            }
        }
        // Scarica pagina
        $html = fetchPage($current, $maxRedirects);
        if (!$html) {
            $visited[] = $current;
            continue;
        }
        // Estrae link e risorse
        $links = extractLinks($html, $current);
        $res = extractResources($html, $current);

        // Aggiunge link (stesso dominio) in coda
        foreach ($links as $lnk) {
            $p = parse_url($lnk);
            if (isset($p['host']) && isset($parsed['host']) && $p['host'] === $parsed['host']) {
                if (!in_array($lnk, $visited) && !in_array($lnk, $toVisit)) {
                    $toVisit[] = $lnk;
                }
            }
        }
        // Accumula risorse
        foreach ($res as $k => $arr) {
            $allResources[$k] = array_merge($allResources[$k], $arr);
        }

        $visited[] = $current;
    }

    // Deduplica risorse
    foreach ($allResources as $k => $arr) {
        $allResources[$k] = array_unique($arr);
    }

    // 3) Generiamo la CSP
    $cspString = buildCSP($allResources);
}

// Funzione helper per stampare i risultati di scanning in HTML
function printResourceList($title, $list) {
    $count = count($list);
    echo "<h4>$title ($count)</h4>";
    echo "<ul class='list-group mb-3'>";
    foreach ($list as $item) {
        $safe = htmlspecialchars($item);
        echo "<li class='list-group-item'>$safe</li>";
    }
    echo "</ul>";
}

// Ora costruiamo il blocco .htaccess finale
$htaccessBlock = '';
if ($domain && !empty($visited)) {
    $lines = [];
    $lines[] = '<IfModule mod_headers.c>';
    // CSP
    $lines[] = "    Header set Content-Security-Policy \"$cspString\"";

    // X-XSS-Protection
    if (in_array('x_xss_protection', $secHeaders)) {
        // Valore standard: "1; mode=block"
        $lines[] = "    Header set X-XSS-Protection \"1; mode=block\"";
    }
    // X-Frame-Options
    if (in_array('x_frame_options', $secHeaders)) {
        $lines[] = "    Header always set X-Frame-Options $xFrameOption";
    }
    // X-Content-Type-Options
    if (in_array('x_content_type_options', $secHeaders)) {
        $lines[] = "    Header set X-Content-Type-Options \"nosniff\"";
    }
    // Strict-Transport-Security
    if (in_array('strict_transport_security', $secHeaders)) {
        $hstsValue = "max-age=$hstsMaxAge";
        if ($hstsIncludeSubdomains) {
            $hstsValue .= "; includeSubDomains";
        }
        if ($hstsPreload) {
            $hstsValue .= "; preload";
        }
        $lines[] = "    Header set Strict-Transport-Security \"$hstsValue\"";
    }
    // Referrer-Policy
    if (in_array('referrer_policy', $secHeaders)) {
        $lines[] = "    Header set Referrer-Policy \"$referrerPolicy\"";
    }
    // Permissions-Policy
    if (in_array('permissions_policy', $secHeaders)) {
        $pp = [];
        $pp[] = "geolocation=$permGeolocation";
        $pp[] = "camera=$permCamera";
        $pp[] = "microphone=$permMicrophone";
        $pp[] = "payment=$permPayment";
        $pp[] = "fullscreen=$permFullscreen";
        $ppString = implode(", ", $pp);
        $lines[] = "    Header set Permissions-Policy \"$ppString\"";
    }
    // COOP
    if (in_array('coop', $secHeaders) && $coop !== 'unsafe-none') {
        $lines[] = "    Header set Cross-Origin-Opener-Policy \"$coop\"";
    }
    // COEP
    if (in_array('coep', $secHeaders) && $coep !== 'unsafe-none') {
        $lines[] = "    Header set Cross-Origin-Embedder-Policy \"$coep\"";
    }
    // CORP
    if (in_array('corp', $secHeaders)) {
        $lines[] = "    Header set Cross-Origin-Resource-Policy \"$corp\"";
    }

    $lines[] = '</IfModule>';
    $htaccessBlock = implode("\n", $lines);
}
?>
<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <title>Scanner CSP & Sicurezza</title>
  <!-- Bootstrap 5 -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-5">
  <h1 class="mb-4">Scanner CSP &amp; Header di Sicurezza</h1>
  <p class="text-muted">Questa demo scansiona un numero limitato di pagine di un dominio, estrae le fonti (script, css, immagini, ecc.) e genera una bozza di <strong>Content-Security-Policy</strong>. Inoltre puoi configurare altri header di sicurezza.</p>

  <form method="get" class="row g-3 mb-5">
    <div class="col-md-6">
      <label for="domain" class="form-label">Dominio da scansionare (es: https://example.com)</label>
      <input type="text" name="domain" id="domain" class="form-control" placeholder="https://example.com" value="<?php echo htmlspecialchars($domain); ?>">
    </div>
    <div class="col-md-3">
      <label for="max_pages" class="form-label">Max pagine da scansionare</label>
      <input type="number" name="max_pages" id="max_pages" class="form-control" value="<?php echo $maxPages; ?>">
      <small class="text-muted">Default: <?php echo $defaultMaxPages; ?></small>
    </div>
    <div class="col-md-3">
      <label for="max_redirects" class="form-label">Max redirect da seguire</label>
      <input type="number" name="max_redirects" id="max_redirects" class="form-control" value="<?php echo $maxRedirects; ?>">
      <small class="text-muted">Default: <?php echo $defaultMaxRedirects; ?></small>
    </div>

    <hr class="my-4">

    <h4>Seleziona gli header di sicurezza da includere</h4>
    <div class="col-md-12">
      <div class="form-check">
        <input class="form-check-input" type="checkbox" name="sec_headers[]" value="x_xss_protection" id="xss" <?php echo in_array('x_xss_protection', $secHeaders) ? 'checked' : ''; ?>>
        <label class="form-check-label" for="xss">
          X-XSS-Protection <small class="text-muted">(Deprecato sui browser moderni, ma utile su alcuni legacy)</small>
        </label>
      </div>
      <div class="form-check">
        <input class="form-check-input" type="checkbox" name="sec_headers[]" value="x_frame_options" id="xfo" <?php echo in_array('x_frame_options', $secHeaders) ? 'checked' : ''; ?>>
        <label class="form-check-label" for="xfo">
          X-Frame-Options <small class="text-muted">(Protegge da clickjacking)</small>
        </label>
      </div>
      <div class="ms-4 mb-3">
        <label class="form-label" for="x_frame_option">Valore:</label>
        <select name="x_frame_option" id="x_frame_option" class="form-select" style="max-width:300px;">
          <option value="SAMEORIGIN" <?php if($xFrameOption==='SAMEORIGIN') echo 'selected'; ?>>SAMEORIGIN</option>
          <option value="DENY" <?php if($xFrameOption==='DENY') echo 'selected'; ?>>DENY</option>
          <option value="ALLOW-FROM" <?php if($xFrameOption==='ALLOW-FROM') echo 'selected'; ?>>ALLOW-FROM (obsoleto su alcuni browser)</option>
        </select>
      </div>
      <div class="form-check">
        <input class="form-check-input" type="checkbox" name="sec_headers[]" value="x_content_type_options" id="xcto" <?php echo in_array('x_content_type_options', $secHeaders) ? 'checked' : ''; ?>>
        <label class="form-check-label" for="xcto">
          X-Content-Type-Options <small class="text-muted">("nosniff", previene interpretazioni errate dei MIME type)</small>
        </label>
      </div>
      <div class="form-check">
        <input class="form-check-input" type="checkbox" name="sec_headers[]" value="strict_transport_security" id="hsts" <?php echo in_array('strict_transport_security', $secHeaders) ? 'checked' : ''; ?>>
        <label class="form-check-label" for="hsts">
          Strict-Transport-Security (HSTS) <small class="text-muted">(Richiede HTTPS)</small>
        </label>
      </div>
      <div class="row ms-4 mb-3">
        <div class="col-md-4">
          <label for="hsts_max_age" class="form-label">Max-Age (sec)</label>
          <input type="number" name="hsts_max_age" id="hsts_max_age" class="form-control" value="<?php echo $hstsMaxAge; ?>">
        </div>
        <div class="col-md-4 form-check align-self-end">
          <input class="form-check-input" type="checkbox" name="hsts_include_subdomains" id="hsts_include_subdomains" <?php echo $hstsIncludeSubdomains ? 'checked' : ''; ?>>
          <label class="form-check-label" for="hsts_include_subdomains">includeSubDomains</label>
        </div>
        <div class="col-md-4 form-check align-self-end">
          <input class="form-check-input" type="checkbox" name="hsts_preload" id="hsts_preload" <?php echo $hstsPreload ? 'checked' : ''; ?>>
          <label class="form-check-label" for="hsts_preload">preload</label>
        </div>
      </div>
      <div class="form-check">
        <input class="form-check-input" type="checkbox" name="sec_headers[]" value="referrer_policy" id="rp" <?php echo in_array('referrer_policy', $secHeaders) ? 'checked' : ''; ?>>
        <label class="form-check-label" for="rp">
          Referrer-Policy <small class="text-muted">(Controlla l'invio dell'header Referer)</small>
        </label>
      </div>
      <div class="ms-4 mb-3" style="max-width:300px;">
        <label for="referrer_policy" class="form-label">Valore:</label>
        <select name="referrer_policy" id="referrer_policy" class="form-select">
          <option value="no-referrer" <?php if($referrerPolicy==='no-referrer') echo 'selected'; ?>>no-referrer</option>
          <option value="no-referrer-when-downgrade" <?php if($referrerPolicy==='no-referrer-when-downgrade') echo 'selected'; ?>>no-referrer-when-downgrade</option>
          <option value="same-origin" <?php if($referrerPolicy==='same-origin') echo 'selected'; ?>>same-origin</option>
          <option value="origin" <?php if($referrerPolicy==='origin') echo 'selected'; ?>>origin</option>
          <option value="strict-origin" <?php if($referrerPolicy==='strict-origin') echo 'selected'; ?>>strict-origin</option>
          <option value="origin-when-cross-origin" <?php if($referrerPolicy==='origin-when-cross-origin') echo 'selected'; ?>>origin-when-cross-origin</option>
          <option value="strict-origin-when-cross-origin" <?php if($referrerPolicy==='strict-origin-when-cross-origin') echo 'selected'; ?>>strict-origin-when-cross-origin</option>
          <option value="unsafe-url" <?php if($referrerPolicy==='unsafe-url') echo 'selected'; ?>>unsafe-url</option>
        </select>
      </div>

      <div class="form-check">
        <input class="form-check-input" type="checkbox" name="sec_headers[]" value="permissions_policy" id="pp" <?php echo in_array('permissions_policy', $secHeaders) ? 'checked' : ''; ?>>
        <label class="form-check-label" for="pp">
          Permissions-Policy <small class="text-muted">(Limita l'uso di API come geolocalizzazione, camera, ecc.)</small>
        </label>
      </div>
      <div class="row ms-4 mb-3">
        <p class="text-muted">Specifica come limitare ogni API. Esempi: <code>(self)</code> per consentire solo al tuo dominio, <code>()</code> per disabilitare completamente.</p>
        <div class="col-md-2">
          <label for="perm_geolocation" class="form-label">geolocation</label>
          <input type="text" class="form-control" name="perm_geolocation" id="perm_geolocation" value="<?php echo htmlspecialchars($permGeolocation); ?>">
        </div>
        <div class="col-md-2">
          <label for="perm_camera" class="form-label">camera</label>
          <input type="text" class="form-control" name="perm_camera" id="perm_camera" value="<?php echo htmlspecialchars($permCamera); ?>">
        </div>
        <div class="col-md-2">
          <label for="perm_microphone" class="form-label">microphone</label>
          <input type="text" class="form-control" name="perm_microphone" id="perm_microphone" value="<?php echo htmlspecialchars($permMicrophone); ?>">
        </div>
        <div class="col-md-2">
          <label for="perm_payment" class="form-label">payment</label>
          <input type="text" class="form-control" name="perm_payment" id="perm_payment" value="<?php echo htmlspecialchars($permPayment); ?>">
        </div>
        <div class="col-md-2">
          <label for="perm_fullscreen" class="form-label">fullscreen</label>
          <input type="text" class="form-control" name="perm_fullscreen" id="perm_fullscreen" value="<?php echo htmlspecialchars($permFullscreen); ?>">
        </div>
      </div>

      <div class="form-check">
        <input class="form-check-input" type="checkbox" name="sec_headers[]" value="coop" id="coop_cb" <?php echo in_array('coop', $secHeaders) ? 'checked' : ''; ?>>
        <label class="form-check-label" for="coop_cb">
          Cross-Origin-Opener-Policy (COOP)
          <small class="text-muted">(Isola la finestra da contesti cross-origin)</small>
        </label>
      </div>
      <div class="ms-4 mb-3" style="max-width:300px;">
        <label for="coop" class="form-label">Valore:</label>
        <select name="coop" id="coop" class="form-select">
          <option value="unsafe-none" <?php if($coop==='unsafe-none') echo 'selected'; ?>>unsafe-none (disabilitato)</option>
          <option value="same-origin" <?php if($coop==='same-origin') echo 'selected'; ?>>same-origin</option>
          <option value="same-origin-allow-popups" <?php if($coop==='same-origin-allow-popups') echo 'selected'; ?>>same-origin-allow-popups</option>
        </select>
      </div>

      <div class="form-check">
        <input class="form-check-input" type="checkbox" name="sec_headers[]" value="coep" id="coep_cb" <?php echo in_array('coep', $secHeaders) ? 'checked' : ''; ?>>
        <label class="form-check-label" for="coep_cb">
          Cross-Origin-Embedder-Policy (COEP)
          <small class="text-muted">(Richiede risorse cross-origin con CORP/CORS)</small>
        </label>
      </div>
      <div class="ms-4 mb-3" style="max-width:300px;">
        <label for="coep" class="form-label">Valore:</label>
        <select name="coep" id="coep" class="form-select">
          <option value="unsafe-none" <?php if($coep==='unsafe-none') echo 'selected'; ?>>unsafe-none (disabilitato)</option>
          <option value="require-corp" <?php if($coep==='require-corp') echo 'selected'; ?>>require-corp</option>
          <option value="credentialless" <?php if($coep==='credentialless') echo 'selected'; ?>>credentialless</option>
        </select>
      </div>

      <div class="form-check">
        <input class="form-check-input" type="checkbox" name="sec_headers[]" value="corp" id="corp_cb" <?php echo in_array('corp', $secHeaders) ? 'checked' : ''; ?>>
        <label class="form-check-label" for="corp_cb">
          Cross-Origin-Resource-Policy (CORP)
          <small class="text-muted">(Definisce chi può incorporare le tue risorse)</small>
        </label>
      </div>
      <div class="ms-4 mb-3" style="max-width:300px;">
        <label for="corp" class="form-label">Valore:</label>
        <select name="corp" id="corp" class="form-select">
          <option value="cross-origin" <?php if($corp==='cross-origin') echo 'selected'; ?>>cross-origin (più permissivo)</option>
          <option value="same-site" <?php if($corp==='same-site') echo 'selected'; ?>>same-site</option>
          <option value="same-origin" <?php if($corp==='same-origin') echo 'selected'; ?>>same-origin (più restrittivo)</option>
        </select>
      </div>
    </div>

    <div class="col-12 mt-3">
      <button type="submit" class="btn btn-primary">Scansiona</button>
    </div>
  </form>

  <?php if ($domain && !empty($visited)): ?>
    <h2 class="mb-4">Risultati Scansione</h2>
    <div class="card mb-4">
      <div class="card-body">
        <h3 class="card-title h5">Pagine visitate (max <?php echo $maxPages; ?>)</h3>
        <ul class="list-group">
          <?php foreach ($visited as $v): ?>
            <li class="list-group-item"><?php echo htmlspecialchars($v); ?></li>
          <?php endforeach; ?>
        </ul>
      </div>
    </div>

    <div class="card mb-4">
      <div class="card-body">
        <h3 class="card-title h5">Risorse trovate</h3>
        <?php
        printResourceList('Script', $allResources['script']);
        printResourceList('Stili (CSS)', $allResources['style']);
        printResourceList('Immagini', $allResources['img']);
        printResourceList('Font', $allResources['font']);
        printResourceList('Frame (iframe)', $allResources['frame']);
        ?>
      </div>
    </div>

    <div class="card mb-4">
      <div class="card-body">
        <h3 class="card-title h5">Bozza di Content-Security-Policy</h3>
        <p class="text-muted">Attenzione a script/stili inline: potresti dover aggiungere <code>'unsafe-inline'</code> o usare <code>nonce</code>/<code>sha256-hash</code> per evitare di rompere funzionalità.</p>
        <pre class="bg-light p-3"><?php echo htmlspecialchars($cspString); ?></pre>
      </div>
    </div>

    <div class="card mb-4">
      <div class="card-body">
        <h3 class="card-title h5">Blocco .htaccess generato</h3>
        <?php if ($htaccessBlock): ?>
          <pre class="bg-light p-3"><?php echo htmlspecialchars($htaccessBlock); ?></pre>
          <p class="text-muted">Copia e incolla questo blocco nel tuo file <code>.htaccess</code> o nella configurazione del VirtualHost. Verifica che <code>mod_headers</code> sia abilitato e testa a fondo il sito per evitare malfunzionamenti.</p>
        <?php else: ?>
          <p class="text-muted">Nessun header di sicurezza selezionato o nessuna pagina trovata.</p>
        <?php endif; ?>
      </div>
    </div>
  <?php elseif($domain): ?>
    <div class="alert alert-warning">
      Non è stato possibile scansionare alcuna pagina o il dominio non risponde.
    </div>
  <?php endif; ?>
</div>
</body>
</html>
