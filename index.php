<?php
/**
 * Web App per scansione sito e generazione header di sicurezza
 *
 * - Scansiona un dominio (limite pagine e redirect configurabili)
 * - Estrae risorse (script, CSS, immagini, font, iframe)
 * - Genera una bozza di Content-Security-Policy (CSP)
 * - Propone un blocco .htaccess con header di sicurezza configurabili
 *
 * Requisiti: PHP con cURL abilitato
 */

ini_set('max_execution_time', 300);

// Valori di default per la scansione
$defaultMaxPages = 10;
$defaultMaxRedirects = 5;

// Recupera i parametri dal form (metodo GET)
$domain         = isset($_GET['domain']) ? trim($_GET['domain']) : '';
$maxPages       = isset($_GET['max_pages']) ? (int)$_GET['max_pages'] : $defaultMaxPages;
$maxRedirects   = isset($_GET['max_redirects']) ? (int)$_GET['max_redirects'] : $defaultMaxRedirects;

// Header di sicurezza scelti (array dei nomi, per esempio: x_xss_protection, x_frame_options, ecc.)
$secHeaders = $_GET['sec_headers'] ?? [];
if (!is_array($secHeaders)) $secHeaders = [];

// Parametri specifici per header:
$xFrameOption         = $_GET['x_frame_option'] ?? 'SAMEORIGIN';
$referrerPolicy       = $_GET['referrer_policy'] ?? 'strict-origin-when-cross-origin';
$hstsMaxAge           = isset($_GET['hsts_max_age']) ? (int)$_GET['hsts_max_age'] : 31536000;
$hstsIncludeSubdomains= isset($_GET['hsts_include_subdomains']) && $_GET['hsts_include_subdomains'] === 'on';
$hstsPreload          = isset($_GET['hsts_preload']) && $_GET['hsts_preload'] === 'on';

// Permissions-Policy (inserire come stringa es. (self) oppure () per disabilitare)
$permGeolocation = $_GET['perm_geolocation'] ?? '(self)';
$permCamera      = $_GET['perm_camera'] ?? '()';
$permMicrophone  = $_GET['perm_microphone'] ?? '()';
$permPayment     = $_GET['perm_payment'] ?? '(self)';
$permFullscreen  = $_GET['perm_fullscreen'] ?? '(self)';

// Cross-Origin Policies
$coop = $_GET['coop'] ?? 'unsafe-none';
$coep = $_GET['coep'] ?? 'unsafe-none';
$corp = $_GET['corp'] ?? 'cross-origin';

/** ****************************
 * FUNZIONI UTILITY
 *******************************/

// Scarica una pagina tramite cURL
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

// Converte URL relativi in assoluti
function makeAbsoluteUrl($base, $relative) {
    if (parse_url($relative, PHP_URL_SCHEME) != '' || str_starts_with($relative, '//')) {
        return $relative;
    }
    if ($relative && $relative[0] === '#') return '';
    return rtrim(dirname($base), '/') . '/' . ltrim($relative, '/');
}

// Estrae link (tag <a href="...">)
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

// Estrae risorse: script, stili, immagini, font, iframe
function extractResources($html, $baseUrl) {
    $resources = [
        'script' => [],
        'style'  => [],
        'img'    => [],
        'font'   => [],
        'frame'  => []
    ];
    if (preg_match_all('/<script[^>]+src=["\']?([^"\'>]+)["\']?/i', $html, $matches)) {
        foreach ($matches[1] as $src) {
            $abs = makeAbsoluteUrl($baseUrl, $src);
            if ($abs) $resources['script'][] = $abs;
        }
    }
    if (preg_match_all('/<link[^>]+rel=["\']?stylesheet["\']?[^>]+href=["\']?([^"\'>]+)["\']?/i', $html, $matches)) {
        foreach ($matches[1] as $src) {
            $abs = makeAbsoluteUrl($baseUrl, $src);
            if ($abs) $resources['style'][] = $abs;
        }
    }
    if (preg_match_all('/<img[^>]+src=["\']?([^"\'>]+)["\']?/i', $html, $matches)) {
        foreach ($matches[1] as $src) {
            $abs = makeAbsoluteUrl($baseUrl, $src);
            if ($abs) $resources['img'][] = $abs;
        }
    }
    if (preg_match_all('/<iframe[^>]+src=["\']?([^"\'>]+)["\']?/i', $html, $matches)) {
        foreach ($matches[1] as $src) {
            $abs = makeAbsoluteUrl($baseUrl, $src);
            if ($abs) $resources['frame'][] = $abs;
        }
    }
    if (preg_match_all('/<link[^>]+as=["\']?font["\']?[^>]+href=["\']?([^"\'>]+)["\']?/i', $html, $matches)) {
        foreach ($matches[1] as $src) {
            $abs = makeAbsoluteUrl($baseUrl, $src);
            if ($abs) $resources['font'][] = $abs;
        }
    }
    foreach ($resources as $k => $arr) {
        $resources[$k] = array_unique($arr);
    }
    return $resources;
}

// Estrae le regole Disallow dal robots.txt
function fetchRobotsDisallow($domain, $maxRedirects) {
    $disallowList = [];
    $robotsUrl = rtrim($domain, '/') . '/robots.txt';
    $txt = @fetchPage($robotsUrl, $maxRedirects);
    if ($txt && preg_match_all('/Disallow:\s*(\/[^\r\n\s]*)/i', $txt, $matches)) {
        $disallowList = $matches[1];
    }
    return $disallowList;
}

// Ricava l'origin (scheme://host[:port]) da un URL
function getOrigin($url) {
    $p = parse_url($url);
    if (!isset($p['scheme']) || !isset($p['host'])) return '';
    $origin = $p['scheme'] . '://' . $p['host'];
    if (isset($p['port'])) $origin .= ':' . $p['port'];
    return $origin;
}

// Costruisce la CSP dalle risorse raccolte
function buildCSP($allResources) {
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
    foreach ($origins as $k => &$arr) {
        $arr[] = "'self'";
        if ($k === 'img-src') $arr[] = 'data:'; // per immagini inline base64
        $arr = array_unique($arr);
    }
    $cspParts = ["default-src 'self'"];
    foreach ($origins as $directive => $arr) {
        if (!empty($arr)) $cspParts[] = "$directive " . implode(' ', $arr);
    }
    return implode('; ', $cspParts);
}

// Funzione helper per stampare liste di risorse in HTML
function printResourceList($title, $list) {
    echo "<h4>$title (" . count($list) . ")</h4>";
    echo "<ul class='list-group mb-3'>";
    foreach ($list as $item) {
        echo "<li class='list-group-item'>" . htmlspecialchars($item) . "</li>";
    }
    echo "</ul>";
}

// Iniziamo la scansione se è stato inserito un dominio
$visited = [];
$allResources = [
    'script' => [],
    'style'  => [],
    'img'    => [],
    'font'   => [],
    'frame'  => []
];
$cspString = '';
if ($domain) {
    if (!preg_match('#^https?://#', $domain)) $domain = 'https://' . $domain;
    $disallowList = fetchRobotsDisallow($domain, $maxRedirects);
    $toVisit = [$domain];
    while (!empty($toVisit) && count($visited) < $maxPages) {
        $current = rtrim(array_shift($toVisit), '/');
        if (in_array($current, $visited)) continue;
        $parsed = parse_url($current);
        $path = $parsed['path'] ?? '/';
        foreach ($disallowList as $dis) {
            if (str_starts_with($path, $dis)) continue 2;
        }
        $html = fetchPage($current, $maxRedirects);
        if (!$html) { $visited[] = $current; continue; }
        $links = extractLinks($html, $current);
        $res   = extractResources($html, $current);
        foreach ($links as $lnk) {
            $p = parse_url($lnk);
            if (isset($p['host'], $parsed['host']) && $p['host'] === $parsed['host']) {
                if (!in_array($lnk, $visited) && !in_array($lnk, $toVisit)) {
                    $toVisit[] = $lnk;
                }
            }
        }
        foreach ($res as $k => $arr) {
            $allResources[$k] = array_merge($allResources[$k], $arr);
        }
        $visited[] = $current;
    }
    foreach ($allResources as $k => $arr) {
        $allResources[$k] = array_unique($arr);
    }
    $cspString = buildCSP($allResources);
}

// Costruisce il blocco .htaccess con gli header selezionati
$htaccessBlock = '';
if ($domain && !empty($visited)) {
    $lines = [];
    $lines[] = '<IfModule mod_headers.c>';
    $lines[] = "    Header set Content-Security-Policy \"$cspString\"";
    if (in_array('x_xss_protection', $secHeaders))
        $lines[] = "    Header set X-XSS-Protection \"1; mode=block\"";
    if (in_array('x_frame_options', $secHeaders))
        $lines[] = "    Header always set X-Frame-Options $xFrameOption";
    if (in_array('x_content_type_options', $secHeaders))
        $lines[] = "    Header set X-Content-Type-Options \"nosniff\"";
    if (in_array('strict_transport_security', $secHeaders)) {
        $hstsValue = "max-age=$hstsMaxAge";
        if ($hstsIncludeSubdomains) $hstsValue .= "; includeSubDomains";
        if ($hstsPreload) $hstsValue .= "; preload";
        $lines[] = "    Header set Strict-Transport-Security \"$hstsValue\"";
    }
    if (in_array('referrer_policy', $secHeaders))
        $lines[] = "    Header set Referrer-Policy \"$referrerPolicy\"";
    if (in_array('permissions_policy', $secHeaders)) {
        $pp = [];
        $pp[] = "geolocation=$permGeolocation";
        $pp[] = "camera=$permCamera";
        $pp[] = "microphone=$permMicrophone";
        $pp[] = "payment=$permPayment";
        $pp[] = "fullscreen=$permFullscreen";
        $lines[] = "    Header set Permissions-Policy \"" . implode(", ", $pp) . "\"";
    }
    if (in_array('coop', $secHeaders) && $coop !== 'unsafe-none')
        $lines[] = "    Header set Cross-Origin-Opener-Policy \"$coop\"";
    if (in_array('coep', $secHeaders) && $coep !== 'unsafe-none')
        $lines[] = "    Header set Cross-Origin-Embedder-Policy \"$coep\"";
    if (in_array('corp', $secHeaders))
        $lines[] = "    Header set Cross-Origin-Resource-Policy \"$corp\"";
    $lines[] = '</IfModule>';
    $htaccessBlock = implode("\n", $lines);
}
?>
<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <title>Scanner CSP & Sicurezza</title>
  <!-- Bootstrap 5 CSS -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-5">
  <h1 class="mb-4">Scanner CSP &amp; Header di Sicurezza</h1>
  <p class="text-muted">Inserisci il dominio da scansionare e configura le impostazioni di sicurezza. La demo scansiona alcune pagine (fino al numero impostato) del sito, estrae le fonti (script, CSS, immagini, font, iframe) e genera una bozza di Content-Security-Policy e un blocco .htaccess con header di sicurezza.</p>

  <form method="get" class="row g-3 mb-5">
    <div class="col-md-6">
      <label for="domain" class="form-label">Dominio (es: https://example.com)</label>
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

    <h4>Header di Sicurezza da Includere</h4>
    <!-- X-XSS-Protection -->
    <div class="form-check">
      <input class="form-check-input" type="checkbox" name="sec_headers[]" value="x_xss_protection" id="xss" <?php echo in_array('x_xss_protection', $secHeaders) ? 'checked' : ''; ?>>
      <label class="form-check-label" for="xss">
        X-XSS-Protection <small class="text-muted">(Protegge da attacchi XSS; deprecato nei browser moderni)</small>
      </label>
    </div>
    <!-- X-Frame-Options -->
    <div class="form-check">
      <input class="form-check-input" type="checkbox" name="sec_headers[]" value="x_frame_options" id="xfo" <?php echo in_array('x_frame_options', $secHeaders) ? 'checked' : ''; ?>>
      <label class="form-check-label" for="xfo">
        X-Frame-Options <small class="text-muted">(Previene clickjacking)</small>
      </label>
    </div>
    <div class="ms-4 mb-3" style="max-width:300px;">
      <label for="x_frame_option" class="form-label">Valore</label>
      <select name="x_frame_option" id="x_frame_option" class="form-select">
        <option value="SAMEORIGIN" <?php if($xFrameOption==='SAMEORIGIN') echo 'selected'; ?>>SAMEORIGIN</option>
        <option value="DENY" <?php if($xFrameOption==='DENY') echo 'selected'; ?>>DENY</option>
        <option value="ALLOW-FROM" <?php if($xFrameOption==='ALLOW-FROM') echo 'selected'; ?>>ALLOW-FROM</option>
      </select>
    </div>
    <!-- X-Content-Type-Options -->
    <div class="form-check">
      <input class="form-check-input" type="checkbox" name="sec_headers[]" value="x_content_type_options" id="xcto" <?php echo in_array('x_content_type_options', $secHeaders) ? 'checked' : ''; ?>>
      <label class="form-check-label" for="xcto">
        X-Content-Type-Options <small class="text-muted">(Imposta "nosniff")</small>
      </label>
    </div>
    <!-- Strict-Transport-Security -->
    <div class="form-check">
      <input class="form-check-input" type="checkbox" name="sec_headers[]" value="strict_transport_security" id="hsts" <?php echo in_array('strict_transport_security', $secHeaders) ? 'checked' : ''; ?>>
      <label class="form-check-label" for="hsts">
        Strict-Transport-Security (HSTS) <small class="text-muted">(Richiede HTTPS e protegge dalle downgrade attack)</small>
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
    <!-- Referrer-Policy -->
    <div class="form-check">
      <input class="form-check-input" type="checkbox" name="sec_headers[]" value="referrer_policy" id="rp" <?php echo in_array('referrer_policy', $secHeaders) ? 'checked' : ''; ?>>
      <label class="form-check-label" for="rp">
        Referrer-Policy <small class="text-muted">(Controlla l'invio dell'header Referer)</small>
      </label>
    </div>
    <div class="ms-4 mb-3" style="max-width:300px;">
      <label for="referrer_policy" class="form-label">Valore</label>
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
    <!-- Permissions-Policy -->
    <div class="form-check">
      <input class="form-check-input" type="checkbox" name="sec_headers[]" value="permissions_policy" id="pp" <?php echo in_array('permissions_policy', $secHeaders) ? 'checked' : ''; ?>>
      <label class="form-check-label" for="pp">
        Permissions-Policy <small class="text-muted">(Limita l'accesso a API: geolocalizzazione, camera, microfono, payment, fullscreen)</small>
      </label>
    </div>
    <div class="row ms-4 mb-3">
      <div class="col-md-2">
        <label for="perm_geolocation" class="form-label">geolocation</label>
        <input type="text" name="perm_geolocation" id="perm_geolocation" class="form-control" value="<?php echo htmlspecialchars($permGeolocation); ?>">
      </div>
      <div class="col-md-2">
        <label for="perm_camera" class="form-label">camera</label>
        <input type="text" name="perm_camera" id="perm_camera" class="form-control" value="<?php echo htmlspecialchars($permCamera); ?>">
      </div>
      <div class="col-md-2">
        <label for="perm_microphone" class="form-label">microphone</label>
        <input type="text" name="perm_microphone" id="perm_microphone" class="form-control" value="<?php echo htmlspecialchars($permMicrophone); ?>">
      </div>
      <div class="col-md-2">
        <label for="perm_payment" class="form-label">payment</label>
        <input type="text" name="perm_payment" id="perm_payment" class="form-control" value="<?php echo htmlspecialchars($permPayment); ?>">
      </div>
      <div class="col-md-2">
        <label for="perm_fullscreen" class="form-label">fullscreen</label>
        <input type="text" name="perm_fullscreen" id="perm_fullscreen" class="form-control" value="<?php echo htmlspecialchars($permFullscreen); ?>">
      </div>
    </div>
    <!-- COOP -->
    <div class="form-check">
      <input class="form-check-input" type="checkbox" name="sec_headers[]" value="coop" id="coop_cb" <?php echo in_array('coop', $secHeaders) ? 'checked' : ''; ?>>
      <label class="form-check-label" for="coop_cb">
        Cross-Origin-Opener-Policy (COOP) <small class="text-muted">(Isola la finestra da contesti cross-origin)</small>
      </label>
    </div>
    <div class="ms-4 mb-3" style="max-width:300px;">
      <label for="coop" class="form-label">Valore</label>
      <select name="coop" id="coop" class="form-select">
        <option value="unsafe-none" <?php if($coop==='unsafe-none') echo 'selected'; ?>>unsafe-none</option>
        <option value="same-origin" <?php if($coop==='same-origin') echo 'selected'; ?>>same-origin</option>
        <option value="same-origin-allow-popups" <?php if($coop==='same-origin-allow-popups') echo 'selected'; ?>>same-origin-allow-popups</option>
      </select>
    </div>
    <!-- COEP -->
    <div class="form-check">
      <input class="form-check-input" type="checkbox" name="sec_headers[]" value="coep" id="coep_cb" <?php echo in_array('coep', $secHeaders) ? 'checked' : ''; ?>>
      <label class="form-check-label" for="coep_cb">
        Cross-Origin-Embedder-Policy (COEP) <small class="text-muted">(Richiede che le risorse cross-origin siano servite con CORP/CORS)</small>
      </label>
    </div>
    <div class="ms-4 mb-3" style="max-width:300px;">
      <label for="coep" class="form-label">Valore</label>
      <select name="coep" id="coep" class="form-select">
        <option value="unsafe-none" <?php if($coep==='unsafe-none') echo 'selected'; ?>>unsafe-none</option>
        <option value="require-corp" <?php if($coep==='require-corp') echo 'selected'; ?>>require-corp</option>
        <option value="credentialless" <?php if($coep==='credentialless') echo 'selected'; ?>>credentialless</option>
      </select>
    </div>
    <!-- CORP -->
    <div class="form-check">
      <input class="form-check-input" type="checkbox" name="sec_headers[]" value="corp" id="corp_cb" <?php echo in_array('corp', $secHeaders) ? 'checked' : ''; ?>>
      <label class="form-check-label" for="corp_cb">
        Cross-Origin-Resource-Policy (CORP) <small class="text-muted">(Definisce chi può incorporare le tue risorse)</small>
      </label>
    </div>
    <div class="ms-4 mb-3" style="max-width:300px;">
      <label for="corp" class="form-label">Valore</label>
      <select name="corp" id="corp" class="form-select">
        <option value="cross-origin" <?php if($corp==='cross-origin') echo 'selected'; ?>>cross-origin</option>
        <option value="same-site" <?php if($corp==='same-site') echo 'selected'; ?>>same-site</option>
        <option value="same-origin" <?php if($corp==='same-origin') echo 'selected'; ?>>same-origin</option>
      </select>
    </div>

    <div class="col-12">
      <button type="submit" class="btn btn-primary">Scansiona e genera header</button>
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
        <p class="text-muted">La CSP include gli origin delle risorse trovate e <code>'self'</code>. Ricorda che se usi script/stili inline potresti dover aggiungere <code>'unsafe-inline'</code> oppure nonce/hash.</p>
        <pre class="bg-light p-3"><?php echo htmlspecialchars($cspString); ?></pre>
      </div>
    </div>

    <div class="card mb-4">
      <div class="card-body">
        <h3 class="card-title h5">Blocco .htaccess generato</h3>
        <?php if ($htaccessBlock): ?>
          <pre class="bg-light p-3"><?php echo htmlspecialchars($htaccessBlock); ?></pre>
          <p class="text-muted">Copia questo blocco nel tuo file <code>.htaccess</code> o nella configurazione del VirtualHost. Assicurati che <code>mod_headers</code> sia abilitato e testa a fondo il sito.</p>
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
