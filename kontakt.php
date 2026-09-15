<?php
/**
 * Versand des Kontaktformulars. Nimmt JSON per POST, prüft die Felder, schickt eine
 * Klartext-Mail an EMPFAENGER. Speichert nichts außer einem kurzlebigen Zähler je IP
 * für den Spam-Schutz.
 *
 * Diese drei Werte selbst eintragen:
 */
const EMPFAENGER    = 'hallo@marcel-worpswede.de';
const ABSENDER      = 'website@aemwe.xyz';   // muss zur Domain des Webspace passen, sonst landet es im Spam
const ABSENDER_NAME = 'Website Marcel';

/* ── Grenzen ── */
const MAX_BODY_BYTES   = 16384;
const MAX_KURZ         = 200;
const MAX_TELEFON      = 50;
const MAX_TEXT         = 2000;
const MAX_LISTE        = 10;
const MIN_SEKUNDEN     = 4;        // Zeit zwischen Seitenaufruf und Absenden
const RATE_MAX         = 5;        // Anfragen je IP ...
const RATE_FENSTER     = 3600;     // ... in diesem Zeitraum (Sekunden)

const DRINGLICHKEIT = [
    null,
    ['Nur so eine Idee', 'kein Zeitdruck'],
    ['Irgendwann dieses Jahr', 'innerhalb des Jahres wäre gut'],
    ['Entspannt', 'in den nächsten Monaten'],
    ['Bald', 'in den nächsten Wochen'],
    ['Dringend', 'innerhalb einer Woche'],
    ['Sehr dringend', 'in den nächsten Tagen'],
];
const WEG_TEXT = [
    'schritte' => 'Schritt für Schritt',
    'freitext' => 'Freitext',
    'sprechen' => 'Möchte einfach sprechen',
];
const KANAL_TEXT = ['anrufen' => 'Lieber anrufen', 'schreiben' => 'Lieber schreiben'];
const NA = 'nicht angegeben';

date_default_timezone_set('Europe/Berlin');
header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store');

function antwort(int $code, array $daten): never
{
    http_response_code($code);
    echo json_encode($daten, JSON_UNESCAPED_UNICODE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    antwort(405, ['status' => 'fehler', 'grund' => 'methode']);
}
if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) {
    antwort(415, ['status' => 'fehler', 'grund' => 'format']);
}

$roh = file_get_contents('php://input', false, null, 0, MAX_BODY_BYTES + 1);
if ($roh === false || strlen($roh) > MAX_BODY_BYTES) {
    antwort(413, ['status' => 'fehler', 'grund' => 'zu-gross']);
}
$json = json_decode($roh, true);
if (!is_array($json)) {
    antwort(400, ['status' => 'fehler', 'grund' => 'json']);
}

/* ── Felder in Form bringen ── */

/** Einzeiliger Text: gekappt, ohne Zeilenumbrüche (Header-Injection) und Steuerzeichen. */
function kurz(mixed $wert, int $max): string
{
    if (!is_string($wert)) return '';
    $wert = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $wert) ?? '';
    return trim(mb_substr($wert, 0, $max));
}

/** Mehrzeiliger Text: gekappt, Zeilenumbrüche bleiben, andere Steuerzeichen nicht. */
function lang(mixed $wert, int $max): string
{
    if (!is_string($wert)) return '';
    $wert = str_replace("\r\n", "\n", $wert);
    $wert = preg_replace('/[^\P{C}\n]+/u', '', $wert) ?? '';
    return trim(mb_substr($wert, 0, $max));
}

function liste(mixed $wert): array
{
    if (!is_array($wert)) return [];
    $aus = [];
    foreach (array_slice($wert, 0, MAX_LISTE) as $eintrag) {
        $e = kurz($eintrag, 100);
        if ($e !== '') $aus[] = $e;
    }
    return $aus;
}

$wer      = kurz($json['wer'] ?? '', 100);
$worum    = liste($json['worum'] ?? []);
$stufe    = (int) ($json['dringlichkeit'] ?? 0);
$stufe    = ($stufe >= 0 && $stufe < count(DRINGLICHKEIT)) ? $stufe : 0;
$nervt    = lang($json['nervt'] ?? '', MAX_TEXT);
$freitext = lang($json['freitext'] ?? '', MAX_TEXT);
$name     = kurz($json['name'] ?? '', MAX_KURZ);
$email    = kurz($json['email'] ?? '', MAX_KURZ);
$telefon  = kurz($json['telefon'] ?? '', MAX_TELEFON);
$kanal    = kurz($json['kanal'] ?? '', 20);
$kanal    = isset(KANAL_TEXT[$kanal]) ? $kanal : '';
$kopie    = ($json['kopie'] ?? false) === true;
$weg      = kurz($json['weg'] ?? '', 20);
$weg      = isset(WEG_TEXT[$weg]) ? $weg : 'schritte';
$honig    = kurz($json['website'] ?? '', 50);
$geoeffnet = (float) ($json['geoeffnetUm'] ?? 0) / 1000;

/* ── Pflichtregel ── */

if ($email === '' && $telefon === '') {
    antwort(422, ['status' => 'fehler', 'grund' => 'kontakt']);
}
if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
    antwort(422, ['status' => 'fehler', 'grund' => 'email']);
}

/* ── Spam-Schutz: bei Treffer "ok" zurückgeben, aber nichts senden ── */

function spam(): bool
{
    global $honig, $geoeffnet;
    if ($honig !== '') return true;
    if ($geoeffnet <= 0 || (microtime(true) - $geoeffnet) < MIN_SEKUNDEN) return true;

    $ip    = $_SERVER['REMOTE_ADDR'] ?? 'unbekannt';
    $datei = sys_get_temp_dir() . '/kontakt-' . sha1($ip);
    $jetzt = time();

    // Abgelaufene Zähler aller IPs löschen, damit nichts länger als RATE_FENSTER liegen bleibt
    // (so steht es auch in der Datenschutzerklärung).
    foreach (glob(sys_get_temp_dir() . '/kontakt-*') ?: [] as $alt) {
        if (preg_match('/\/kontakt-[0-9a-f]{40}$/', $alt) && $jetzt - (int) @filemtime($alt) >= RATE_FENSTER) {
            @unlink($alt);
        }
    }
    $zeiten = [];
    if (is_file($datei)) {
        foreach (file($datei, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $z) {
            if ($jetzt - (int) $z < RATE_FENSTER) $zeiten[] = (int) $z;
        }
    }
    $zeiten[] = $jetzt;
    @file_put_contents($datei, implode("\n", $zeiten) . "\n", LOCK_EX);
    return count($zeiten) > RATE_MAX;
}

if (spam()) {
    antwort(200, ['status' => 'ok']);
}

/* ── Mail bauen (gleiche Struktur wie die Vorschau im Browser) ── */

function zeile(string $label, string $wert): string
{
    return str_pad($label, 18) . ($wert !== '' ? $wert : NA);
}

function block(string $label, string $text): array
{
    if ($text === '') return [zeile($label . ':', '')];
    $aus = [$label . ':'];
    foreach (explode("\n", $text) as $l) $aus[] = '  ' . $l;
    return $aus;
}

$d = DRINGLICHKEIT[$stufe];
$dringText = $d ? $d[0] . ' (' . $d[1] . ')' : '';

$zeilen = [];
if ($weg === 'sprechen') {
    $zeilen[] = 'Möchte einfach sprechen.';
    $zeilen[] = '';
}
$zeilen[] = 'Neue Anfrage über die Website';
$zeilen[] = 'Weg: ' . WEG_TEXT[$weg];
$zeilen[] = 'Zeit: ' . date('d.m.Y, H:i');
$zeilen[] = '';
$zeilen[] = zeile('Wer:', $wer);
$zeilen[] = zeile('Worum:', implode(', ', $worum));
$zeilen[] = zeile('Dringlichkeit:', $dringText);
array_push($zeilen, ...block('Nervt am meisten', $nervt));
if ($weg === 'freitext' || $freitext !== '') {
    array_push($zeilen, ...block('Freitext', $freitext));
}
$zeilen[] = '';
$zeilen[] = zeile('Kontakt:', $name);
$zeilen[] = zeile('E-Mail:', $email);
$zeilen[] = zeile('Telefon:', $telefon);
$zeilen[] = zeile('Wunsch:', $kanal !== '' ? KANAL_TEXT[$kanal] : '');
$text = implode("\n", $zeilen) . "\n";

$betreffTeile = [];
if ($wer !== '') $betreffTeile[] = $wer;
if ($weg === 'sprechen') {
    $betreffTeile[] = 'möchte einfach sprechen';
} elseif ($weg === 'freitext') {
    $betreffTeile[] = 'Freitext';
} else {
    if ($worum) {
        $betreffTeile[] = count($worum) <= 3
            ? implode(', ', $worum)
            : implode(', ', array_slice($worum, 0, 3)) . ', …';
    }
    if ($d) $betreffTeile[] = $d[0];
}
$betreff = $betreffTeile ? 'Anfrage: ' . implode(' · ', $betreffTeile) : 'Anfrage über die Website';

/* ── Senden ── */

function sende(string $an, string $betreff, string $text, ?string $replyTo): bool
{
    $kopf = [
        'From: ' . mb_encode_mimeheader(ABSENDER_NAME, 'UTF-8') . ' <' . ABSENDER . '>',
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: 8bit',
        'X-Mailer: kontakt.php',
    ];
    if ($replyTo !== null) $kopf[] = 'Reply-To: ' . $replyTo;
    return mail($an, mb_encode_mimeheader($betreff, 'UTF-8'), $text, implode("\r\n", $kopf), '-f' . ABSENDER);
}

$ok = sende(EMPFAENGER, $betreff, $text, $email !== '' ? $email : null);
if (!$ok) {
    error_log('kontakt.php: mail() fehlgeschlagen');
    antwort(500, ['status' => 'fehler', 'grund' => 'versand']);
}

if ($kopie && $email !== '') {
    $vorspann = "Hallo" . ($name !== '' ? ' ' . $name : '') . ",\n\n"
        . "das ist die Kopie deiner Anfrage über die Website. Ich melde mich innerhalb von zwei Werktagen.\n\n"
        . "Marcel\n\n" . str_repeat('-', 40) . "\n\n";
    sende($email, 'Kopie deiner Anfrage an Marcel', $vorspann . $text, null);
}

antwort(200, ['status' => 'ok']);
