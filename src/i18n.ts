// ── i18n Module ── Edge Secrets ─────────────────────────────────────────────

export type LangCode = 'en' | 'pl' | 'de' | 'fr' | 'es' | 'uk' | 'pt' | 'zh' | 'cs'

export const SUPPORTED_LANGS: readonly LangCode[] = ['en', 'pl', 'de', 'fr', 'es', 'uk', 'pt', 'zh', 'cs'] as const

export interface Translations {
  // ── Public pages (receive / share) ──
  title_cred: string
  title_file: string
  label_key: string
  placeholder_key: string
  btn_decrypt: string
  ready_msg: string
  btn_open: string
  label_decrypted: string
  btn_copy: string
  file_protected: string
  btn_unlock: string

  // ── Gen panel — tabs ──
  tab_creds: string
  tab_files: string
  tab_links: string

  // ── Gen panel — credentials ──
  label_secret: string
  action_gen_password: string
  placeholder_secret: string
  label_encrypt_key: string
  action_gen_key: string
  placeholder_encrypt: string
  label_ttl: string
  ttl_1h: string
  ttl_24h: string
  ttl_72h: string
  btn_generate_links: string
  option1_manual: string
  option2_fast: string
  copy: string
  btn_new_operation: string

  // ── Gen panel — files ──
  label_pwd_optional: string
  placeholder_leave_empty: string
  label_retention: string
  label_download_limit: string
  ttl_12h: string
  ttl_2d: string
  ttl_7d: string
  limit_1: string
  limit_5: string
  limit_unlimited: string
  btn_send_file: string
  label_storage: string
  loading: string

  // ── Gen panel — links ──
  label_target_url: string
  label_expiry: string
  label_click_limit: string
  ttl_never: string
  limit_10: string
  limit_100: string
  btn_shorten: string
  label_short_link: string
  btn_new_link: string

  // ── Settings panel ──
  cfg_accent: string
  cfg_bg: string
  cfg_branding: string
  cfg_name: string
  cfg_tagline_label: string
  cfg_tagline_placeholder: string
  cfg_logo_label: string
  cfg_logo_specs: string
  cfg_upload: string
  cfg_delete: string

  // ── QR modal ──
  qr_title: string
  qr_close: string

  // ── Client-side JS strings (passed via window.L) ──
  js_copied: string
  js_manual: string
  js_nopass: string
  js_timer: string
  js_error: string
  js_info: string
  js_enter_data: string
  js_server_error: string
  js_select_file: string
  js_initializing: string
  js_uploading: string
  js_done: string
  js_click_select: string
  js_error_prefix: string
  js_used: string
  js_downloads: string
  js_confirm_delete: string
  js_enter_url: string
  js_error_occurred: string
  js_shorten_fail: string
  js_logo_max: string
  js_logo_active: string
  js_no_logo: string
  js_logo_fail: string
  js_saved: string
  js_save: string
  js_btn_delete: string

  // ── Language picker ──
  lang_picker_title: string

  // ── Turnstile ──
  cfg_turnstile: string
  cfg_turnstile_site_key: string
  cfg_turnstile_creds: string
  cfg_turnstile_files: string
  ts_verify: string

  // ── Storage limits (configurable in Appearance) ──
  cfg_limits_title: string
  cfg_max_storage: string
  cfg_max_upload: string
  cfg_limits_hint: string
  cfg_limits_invalid: string
  cfg_limits_upload_gt_storage: string
  cfg_free_warning_title: string
  cfg_free_warning_body: string
  cfg_okay_mismatch: string
  cfg_btn_confirm: string
  cfg_btn_cancel: string
  js_file_too_large: string

  // ── E2EE file sharing (client-side encryption) ──
  cfg_turnstile_files_e2ee: string
  file_toggle_e2ee: string
  file_e2ee_hint: string
  file_e2ee_label_key: string
  file_e2ee_protected: string
  file_e2ee_btn_decrypt: string
  file_list_encrypted: string
  js_e2ee_max_size: string
  js_e2ee_require_pwd: string
  js_e2ee_encrypting: string
  js_e2ee_preparing: string
  js_e2ee_downloading: string
  js_e2ee_decrypting: string
  js_e2ee_decrypt_failed: string

  // ── Drag & drop overlay ──
  file_drop_here: string
}

// ── Translations ────────────────────────────────────────────────────────────

export const I18N: Record<LangCode, Translations> = {

  // ────────────────────────── English ──────────────────────────
  en: {
    title_cred: 'Secure Data Retrieval',
    title_file: 'Secure File Download',
    label_key: 'ENTER DECRYPTION KEY',
    placeholder_key: 'Access key...',
    btn_decrypt: 'DECRYPT',
    ready_msg: 'DATA READY TO READ',
    btn_open: 'OPEN MESSAGE',
    label_decrypted: 'DECRYPTED DATA:',
    btn_copy: 'COPY CONTENT',
    file_protected: 'PASSWORD PROTECTED FILE',
    btn_unlock: 'UNLOCK & DOWNLOAD',

    tab_creds: 'CREDENTIALS',
    tab_files: 'FILES',
    tab_links: 'LINKS',

    label_secret: 'SECRET CONTENT',
    action_gen_password: 'GENERATE PASSWORD',
    placeholder_secret: 'Paste confidential data here...',
    label_encrypt_key: 'ENCRYPTION KEY',
    action_gen_key: 'GENERATE KEY',
    placeholder_encrypt: 'Password to unlock...',
    label_ttl: 'EXPIRATION TIME',
    ttl_1h: '1 Hour',
    ttl_24h: '24 Hours',
    ttl_72h: '72 Hours',
    btn_generate_links: 'GENERATE LINKS',
    option1_manual: 'OPTION 1: MANUAL (WITHOUT PASSWORD)',
    option2_fast: 'OPTION 2: FAST (LINK WITH PASSWORD)',
    copy: 'COPY',
    btn_new_operation: 'NEW OPERATION',

    label_pwd_optional: 'PASSWORD (OPTIONAL)',
    placeholder_leave_empty: 'Leave empty for public link',
    label_retention: 'RETENTION',
    label_download_limit: 'DOWNLOAD LIMIT',
    ttl_12h: '12 Hours',
    ttl_2d: '2 Days',
    ttl_7d: '7 Days',
    limit_1: '1 Time',
    limit_5: '5 Times',
    limit_unlimited: 'Unlimited',
    btn_send_file: 'UPLOAD FILE',
    label_storage: 'STORAGE',
    loading: 'Loading...',

    label_target_url: 'TARGET URL',
    label_expiry: 'EXPIRATION',
    label_click_limit: 'CLICK LIMIT',
    ttl_never: 'Never',
    limit_10: '10 Times',
    limit_100: '100 Times',
    btn_shorten: 'SHORTEN LINK',
    label_short_link: 'SHORTENED LINK',
    btn_new_link: 'NEW LINK',

    cfg_accent: 'Accent',
    cfg_bg: 'Background',
    cfg_branding: 'Branding',
    cfg_name: 'Name',
    cfg_tagline_label: 'Tagline',
    cfg_tagline_placeholder: 'Optional subtitle...',
    cfg_logo_label: 'Logo',
    cfg_logo_specs: 'PNG / SVG / WebP, max 256 KB',
    cfg_upload: 'UPLOAD',
    cfg_delete: 'DELETE',

    qr_title: 'QR CODE',
    qr_close: 'CLOSE',

    js_copied: 'Copied!',
    js_manual: 'Copy manually: ',
    js_nopass: 'Password required',
    js_timer: 'AUTO-DELETE IN: ',
    js_error: 'ERROR',
    js_info: 'INFO',
    js_enter_data: 'Enter your data.',
    js_server_error: 'Server error',
    js_select_file: 'Select a file',
    js_initializing: 'Initializing...',
    js_uploading: 'Uploading: ',
    js_done: 'Done!',
    js_click_select: 'CLICK TO SELECT FILE',
    js_error_prefix: 'Error: ',
    js_used: 'Used: ',
    js_downloads: 'Downloads: ',
    js_confirm_delete: 'Delete file permanently?',
    js_enter_url: 'Enter URL',
    js_error_occurred: 'An error occurred',
    js_shorten_fail: 'Failed to shorten link',
    js_logo_max: 'Logo max 256 KB',
    js_logo_active: 'Logo active',
    js_no_logo: 'No logo',
    js_logo_fail: 'Failed to upload logo',
    js_saved: 'SAVED \u2713',
    js_save: 'SAVE',
    js_btn_delete: 'DELETE',

    lang_picker_title: 'Language',

    cfg_turnstile: 'TURNSTILE',
    cfg_turnstile_site_key: 'Site Key',
    cfg_turnstile_creds: 'Protect secret retrieval',
    cfg_turnstile_files: 'Protect file downloads',
    ts_verify: 'SECURITY CHECK',

    cfg_limits_title: 'STORAGE LIMITS',
    cfg_max_storage: 'TOTAL STORAGE (GB)',
    cfg_max_upload: 'MAX PER FILE (GB)',
    cfg_limits_hint: 'Cloudflare R2 free tier is 10 GB. Going beyond requires confirmation and may incur costs.',
    cfg_limits_invalid: 'Limit values must be positive numbers.',
    cfg_limits_upload_gt_storage: 'Per-file limit cannot exceed total storage.',
    cfg_free_warning_title: 'EXCEEDING FREE TIER',
    cfg_free_warning_body: 'The values you entered go beyond the Cloudflare R2 free tier (10 GB) and may incur storage costs. Type OKAY (uppercase) to confirm:',
    cfg_okay_mismatch: 'You must type OKAY exactly (uppercase).',
    cfg_btn_confirm: 'CONFIRM',
    cfg_btn_cancel: 'CANCEL',
    js_file_too_large: 'File exceeds the configured upload limit.',

    cfg_turnstile_files_e2ee: 'Protect E2EE downloads',
    file_toggle_e2ee: 'END-TO-END ENCRYPTION',
    file_e2ee_hint: 'Client-side AES-GCM + Argon2id. Server never sees contents or passphrase. Max 150 MB. Losing the passphrase makes the file permanently unrecoverable.',
    file_e2ee_label_key: 'ENCRYPTION PASSPHRASE',
    file_e2ee_protected: 'ENCRYPTED FILE',
    file_e2ee_btn_decrypt: 'DECRYPT & DOWNLOAD',
    file_list_encrypted: 'End-to-end encrypted — passphrase required',
    js_e2ee_max_size: 'File exceeds the 150 MB E2EE limit.',
    js_e2ee_require_pwd: 'E2EE requires a passphrase.',
    js_e2ee_encrypting: 'Encrypting...',
    js_e2ee_preparing: 'Preparing...',
    js_e2ee_downloading: 'Downloading',
    js_e2ee_decrypting: 'Decrypting...',
    js_e2ee_decrypt_failed: 'Decryption failed — wrong passphrase?',
    file_drop_here: 'Drop file to upload',
  },

  // ────────────────────────── Polski ──────────────────────────
  pl: {
    title_cred: 'Odbierz wiadomość',
    title_file: 'Pobieranie Pliku',
    label_key: 'WPROWADŹ KLUCZ DESZYFRUJĄCY',
    placeholder_key: 'Klucz dostępu...',
    btn_decrypt: 'ODSZYFRUJ',
    ready_msg: 'DANE GOTOWE DO ODCZYTU',
    btn_open: 'OTWÓRZ WIADOMOŚĆ',
    label_decrypted: 'DANE ODSZYFROWANE:',
    btn_copy: 'KOPIUJ TREŚĆ',
    file_protected: 'PLIK ZABEZPIECZONY HASŁEM',
    btn_unlock: 'ODBLOKUJ I POBIERZ',

    tab_creds: 'POŚWIADCZENIA',
    tab_files: 'PLIKI',
    tab_links: 'LINKI',

    label_secret: 'TREŚĆ SEKRETU',
    action_gen_password: 'GENERUJ HASŁO',
    placeholder_secret: 'Wklej poufne dane tutaj...',
    label_encrypt_key: 'KLUCZ SZYFRUJĄCY',
    action_gen_key: 'LOSUJ KLUCZ',
    placeholder_encrypt: 'Hasło do odblokowania...',
    label_ttl: 'CZAS WYGAŚNIĘCIA',
    ttl_1h: '1 Godzina',
    ttl_24h: '24 Godziny',
    ttl_72h: '72 Godziny',
    btn_generate_links: 'GENERUJ LINKI',
    option1_manual: 'OPCJA 1: MANUAL (BEZ HASŁA)',
    option2_fast: 'OPCJA 2: FAST (LINK Z HASŁEM)',
    copy: 'KOPIUJ',
    btn_new_operation: 'NOWA OPERACJA',

    label_pwd_optional: 'HASŁO (OPCJONALNE)',
    placeholder_leave_empty: 'Zostaw puste dla linku publicznego',
    label_retention: 'RETENCJA',
    label_download_limit: 'LIMIT POBRAŃ',
    ttl_12h: '12 Godzin',
    ttl_2d: '2 Dni',
    ttl_7d: '7 Dni',
    limit_1: '1 Raz',
    limit_5: '5 Razy',
    limit_unlimited: 'Bez limitu',
    btn_send_file: 'WYŚLIJ PLIK',
    label_storage: 'STORAGE',
    loading: 'Ładowanie...',

    label_target_url: 'DOCELOWY URL',
    label_expiry: 'WYGAŚNIĘCIE',
    label_click_limit: 'LIMIT KLIKNIĘĆ',
    ttl_never: 'Nigdy',
    limit_10: '10 Razy',
    limit_100: '100 Razy',
    btn_shorten: 'SKRÓĆ LINK',
    label_short_link: 'SKRÓCONY LINK',
    btn_new_link: 'NOWY LINK',

    cfg_accent: 'Akcent',
    cfg_bg: 'Tło',
    cfg_branding: 'Branding',
    cfg_name: 'Nazwa',
    cfg_tagline_label: 'Tagline',
    cfg_tagline_placeholder: 'Opcjonalny podpis...',
    cfg_logo_label: 'Logo',
    cfg_logo_specs: 'PNG / SVG / WebP, max 256 KB',
    cfg_upload: 'WGRAJ',
    cfg_delete: 'USUŃ',

    qr_title: 'KOD QR',
    qr_close: 'ZAMKNIJ',

    js_copied: 'Skopiowano!',
    js_manual: 'Skopiuj ręcznie: ',
    js_nopass: 'Brak hasła',
    js_timer: 'ZAPOMINANIE ZA: ',
    js_error: 'BŁĄD',
    js_info: 'INFO',
    js_enter_data: 'Wpisz dane.',
    js_server_error: 'Błąd serwera',
    js_select_file: 'Wybierz plik',
    js_initializing: 'Inicjowanie...',
    js_uploading: 'Wysyłanie: ',
    js_done: 'Gotowe!',
    js_click_select: 'KLIKNIJ ABY WYBRAĆ PLIK',
    js_error_prefix: 'Błąd: ',
    js_used: 'Użyto: ',
    js_downloads: 'Pobrań: ',
    js_confirm_delete: 'Usunąć plik trwale?',
    js_enter_url: 'Wprowadź URL',
    js_error_occurred: 'Wystąpił błąd',
    js_shorten_fail: 'Nie udało się skrócić linku',
    js_logo_max: 'Logo max 256 KB',
    js_logo_active: 'Logo aktywne',
    js_no_logo: 'Brak logo',
    js_logo_fail: 'Nie udało się wgrać logo',
    js_saved: 'ZAPISANO \u2713',
    js_save: 'ZAPISZ',
    js_btn_delete: 'USUŃ',

    lang_picker_title: 'Język',

    cfg_turnstile: 'TURNSTILE',
    cfg_turnstile_site_key: 'Site Key',
    cfg_turnstile_creds: 'Chroń odbiór secretów',
    cfg_turnstile_files: 'Chroń pobieranie plików',
    ts_verify: 'WERYFIKACJA BEZPIECZEŃSTWA',

    cfg_limits_title: 'LIMITY POJEMNOŚCI',
    cfg_max_storage: 'CAŁKOWITA POJEMNOŚĆ (GB)',
    cfg_max_upload: 'MAKS. NA PLIK (GB)',
    cfg_limits_hint: 'Darmowy plan Cloudflare R2 to 10 GB. Przekroczenie wymaga potwierdzenia i może skutkować kosztami.',
    cfg_limits_invalid: 'Wartości limitów muszą być liczbami dodatnimi.',
    cfg_limits_upload_gt_storage: 'Limit na plik nie może przekraczać całkowitej pojemności.',
    cfg_free_warning_title: 'PRZEKROCZENIE PLANU FREE',
    cfg_free_warning_body: 'Wpisane wartości przekraczają darmowy plan Cloudflare R2 (10 GB) i mogą skutkować kosztami przechowywania. Wpisz OKAY (wielkimi literami), aby potwierdzić:',
    cfg_okay_mismatch: 'Musisz wpisać OKAY dokładnie (wielkie litery).',
    cfg_btn_confirm: 'POTWIERDŹ',
    cfg_btn_cancel: 'ANULUJ',
    js_file_too_large: 'Plik przekracza skonfigurowany limit uploadu.',

    cfg_turnstile_files_e2ee: 'Ochrona pobierania E2EE',
    file_toggle_e2ee: 'SZYFROWANIE END-TO-END',
    file_e2ee_hint: 'AES-GCM + Argon2id po stronie klienta. Serwer nie widzi zawartości ani hasła. Maks. 150 MB. Utrata hasła = plik nieodzyskiwalny.',
    file_e2ee_label_key: 'HASŁO SZYFRUJĄCE',
    file_e2ee_protected: 'ZASZYFROWANY PLIK',
    file_e2ee_btn_decrypt: 'ODSZYFRUJ I POBIERZ',
    file_list_encrypted: 'Szyfrowany end-to-end — wymagane hasło',
    js_e2ee_max_size: 'Plik przekracza limit 150 MB dla E2EE.',
    js_e2ee_require_pwd: 'E2EE wymaga hasła.',
    js_e2ee_encrypting: 'Szyfrowanie...',
    js_e2ee_preparing: 'Przygotowywanie...',
    js_e2ee_downloading: 'Pobieranie',
    js_e2ee_decrypting: 'Odszyfrowywanie...',
    js_e2ee_decrypt_failed: 'Deszyfrowanie nieudane — błędne hasło?',
    file_drop_here: 'Upuść plik aby wgrać',
  },

  // ────────────────────────── Deutsch ──────────────────────────
  de: {
    title_cred: 'Sichere Datenabfrage',
    title_file: 'Sicherer Dateidownload',
    label_key: 'ENTSCHLÜSSELUNGSSCHLÜSSEL EINGEBEN',
    placeholder_key: 'Zugriffsschlüssel...',
    btn_decrypt: 'ENTSCHLÜSSELN',
    ready_msg: 'DATEN BEREIT ZUM LESEN',
    btn_open: 'NACHRICHT ÖFFNEN',
    label_decrypted: 'ENTSCHLÜSSELTE DATEN:',
    btn_copy: 'INHALT KOPIEREN',
    file_protected: 'PASSWORTGESCHÜTZTE DATEI',
    btn_unlock: 'ENTSPERREN & HERUNTERLADEN',

    tab_creds: 'ZUGANGSDATEN',
    tab_files: 'DATEIEN',
    tab_links: 'LINKS',

    label_secret: 'GEHEIMER INHALT',
    action_gen_password: 'PASSWORT GENERIEREN',
    placeholder_secret: 'Vertrauliche Daten hier einfügen...',
    label_encrypt_key: 'VERSCHLÜSSELUNGSSCHLÜSSEL',
    action_gen_key: 'SCHLÜSSEL GENERIEREN',
    placeholder_encrypt: 'Passwort zum Entsperren...',
    label_ttl: 'ABLAUFZEIT',
    ttl_1h: '1 Stunde',
    ttl_24h: '24 Stunden',
    ttl_72h: '72 Stunden',
    btn_generate_links: 'LINKS GENERIEREN',
    option1_manual: 'OPTION 1: MANUELL (OHNE PASSWORT)',
    option2_fast: 'OPTION 2: SCHNELL (LINK MIT PASSWORT)',
    copy: 'KOPIEREN',
    btn_new_operation: 'NEUER VORGANG',

    label_pwd_optional: 'PASSWORT (OPTIONAL)',
    placeholder_leave_empty: 'Leer lassen für öffentlichen Link',
    label_retention: 'AUFBEWAHRUNG',
    label_download_limit: 'DOWNLOAD-LIMIT',
    ttl_12h: '12 Stunden',
    ttl_2d: '2 Tage',
    ttl_7d: '7 Tage',
    limit_1: '1 Mal',
    limit_5: '5 Mal',
    limit_unlimited: 'Unbegrenzt',
    btn_send_file: 'DATEI HOCHLADEN',
    label_storage: 'SPEICHER',
    loading: 'Laden...',

    label_target_url: 'ZIEL-URL',
    label_expiry: 'ABLAUF',
    label_click_limit: 'KLICK-LIMIT',
    ttl_never: 'Nie',
    limit_10: '10 Mal',
    limit_100: '100 Mal',
    btn_shorten: 'LINK KÜRZEN',
    label_short_link: 'GEKÜRZTER LINK',
    btn_new_link: 'NEUER LINK',

    cfg_accent: 'Akzent',
    cfg_bg: 'Hintergrund',
    cfg_branding: 'Branding',
    cfg_name: 'Name',
    cfg_tagline_label: 'Tagline',
    cfg_tagline_placeholder: 'Optionaler Untertitel...',
    cfg_logo_label: 'Logo',
    cfg_logo_specs: 'PNG / SVG / WebP, max 256 KB',
    cfg_upload: 'HOCHLADEN',
    cfg_delete: 'LÖSCHEN',

    qr_title: 'QR-CODE',
    qr_close: 'SCHLIEßEN',

    js_copied: 'Kopiert!',
    js_manual: 'Manuell kopieren: ',
    js_nopass: 'Passwort erforderlich',
    js_timer: 'AUTO-LÖSCHUNG IN: ',
    js_error: 'FEHLER',
    js_info: 'INFO',
    js_enter_data: 'Daten eingeben.',
    js_server_error: 'Serverfehler',
    js_select_file: 'Datei auswählen',
    js_initializing: 'Initialisierung...',
    js_uploading: 'Hochladen: ',
    js_done: 'Fertig!',
    js_click_select: 'KLICKEN UM DATEI AUSZUWÄHLEN',
    js_error_prefix: 'Fehler: ',
    js_used: 'Belegt: ',
    js_downloads: 'Downloads: ',
    js_confirm_delete: 'Datei dauerhaft löschen?',
    js_enter_url: 'URL eingeben',
    js_error_occurred: 'Ein Fehler ist aufgetreten',
    js_shorten_fail: 'Link konnte nicht gekürzt werden',
    js_logo_max: 'Logo max 256 KB',
    js_logo_active: 'Logo aktiv',
    js_no_logo: 'Kein Logo',
    js_logo_fail: 'Logo-Upload fehlgeschlagen',
    js_saved: 'GESPEICHERT \u2713',
    js_save: 'SPEICHERN',
    js_btn_delete: 'LÖSCHEN',

    lang_picker_title: 'Sprache',

    cfg_turnstile: 'TURNSTILE',
    cfg_turnstile_site_key: 'Site Key',
    cfg_turnstile_creds: 'Secrets schützen',
    cfg_turnstile_files: 'Downloads schützen',
    ts_verify: 'SICHERHEITSCHECK',

    cfg_limits_title: 'SPEICHERLIMITS',
    cfg_max_storage: 'GESAMTSPEICHER (GB)',
    cfg_max_upload: 'MAX PRO DATEI (GB)',
    cfg_limits_hint: 'Cloudflare R2 Free-Tier beträgt 10 GB. Eine Überschreitung erfordert Bestätigung und kann Kosten verursachen.',
    cfg_limits_invalid: 'Limit-Werte müssen positive Zahlen sein.',
    cfg_limits_upload_gt_storage: 'Datei-Limit darf den Gesamtspeicher nicht überschreiten.',
    cfg_free_warning_title: 'FREE-TIER ÜBERSCHRITTEN',
    cfg_free_warning_body: 'Die eingegebenen Werte überschreiten den Cloudflare R2 Free-Tier (10 GB) und können Speicherkosten verursachen. Tippen Sie OKAY (Großbuchstaben) zur Bestätigung:',
    cfg_okay_mismatch: 'Sie müssen OKAY exakt (Großbuchstaben) eingeben.',
    cfg_btn_confirm: 'BESTÄTIGEN',
    cfg_btn_cancel: 'ABBRECHEN',
    js_file_too_large: 'Datei überschreitet das konfigurierte Upload-Limit.',

    cfg_turnstile_files_e2ee: 'E2EE-Downloads schützen',
    file_toggle_e2ee: 'END-TO-END-VERSCHLÜSSELUNG',
    file_e2ee_hint: 'Clientseitiges AES-GCM + Argon2id. Der Server sieht weder Inhalt noch Passphrase. Max 150 MB. Verlorene Passphrase macht die Datei dauerhaft nicht wiederherstellbar.',
    file_e2ee_label_key: 'VERSCHLÜSSELUNGSPASSPHRASE',
    file_e2ee_protected: 'VERSCHLÜSSELTE DATEI',
    file_e2ee_btn_decrypt: 'ENTSCHLÜSSELN & HERUNTERLADEN',
    file_list_encrypted: 'Ende-zu-Ende verschlüsselt — Passphrase erforderlich',
    js_e2ee_max_size: 'Datei überschreitet das 150-MB-E2EE-Limit.',
    js_e2ee_require_pwd: 'E2EE benötigt eine Passphrase.',
    js_e2ee_encrypting: 'Verschlüsselung...',
    js_e2ee_preparing: 'Vorbereitung...',
    js_e2ee_downloading: 'Herunterladen',
    js_e2ee_decrypting: 'Entschlüsselung...',
    js_e2ee_decrypt_failed: 'Entschlüsselung fehlgeschlagen — falsche Passphrase?',
    file_drop_here: 'Datei hier ablegen',
  },

  // ────────────────────────── Français ──────────────────────────
  fr: {
    title_cred: 'Récupération sécurisée',
    title_file: 'Téléchargement sécurisé',
    label_key: 'ENTREZ LA CLÉ DE DÉCHIFFREMENT',
    placeholder_key: "Clé d'accès...",
    btn_decrypt: 'DÉCHIFFRER',
    ready_msg: 'DONNÉES PRÊTES À LIRE',
    btn_open: 'OUVRIR LE MESSAGE',
    label_decrypted: 'DONNÉES DÉCHIFFRÉES :',
    btn_copy: 'COPIER LE CONTENU',
    file_protected: 'FICHIER PROTÉGÉ PAR MOT DE PASSE',
    btn_unlock: 'DÉVERROUILLER ET TÉLÉCHARGER',

    tab_creds: 'IDENTIFIANTS',
    tab_files: 'FICHIERS',
    tab_links: 'LIENS',

    label_secret: 'CONTENU SECRET',
    action_gen_password: 'GÉNÉRER MOT DE PASSE',
    placeholder_secret: 'Collez les données confidentielles ici...',
    label_encrypt_key: 'CLÉ DE CHIFFREMENT',
    action_gen_key: 'GÉNÉRER CLÉ',
    placeholder_encrypt: 'Mot de passe pour déverrouiller...',
    label_ttl: "DURÉE D'EXPIRATION",
    ttl_1h: '1 Heure',
    ttl_24h: '24 Heures',
    ttl_72h: '72 Heures',
    btn_generate_links: 'GÉNÉRER LES LIENS',
    option1_manual: 'OPTION 1 : MANUEL (SANS MOT DE PASSE)',
    option2_fast: 'OPTION 2 : RAPIDE (LIEN AVEC MOT DE PASSE)',
    copy: 'COPIER',
    btn_new_operation: 'NOUVELLE OPÉRATION',

    label_pwd_optional: 'MOT DE PASSE (OPTIONNEL)',
    placeholder_leave_empty: 'Laisser vide pour un lien public',
    label_retention: 'RÉTENTION',
    label_download_limit: 'LIMITE DE TÉLÉCHARGEMENTS',
    ttl_12h: '12 Heures',
    ttl_2d: '2 Jours',
    ttl_7d: '7 Jours',
    limit_1: '1 Fois',
    limit_5: '5 Fois',
    limit_unlimited: 'Illimité',
    btn_send_file: 'ENVOYER LE FICHIER',
    label_storage: 'STOCKAGE',
    loading: 'Chargement...',

    label_target_url: 'URL CIBLE',
    label_expiry: 'EXPIRATION',
    label_click_limit: 'LIMITE DE CLICS',
    ttl_never: 'Jamais',
    limit_10: '10 Fois',
    limit_100: '100 Fois',
    btn_shorten: 'RACCOURCIR LE LIEN',
    label_short_link: 'LIEN RACCOURCI',
    btn_new_link: 'NOUVEAU LIEN',

    cfg_accent: 'Accent',
    cfg_bg: 'Arrière-plan',
    cfg_branding: 'Marque',
    cfg_name: 'Nom',
    cfg_tagline_label: 'Slogan',
    cfg_tagline_placeholder: 'Sous-titre optionnel...',
    cfg_logo_label: 'Logo',
    cfg_logo_specs: 'PNG / SVG / WebP, max 256 Ko',
    cfg_upload: 'TÉLÉVERSER',
    cfg_delete: 'SUPPRIMER',

    qr_title: 'CODE QR',
    qr_close: 'FERMER',

    js_copied: 'Copié !',
    js_manual: 'Copier manuellement : ',
    js_nopass: 'Mot de passe requis',
    js_timer: 'SUPPRESSION AUTO DANS : ',
    js_error: 'ERREUR',
    js_info: 'INFO',
    js_enter_data: 'Entrez vos données.',
    js_server_error: 'Erreur serveur',
    js_select_file: 'Sélectionnez un fichier',
    js_initializing: 'Initialisation...',
    js_uploading: 'Envoi : ',
    js_done: 'Terminé !',
    js_click_select: 'CLIQUEZ POUR SÉLECTIONNER UN FICHIER',
    js_error_prefix: 'Erreur : ',
    js_used: 'Utilisé : ',
    js_downloads: 'Téléchargements : ',
    js_confirm_delete: 'Supprimer le fichier définitivement ?',
    js_enter_url: 'Entrez l\'URL',
    js_error_occurred: 'Une erreur est survenue',
    js_shorten_fail: 'Impossible de raccourcir le lien',
    js_logo_max: 'Logo max 256 Ko',
    js_logo_active: 'Logo actif',
    js_no_logo: 'Pas de logo',
    js_logo_fail: 'Échec du téléversement du logo',
    js_saved: 'ENREGISTRÉ \u2713',
    js_save: 'ENREGISTRER',
    js_btn_delete: 'SUPPRIMER',

    lang_picker_title: 'Langue',

    cfg_turnstile: 'TURNSTILE',
    cfg_turnstile_site_key: 'Site Key',
    cfg_turnstile_creds: 'Protéger la récupération',
    cfg_turnstile_files: 'Protéger les téléchargements',
    ts_verify: 'VÉRIFICATION DE SÉCURITÉ',

    cfg_limits_title: 'LIMITES DE STOCKAGE',
    cfg_max_storage: 'STOCKAGE TOTAL (GO)',
    cfg_max_upload: 'MAX PAR FICHIER (GO)',
    cfg_limits_hint: 'Le niveau gratuit de Cloudflare R2 est de 10 Go. Dépasser requiert une confirmation et peut engendrer des frais.',
    cfg_limits_invalid: 'Les valeurs de limite doivent être des nombres positifs.',
    cfg_limits_upload_gt_storage: 'La limite par fichier ne peut pas dépasser le stockage total.',
    cfg_free_warning_title: 'DÉPASSEMENT DU NIVEAU GRATUIT',
    cfg_free_warning_body: 'Les valeurs saisies dépassent le niveau gratuit Cloudflare R2 (10 Go) et peuvent engendrer des frais de stockage. Tapez OKAY (en majuscules) pour confirmer :',
    cfg_okay_mismatch: 'Vous devez taper OKAY exactement (en majuscules).',
    cfg_btn_confirm: 'CONFIRMER',
    cfg_btn_cancel: 'ANNULER',
    js_file_too_large: 'Le fichier dépasse la limite d\'upload configurée.',

    cfg_turnstile_files_e2ee: 'Protéger les téléchargements E2EE',
    file_toggle_e2ee: 'CHIFFREMENT DE BOUT EN BOUT',
    file_e2ee_hint: 'AES-GCM + Argon2id côté client. Le serveur ne voit ni le contenu ni la passphrase. Max 150 Mo. Passphrase perdue = fichier définitivement irrécupérable.',
    file_e2ee_label_key: 'PASSPHRASE DE CHIFFREMENT',
    file_e2ee_protected: 'FICHIER CHIFFRÉ',
    file_e2ee_btn_decrypt: 'DÉCHIFFRER ET TÉLÉCHARGER',
    file_list_encrypted: 'Chiffré de bout en bout — passphrase requise',
    js_e2ee_max_size: 'Le fichier dépasse la limite E2EE de 150 Mo.',
    js_e2ee_require_pwd: 'E2EE requiert une passphrase.',
    js_e2ee_encrypting: 'Chiffrement...',
    js_e2ee_preparing: 'Préparation...',
    js_e2ee_downloading: 'Téléchargement',
    js_e2ee_decrypting: 'Déchiffrement...',
    js_e2ee_decrypt_failed: 'Échec du déchiffrement — mauvaise passphrase ?',
    file_drop_here: 'Déposer le fichier ici',
  },

  // ────────────────────────── Español ──────────────────────────
  es: {
    title_cred: 'Recuperación segura de datos',
    title_file: 'Descarga segura de archivo',
    label_key: 'INGRESE LA CLAVE DE DESCIFRADO',
    placeholder_key: 'Clave de acceso...',
    btn_decrypt: 'DESCIFRAR',
    ready_msg: 'DATOS LISTOS PARA LEER',
    btn_open: 'ABRIR MENSAJE',
    label_decrypted: 'DATOS DESCIFRADOS:',
    btn_copy: 'COPIAR CONTENIDO',
    file_protected: 'ARCHIVO PROTEGIDO CON CONTRASEÑA',
    btn_unlock: 'DESBLOQUEAR Y DESCARGAR',

    tab_creds: 'CREDENCIALES',
    tab_files: 'ARCHIVOS',
    tab_links: 'ENLACES',

    label_secret: 'CONTENIDO SECRETO',
    action_gen_password: 'GENERAR CONTRASEÑA',
    placeholder_secret: 'Pegue datos confidenciales aquí...',
    label_encrypt_key: 'CLAVE DE CIFRADO',
    action_gen_key: 'GENERAR CLAVE',
    placeholder_encrypt: 'Contraseña para desbloquear...',
    label_ttl: 'TIEMPO DE EXPIRACIÓN',
    ttl_1h: '1 Hora',
    ttl_24h: '24 Horas',
    ttl_72h: '72 Horas',
    btn_generate_links: 'GENERAR ENLACES',
    option1_manual: 'OPCIÓN 1: MANUAL (SIN CONTRASEÑA)',
    option2_fast: 'OPCIÓN 2: RÁPIDO (ENLACE CON CONTRASEÑA)',
    copy: 'COPIAR',
    btn_new_operation: 'NUEVA OPERACIÓN',

    label_pwd_optional: 'CONTRASEÑA (OPCIONAL)',
    placeholder_leave_empty: 'Dejar vacío para enlace público',
    label_retention: 'RETENCIÓN',
    label_download_limit: 'LÍMITE DE DESCARGAS',
    ttl_12h: '12 Horas',
    ttl_2d: '2 Días',
    ttl_7d: '7 Días',
    limit_1: '1 Vez',
    limit_5: '5 Veces',
    limit_unlimited: 'Sin límite',
    btn_send_file: 'SUBIR ARCHIVO',
    label_storage: 'ALMACENAMIENTO',
    loading: 'Cargando...',

    label_target_url: 'URL DESTINO',
    label_expiry: 'EXPIRACIÓN',
    label_click_limit: 'LÍMITE DE CLICS',
    ttl_never: 'Nunca',
    limit_10: '10 Veces',
    limit_100: '100 Veces',
    btn_shorten: 'ACORTAR ENLACE',
    label_short_link: 'ENLACE ACORTADO',
    btn_new_link: 'NUEVO ENLACE',

    cfg_accent: 'Acento',
    cfg_bg: 'Fondo',
    cfg_branding: 'Marca',
    cfg_name: 'Nombre',
    cfg_tagline_label: 'Eslogan',
    cfg_tagline_placeholder: 'Subtítulo opcional...',
    cfg_logo_label: 'Logo',
    cfg_logo_specs: 'PNG / SVG / WebP, máx 256 KB',
    cfg_upload: 'SUBIR',
    cfg_delete: 'ELIMINAR',

    qr_title: 'CÓDIGO QR',
    qr_close: 'CERRAR',

    js_copied: '¡Copiado!',
    js_manual: 'Copiar manualmente: ',
    js_nopass: 'Contraseña requerida',
    js_timer: 'AUTO-ELIMINACIÓN EN: ',
    js_error: 'ERROR',
    js_info: 'INFO',
    js_enter_data: 'Ingrese sus datos.',
    js_server_error: 'Error del servidor',
    js_select_file: 'Seleccione un archivo',
    js_initializing: 'Inicializando...',
    js_uploading: 'Subiendo: ',
    js_done: '¡Listo!',
    js_click_select: 'CLIC PARA SELECCIONAR ARCHIVO',
    js_error_prefix: 'Error: ',
    js_used: 'Usado: ',
    js_downloads: 'Descargas: ',
    js_confirm_delete: '¿Eliminar archivo permanentemente?',
    js_enter_url: 'Ingrese URL',
    js_error_occurred: 'Ocurrió un error',
    js_shorten_fail: 'No se pudo acortar el enlace',
    js_logo_max: 'Logo máx 256 KB',
    js_logo_active: 'Logo activo',
    js_no_logo: 'Sin logo',
    js_logo_fail: 'Error al subir el logo',
    js_saved: 'GUARDADO \u2713',
    js_save: 'GUARDAR',
    js_btn_delete: 'ELIMINAR',

    lang_picker_title: 'Idioma',

    cfg_turnstile: 'TURNSTILE',
    cfg_turnstile_site_key: 'Site Key',
    cfg_turnstile_creds: 'Proteger recuperación',
    cfg_turnstile_files: 'Proteger descargas',
    ts_verify: 'VERIFICACIÓN DE SEGURIDAD',

    cfg_limits_title: 'LÍMITES DE ALMACENAMIENTO',
    cfg_max_storage: 'ALMACENAMIENTO TOTAL (GB)',
    cfg_max_upload: 'MÁX POR ARCHIVO (GB)',
    cfg_limits_hint: 'El nivel gratuito de Cloudflare R2 es 10 GB. Excederlo requiere confirmación y puede generar costes.',
    cfg_limits_invalid: 'Los valores de límite deben ser números positivos.',
    cfg_limits_upload_gt_storage: 'El límite por archivo no puede exceder el almacenamiento total.',
    cfg_free_warning_title: 'EXCEDIENDO EL NIVEL GRATUITO',
    cfg_free_warning_body: 'Los valores introducidos exceden el nivel gratuito de Cloudflare R2 (10 GB) y pueden generar costes de almacenamiento. Escriba OKAY (mayúsculas) para confirmar:',
    cfg_okay_mismatch: 'Debe escribir OKAY exactamente (mayúsculas).',
    cfg_btn_confirm: 'CONFIRMAR',
    cfg_btn_cancel: 'CANCELAR',
    js_file_too_large: 'El archivo excede el límite de subida configurado.',

    cfg_turnstile_files_e2ee: 'Proteger descargas E2EE',
    file_toggle_e2ee: 'CIFRADO DE EXTREMO A EXTREMO',
    file_e2ee_hint: 'AES-GCM + Argon2id en cliente. El servidor no ve el contenido ni la frase de contraseña. Máx 150 MB. Perder la frase de contraseña hace el archivo irrecuperable.',
    file_e2ee_label_key: 'FRASE DE CIFRADO',
    file_e2ee_protected: 'ARCHIVO CIFRADO',
    file_e2ee_btn_decrypt: 'DESCIFRAR Y DESCARGAR',
    file_list_encrypted: 'Cifrado extremo a extremo — se requiere frase',
    js_e2ee_max_size: 'El archivo excede el límite E2EE de 150 MB.',
    js_e2ee_require_pwd: 'E2EE requiere una frase de contraseña.',
    js_e2ee_encrypting: 'Cifrando...',
    js_e2ee_preparing: 'Preparando...',
    js_e2ee_downloading: 'Descargando',
    js_e2ee_decrypting: 'Descifrando...',
    js_e2ee_decrypt_failed: 'Descifrado fallido — ¿frase incorrecta?',
    file_drop_here: 'Soltar archivo aquí',
  },

  // ────────────────────────── Українська ──────────────────────────
  uk: {
    title_cred: 'Безпечне отримання даних',
    title_file: 'Безпечне завантаження файлу',
    label_key: 'ВВЕДІТЬ КЛЮЧ ДЕШИФРУВАННЯ',
    placeholder_key: 'Ключ доступу...',
    btn_decrypt: 'ДЕШИФРУВАТИ',
    ready_msg: 'ДАНІ ГОТОВІ ДО ЧИТАННЯ',
    btn_open: 'ВІДКРИТИ ПОВІДОМЛЕННЯ',
    label_decrypted: 'ДЕШИФРОВАНІ ДАНІ:',
    btn_copy: 'КОПІЮВАТИ ВМІСТ',
    file_protected: 'ФАЙЛ ЗАХИЩЕНИЙ ПАРОЛЕМ',
    btn_unlock: 'РОЗБЛОКУВАТИ І ЗАВАНТАЖИТИ',

    tab_creds: 'ОБЛІКОВІ ДАНІ',
    tab_files: 'ФАЙЛИ',
    tab_links: 'ПОСИЛАННЯ',

    label_secret: 'СЕКРЕТНИЙ ВМІСТ',
    action_gen_password: 'ЗГЕНЕРУВАТИ ПАРОЛЬ',
    placeholder_secret: 'Вставте конфіденційні дані тут...',
    label_encrypt_key: 'КЛЮЧ ШИФРУВАННЯ',
    action_gen_key: 'ЗГЕНЕРУВАТИ КЛЮЧ',
    placeholder_encrypt: 'Пароль для розблокування...',
    label_ttl: 'ЧАС ЗАКІНЧЕННЯ',
    ttl_1h: '1 Година',
    ttl_24h: '24 Години',
    ttl_72h: '72 Години',
    btn_generate_links: 'ЗГЕНЕРУВАТИ ПОСИЛАННЯ',
    option1_manual: 'ВАРІАНТ 1: РУЧНИЙ (БЕЗ ПАРОЛЯ)',
    option2_fast: 'ВАРІАНТ 2: ШВИДКИЙ (ПОСИЛАННЯ З ПАРОЛЕМ)',
    copy: 'КОПІЮВАТИ',
    btn_new_operation: 'НОВА ОПЕРАЦІЯ',

    label_pwd_optional: 'ПАРОЛЬ (НЕОБОВ\'ЯЗКОВО)',
    placeholder_leave_empty: 'Залиште порожнім для публічного посилання',
    label_retention: 'ЗБЕРІГАННЯ',
    label_download_limit: 'ЛІМІТ ЗАВАНТАЖЕНЬ',
    ttl_12h: '12 Годин',
    ttl_2d: '2 Дні',
    ttl_7d: '7 Днів',
    limit_1: '1 Раз',
    limit_5: '5 Разів',
    limit_unlimited: 'Без ліміту',
    btn_send_file: 'ЗАВАНТАЖИТИ ФАЙЛ',
    label_storage: 'СХОВИЩЕ',
    loading: 'Завантаження...',

    label_target_url: 'ЦІЛЬОВА URL',
    label_expiry: 'ЗАКІНЧЕННЯ',
    label_click_limit: 'ЛІМІТ КЛІКІВ',
    ttl_never: 'Ніколи',
    limit_10: '10 Разів',
    limit_100: '100 Разів',
    btn_shorten: 'СКОРОТИТИ ПОСИЛАННЯ',
    label_short_link: 'СКОРОЧЕНЕ ПОСИЛАННЯ',
    btn_new_link: 'НОВЕ ПОСИЛАННЯ',

    cfg_accent: 'Акцент',
    cfg_bg: 'Фон',
    cfg_branding: 'Брендинг',
    cfg_name: 'Назва',
    cfg_tagline_label: 'Слоган',
    cfg_tagline_placeholder: 'Необов\'язковий підпис...',
    cfg_logo_label: 'Логотип',
    cfg_logo_specs: 'PNG / SVG / WebP, макс 256 КБ',
    cfg_upload: 'ЗАВАНТАЖИТИ',
    cfg_delete: 'ВИДАЛИТИ',

    qr_title: 'QR-КОД',
    qr_close: 'ЗАКРИТИ',

    js_copied: 'Скопійовано!',
    js_manual: 'Скопіюйте вручну: ',
    js_nopass: 'Потрібен пароль',
    js_timer: 'АВТО-ВИДАЛЕННЯ ЧЕРЕЗ: ',
    js_error: 'ПОМИЛКА',
    js_info: 'ІНФО',
    js_enter_data: 'Введіть дані.',
    js_server_error: 'Помилка сервера',
    js_select_file: 'Оберіть файл',
    js_initializing: 'Ініціалізація...',
    js_uploading: 'Завантаження: ',
    js_done: 'Готово!',
    js_click_select: 'НАТИСНІТЬ ЩОБ ОБРАТИ ФАЙЛ',
    js_error_prefix: 'Помилка: ',
    js_used: 'Використано: ',
    js_downloads: 'Завантажень: ',
    js_confirm_delete: 'Видалити файл назавжди?',
    js_enter_url: 'Введіть URL',
    js_error_occurred: 'Виникла помилка',
    js_shorten_fail: 'Не вдалося скоротити посилання',
    js_logo_max: 'Логотип макс 256 КБ',
    js_logo_active: 'Логотип активний',
    js_no_logo: 'Немає логотипу',
    js_logo_fail: 'Не вдалося завантажити логотип',
    js_saved: 'ЗБЕРЕЖЕНО \u2713',
    js_save: 'ЗБЕРЕГТИ',
    js_btn_delete: 'ВИДАЛИТИ',

    lang_picker_title: 'Мова',

    cfg_turnstile: 'TURNSTILE',
    cfg_turnstile_site_key: 'Site Key',
    cfg_turnstile_creds: 'Захист отримання секретів',
    cfg_turnstile_files: 'Захист завантажень файлів',
    ts_verify: 'ПЕРЕВІРКА БЕЗПЕКИ',

    cfg_limits_title: 'ЛІМІТИ СХОВИЩА',
    cfg_max_storage: 'ЗАГАЛЬНЕ СХОВИЩЕ (ГБ)',
    cfg_max_upload: 'МАКС. НА ФАЙЛ (ГБ)',
    cfg_limits_hint: 'Безкоштовний тариф Cloudflare R2 - це 10 ГБ. Перевищення потребує підтвердження і може спричинити витрати.',
    cfg_limits_invalid: 'Значення лімітів мають бути додатними числами.',
    cfg_limits_upload_gt_storage: 'Ліміт на файл не може перевищувати загальне сховище.',
    cfg_free_warning_title: 'ПЕРЕВИЩЕННЯ БЕЗКОШТОВНОГО ТАРИФУ',
    cfg_free_warning_body: 'Введені значення перевищують безкоштовний тариф Cloudflare R2 (10 ГБ) і можуть спричинити витрати на зберігання. Введіть OKAY (великими літерами), щоб підтвердити:',
    cfg_okay_mismatch: 'Потрібно ввести OKAY точно (великими літерами).',
    cfg_btn_confirm: 'ПІДТВЕРДИТИ',
    cfg_btn_cancel: 'СКАСУВАТИ',
    js_file_too_large: 'Файл перевищує налаштований ліміт завантаження.',

    cfg_turnstile_files_e2ee: 'Захист завантажень E2EE',
    file_toggle_e2ee: 'НАСКРІЗНЕ ШИФРУВАННЯ',
    file_e2ee_hint: 'AES-GCM + Argon2id на боці клієнта. Сервер не бачить ні вмісту, ні ключа. Макс. 150 МБ. Втрата ключа робить файл безповоротно недоступним.',
    file_e2ee_label_key: 'КЛЮЧ ШИФРУВАННЯ',
    file_e2ee_protected: 'ЗАШИФРОВАНИЙ ФАЙЛ',
    file_e2ee_btn_decrypt: 'РОЗШИФРУВАТИ І ЗАВАНТАЖИТИ',
    file_list_encrypted: 'Наскрізне шифрування — потрібен ключ',
    js_e2ee_max_size: 'Файл перевищує обмеження 150 МБ для E2EE.',
    js_e2ee_require_pwd: 'E2EE вимагає ключа.',
    js_e2ee_encrypting: 'Шифрування...',
    js_e2ee_preparing: 'Підготовка...',
    js_e2ee_downloading: 'Завантаження',
    js_e2ee_decrypting: 'Розшифрування...',
    js_e2ee_decrypt_failed: 'Розшифрування не вдалося — неправильний ключ?',
    file_drop_here: 'Відпустити файл тут',
  },

  // ────────────────────────── Português ──────────────────────────
  pt: {
    title_cred: 'Recuperação segura de dados',
    title_file: 'Download seguro de arquivo',
    label_key: 'INSIRA A CHAVE DE DESCRIPTOGRAFIA',
    placeholder_key: 'Chave de acesso...',
    btn_decrypt: 'DESCRIPTOGRAFAR',
    ready_msg: 'DADOS PRONTOS PARA LEITURA',
    btn_open: 'ABRIR MENSAGEM',
    label_decrypted: 'DADOS DESCRIPTOGRAFADOS:',
    btn_copy: 'COPIAR CONTEÚDO',
    file_protected: 'ARQUIVO PROTEGIDO POR SENHA',
    btn_unlock: 'DESBLOQUEAR E BAIXAR',

    tab_creds: 'CREDENCIAIS',
    tab_files: 'ARQUIVOS',
    tab_links: 'LINKS',

    label_secret: 'CONTEÚDO SECRETO',
    action_gen_password: 'GERAR SENHA',
    placeholder_secret: 'Cole dados confidenciais aqui...',
    label_encrypt_key: 'CHAVE DE CRIPTOGRAFIA',
    action_gen_key: 'GERAR CHAVE',
    placeholder_encrypt: 'Senha para desbloquear...',
    label_ttl: 'TEMPO DE EXPIRAÇÃO',
    ttl_1h: '1 Hora',
    ttl_24h: '24 Horas',
    ttl_72h: '72 Horas',
    btn_generate_links: 'GERAR LINKS',
    option1_manual: 'OPÇÃO 1: MANUAL (SEM SENHA)',
    option2_fast: 'OPÇÃO 2: RÁPIDO (LINK COM SENHA)',
    copy: 'COPIAR',
    btn_new_operation: 'NOVA OPERAÇÃO',

    label_pwd_optional: 'SENHA (OPCIONAL)',
    placeholder_leave_empty: 'Deixe vazio para link público',
    label_retention: 'RETENÇÃO',
    label_download_limit: 'LIMITE DE DOWNLOADS',
    ttl_12h: '12 Horas',
    ttl_2d: '2 Dias',
    ttl_7d: '7 Dias',
    limit_1: '1 Vez',
    limit_5: '5 Vezes',
    limit_unlimited: 'Sem limite',
    btn_send_file: 'ENVIAR ARQUIVO',
    label_storage: 'ARMAZENAMENTO',
    loading: 'Carregando...',

    label_target_url: 'URL DESTINO',
    label_expiry: 'EXPIRAÇÃO',
    label_click_limit: 'LIMITE DE CLIQUES',
    ttl_never: 'Nunca',
    limit_10: '10 Vezes',
    limit_100: '100 Vezes',
    btn_shorten: 'ENCURTAR LINK',
    label_short_link: 'LINK ENCURTADO',
    btn_new_link: 'NOVO LINK',

    cfg_accent: 'Destaque',
    cfg_bg: 'Fundo',
    cfg_branding: 'Marca',
    cfg_name: 'Nome',
    cfg_tagline_label: 'Slogan',
    cfg_tagline_placeholder: 'Subtítulo opcional...',
    cfg_logo_label: 'Logo',
    cfg_logo_specs: 'PNG / SVG / WebP, máx 256 KB',
    cfg_upload: 'ENVIAR',
    cfg_delete: 'EXCLUIR',

    qr_title: 'CÓDIGO QR',
    qr_close: 'FECHAR',

    js_copied: 'Copiado!',
    js_manual: 'Copiar manualmente: ',
    js_nopass: 'Senha necessária',
    js_timer: 'AUTO-EXCLUSÃO EM: ',
    js_error: 'ERRO',
    js_info: 'INFO',
    js_enter_data: 'Insira seus dados.',
    js_server_error: 'Erro do servidor',
    js_select_file: 'Selecione um arquivo',
    js_initializing: 'Inicializando...',
    js_uploading: 'Enviando: ',
    js_done: 'Concluído!',
    js_click_select: 'CLIQUE PARA SELECIONAR ARQUIVO',
    js_error_prefix: 'Erro: ',
    js_used: 'Usado: ',
    js_downloads: 'Downloads: ',
    js_confirm_delete: 'Excluir arquivo permanentemente?',
    js_enter_url: 'Insira a URL',
    js_error_occurred: 'Ocorreu um erro',
    js_shorten_fail: 'Falha ao encurtar o link',
    js_logo_max: 'Logo máx 256 KB',
    js_logo_active: 'Logo ativo',
    js_no_logo: 'Sem logo',
    js_logo_fail: 'Falha ao enviar o logo',
    js_saved: 'SALVO \u2713',
    js_save: 'SALVAR',
    js_btn_delete: 'EXCLUIR',

    lang_picker_title: 'Idioma',

    cfg_turnstile: 'TURNSTILE',
    cfg_turnstile_site_key: 'Site Key',
    cfg_turnstile_creds: 'Proteger recuperação',
    cfg_turnstile_files: 'Proteger downloads',
    ts_verify: 'VERIFICAÇÃO DE SEGURANÇA',

    cfg_limits_title: 'LIMITES DE ARMAZENAMENTO',
    cfg_max_storage: 'ARMAZENAMENTO TOTAL (GB)',
    cfg_max_upload: 'MÁX POR ARQUIVO (GB)',
    cfg_limits_hint: 'O nível gratuito do Cloudflare R2 é 10 GB. Excedê-lo requer confirmação e pode gerar custos.',
    cfg_limits_invalid: 'Os valores de limite devem ser números positivos.',
    cfg_limits_upload_gt_storage: 'O limite por arquivo não pode exceder o armazenamento total.',
    cfg_free_warning_title: 'EXCEDENDO O NÍVEL GRATUITO',
    cfg_free_warning_body: 'Os valores inseridos excedem o nível gratuito do Cloudflare R2 (10 GB) e podem gerar custos de armazenamento. Digite OKAY (maiúsculas) para confirmar:',
    cfg_okay_mismatch: 'Você deve digitar OKAY exatamente (maiúsculas).',
    cfg_btn_confirm: 'CONFIRMAR',
    cfg_btn_cancel: 'CANCELAR',
    js_file_too_large: 'O arquivo excede o limite de upload configurado.',

    cfg_turnstile_files_e2ee: 'Proteger downloads E2EE',
    file_toggle_e2ee: 'CRIPTOGRAFIA DE PONTA A PONTA',
    file_e2ee_hint: 'AES-GCM + Argon2id no cliente. O servidor não vê o conteúdo nem a passphrase. Máx 150 MB. Perder a passphrase torna o arquivo permanentemente irrecuperável.',
    file_e2ee_label_key: 'PASSPHRASE DE CRIPTOGRAFIA',
    file_e2ee_protected: 'ARQUIVO CRIPTOGRAFADO',
    file_e2ee_btn_decrypt: 'DESCRIPTOGRAFAR E BAIXAR',
    file_list_encrypted: 'Criptografado ponta a ponta — passphrase necessária',
    js_e2ee_max_size: 'Arquivo excede o limite de 150 MB para E2EE.',
    js_e2ee_require_pwd: 'E2EE requer uma passphrase.',
    js_e2ee_encrypting: 'Criptografando...',
    js_e2ee_preparing: 'Preparando...',
    js_e2ee_downloading: 'Baixando',
    js_e2ee_decrypting: 'Descriptografando...',
    js_e2ee_decrypt_failed: 'Falha na descriptografia — passphrase errada?',
    file_drop_here: 'Soltar arquivo aqui',
  },

  // ────────────────────────── 中文 (简体) ──────────────────────────
  zh: {
    title_cred: '\u5B89\u5168\u6570\u636E\u68C0\u7D22',
    title_file: '\u5B89\u5168\u6587\u4EF6\u4E0B\u8F7D',
    label_key: '\u8F93\u5165\u89E3\u5BC6\u5BC6\u94A5',
    placeholder_key: '\u8BBF\u95EE\u5BC6\u94A5...',
    btn_decrypt: '\u89E3\u5BC6',
    ready_msg: '\u6570\u636E\u5DF2\u51C6\u5907\u5C31\u7EEA',
    btn_open: '\u6253\u5F00\u6D88\u606F',
    label_decrypted: '\u5DF2\u89E3\u5BC6\u6570\u636E\uFF1A',
    btn_copy: '\u590D\u5236\u5185\u5BB9',
    file_protected: '\u5BC6\u7801\u4FDD\u62A4\u6587\u4EF6',
    btn_unlock: '\u89E3\u9501\u5E76\u4E0B\u8F7D',

    tab_creds: '\u51ED\u636E',
    tab_files: '\u6587\u4EF6',
    tab_links: '\u94FE\u63A5',

    label_secret: '\u79D8\u5BC6\u5185\u5BB9',
    action_gen_password: '\u751F\u6210\u5BC6\u7801',
    placeholder_secret: '\u5728\u6B64\u7C98\u8D34\u673A\u5BC6\u6570\u636E...',
    label_encrypt_key: '\u52A0\u5BC6\u5BC6\u94A5',
    action_gen_key: '\u751F\u6210\u5BC6\u94A5',
    placeholder_encrypt: '\u89E3\u9501\u5BC6\u7801...',
    label_ttl: '\u8FC7\u671F\u65F6\u95F4',
    ttl_1h: '1 \u5C0F\u65F6',
    ttl_24h: '24 \u5C0F\u65F6',
    ttl_72h: '72 \u5C0F\u65F6',
    btn_generate_links: '\u751F\u6210\u94FE\u63A5',
    option1_manual: '\u9009\u98791\uFF1A\u624B\u52A8\uFF08\u65E0\u5BC6\u7801\uFF09',
    option2_fast: '\u9009\u98792\uFF1A\u5FEB\u901F\uFF08\u5E26\u5BC6\u7801\u94FE\u63A5\uFF09',
    copy: '\u590D\u5236',
    btn_new_operation: '\u65B0\u64CD\u4F5C',

    label_pwd_optional: '\u5BC6\u7801\uFF08\u53EF\u9009\uFF09',
    placeholder_leave_empty: '\u7559\u7A7A\u4EE5\u521B\u5EFA\u516C\u5F00\u94FE\u63A5',
    label_retention: '\u4FDD\u7559\u65F6\u95F4',
    label_download_limit: '\u4E0B\u8F7D\u9650\u5236',
    ttl_12h: '12 \u5C0F\u65F6',
    ttl_2d: '2 \u5929',
    ttl_7d: '7 \u5929',
    limit_1: '1 \u6B21',
    limit_5: '5 \u6B21',
    limit_unlimited: '\u65E0\u9650\u5236',
    btn_send_file: '\u4E0A\u4F20\u6587\u4EF6',
    label_storage: '\u5B58\u50A8',
    loading: '\u52A0\u8F7D\u4E2D...',

    label_target_url: '\u76EE\u6807 URL',
    label_expiry: '\u8FC7\u671F',
    label_click_limit: '\u70B9\u51FB\u9650\u5236',
    ttl_never: '\u6C38\u4E0D',
    limit_10: '10 \u6B21',
    limit_100: '100 \u6B21',
    btn_shorten: '\u7F29\u77ED\u94FE\u63A5',
    label_short_link: '\u7F29\u77ED\u94FE\u63A5',
    btn_new_link: '\u65B0\u94FE\u63A5',

    cfg_accent: '\u5F3A\u8C03\u8272',
    cfg_bg: '\u80CC\u666F',
    cfg_branding: '\u54C1\u724C',
    cfg_name: '\u540D\u79F0',
    cfg_tagline_label: '\u6807\u8BED',
    cfg_tagline_placeholder: '\u53EF\u9009\u526F\u6807\u9898...',
    cfg_logo_label: '\u6807\u5FD7',
    cfg_logo_specs: 'PNG / SVG / WebP, \u6700\u5927 256 KB',
    cfg_upload: '\u4E0A\u4F20',
    cfg_delete: '\u5220\u9664',

    qr_title: '\u4E8C\u7EF4\u7801',
    qr_close: '\u5173\u95ED',

    js_copied: '\u5DF2\u590D\u5236\uFF01',
    js_manual: '\u624B\u52A8\u590D\u5236\uFF1A',
    js_nopass: '\u9700\u8981\u5BC6\u7801',
    js_timer: '\u81EA\u52A8\u5220\u9664\u5012\u8BA1\u65F6\uFF1A',
    js_error: '\u9519\u8BEF',
    js_info: '\u4FE1\u606F',
    js_enter_data: '\u8BF7\u8F93\u5165\u6570\u636E\u3002',
    js_server_error: '\u670D\u52A1\u5668\u9519\u8BEF',
    js_select_file: '\u8BF7\u9009\u62E9\u6587\u4EF6',
    js_initializing: '\u521D\u59CB\u5316\u4E2D...',
    js_uploading: '\u4E0A\u4F20\u4E2D\uFF1A',
    js_done: '\u5B8C\u6210\uFF01',
    js_click_select: '\u70B9\u51FB\u9009\u62E9\u6587\u4EF6',
    js_error_prefix: '\u9519\u8BEF\uFF1A',
    js_used: '\u5DF2\u7528\uFF1A',
    js_downloads: '\u4E0B\u8F7D\u6B21\u6570\uFF1A',
    js_confirm_delete: '\u6C38\u4E45\u5220\u9664\u6587\u4EF6\uFF1F',
    js_enter_url: '\u8BF7\u8F93\u5165 URL',
    js_error_occurred: '\u53D1\u751F\u9519\u8BEF',
    js_shorten_fail: '\u65E0\u6CD5\u7F29\u77ED\u94FE\u63A5',
    js_logo_max: '\u6807\u5FD7\u6700\u5927 256 KB',
    js_logo_active: '\u6807\u5FD7\u5DF2\u542F\u7528',
    js_no_logo: '\u65E0\u6807\u5FD7',
    js_logo_fail: '\u6807\u5FD7\u4E0A\u4F20\u5931\u8D25',
    js_saved: '\u5DF2\u4FDD\u5B58 \u2713',
    js_save: '\u4FDD\u5B58',
    js_btn_delete: '\u5220\u9664',

    lang_picker_title: '\u8BED\u8A00',

    cfg_turnstile: 'TURNSTILE',
    cfg_turnstile_site_key: '\u7AD9\u70B9\u5BC6\u94A5',
    cfg_turnstile_creds: '\u4FDD\u62A4\u5BC6\u94A5\u83B7\u53D6',
    cfg_turnstile_files: '\u4FDD\u62A4\u6587\u4EF6\u4E0B\u8F7D',
    ts_verify: '\u5B89\u5168\u9A8C\u8BC1',

    cfg_limits_title: '存储限制',
    cfg_max_storage: '总存储 (GB)',
    cfg_max_upload: '单文件最大 (GB)',
    cfg_limits_hint: 'Cloudflare R2 免费套餐为 10 GB。超出需要确认，并可能产生费用。',
    cfg_limits_invalid: '限制值必须为正数。',
    cfg_limits_upload_gt_storage: '单文件限制不能超过总存储。',
    cfg_free_warning_title: '超出免费套餐',
    cfg_free_warning_body: '输入的值超过 Cloudflare R2 免费套餐（10 GB），可能产生存储费用。输入 OKAY（大写）以确认：',
    cfg_okay_mismatch: '必须精确输入 OKAY（大写）。',
    cfg_btn_confirm: '确认',
    cfg_btn_cancel: '取消',
    js_file_too_large: '文件超过已配置的上传限制。',

    cfg_turnstile_files_e2ee: '保护 E2EE 下载',
    file_toggle_e2ee: '端到端加密',
    file_e2ee_hint: '客户端 AES-GCM + Argon2id。服务器看不到内容或密码短语。最大 150 MB。丢失密码短语将使文件永久无法恢复。',
    file_e2ee_label_key: '加密密码短语',
    file_e2ee_protected: '加密文件',
    file_e2ee_btn_decrypt: '解密并下载',
    file_list_encrypted: '端到端加密 — 需要密码短语',
    js_e2ee_max_size: '文件超过 E2EE 150 MB 限制。',
    js_e2ee_require_pwd: 'E2EE 需要密码短语。',
    js_e2ee_encrypting: '加密中...',
    js_e2ee_preparing: '准备中...',
    js_e2ee_downloading: '下载中',
    js_e2ee_decrypting: '解密中...',
    js_e2ee_decrypt_failed: '解密失败 — 密码短语错误？',
    file_drop_here: '放下文件以上传',
  },

  // ────────────────────────── Čeština ──────────────────────────
  cs: {
    title_cred: 'Bezpečné načtení dat',
    title_file: 'Bezpečné stažení souboru',
    label_key: 'ZADEJTE DEŠIFROVACÍ KLÍČ',
    placeholder_key: 'Přístupový klíč...',
    btn_decrypt: 'DEŠIFROVAT',
    ready_msg: 'DATA PŘIPRAVENA K PŘEČTENÍ',
    btn_open: 'OTEVŘÍT ZPRÁVU',
    label_decrypted: 'DEŠIFROVANÁ DATA:',
    btn_copy: 'KOPÍROVAT OBSAH',
    file_protected: 'SOUBOR CHRÁNĚNÝ HESLEM',
    btn_unlock: 'ODEMKNOUT A STÁHNOUT',

    tab_creds: 'PŘIHLAŠOVACÍ ÚDAJE',
    tab_files: 'SOUBORY',
    tab_links: 'ODKAZY',

    label_secret: 'TAJNÝ OBSAH',
    action_gen_password: 'GENEROVAT HESLO',
    placeholder_secret: 'Vložte důvěrná data zde...',
    label_encrypt_key: 'ŠIFROVACÍ KLÍČ',
    action_gen_key: 'GENEROVAT KLÍČ',
    placeholder_encrypt: 'Heslo pro odemčení...',
    label_ttl: 'DOBA PLATNOSTI',
    ttl_1h: '1 Hodina',
    ttl_24h: '24 Hodin',
    ttl_72h: '72 Hodin',
    btn_generate_links: 'GENEROVAT ODKAZY',
    option1_manual: 'MOŽNOST 1: MANUÁLNÍ (BEZ HESLA)',
    option2_fast: 'MOŽNOST 2: RYCHLÉ (ODKAZ S HESLEM)',
    copy: 'KOPÍROVAT',
    btn_new_operation: 'NOVÁ OPERACE',

    label_pwd_optional: 'HESLO (VOLITELNÉ)',
    placeholder_leave_empty: 'Nechte prázdné pro veřejný odkaz',
    label_retention: 'RETENCE',
    label_download_limit: 'LIMIT STAŽENÍ',
    ttl_12h: '12 Hodin',
    ttl_2d: '2 Dny',
    ttl_7d: '7 Dní',
    limit_1: '1 Krát',
    limit_5: '5 Krát',
    limit_unlimited: 'Bez limitu',
    btn_send_file: 'NAHRÁT SOUBOR',
    label_storage: 'ÚLOŽIŠTĚ',
    loading: 'Načítání...',

    label_target_url: 'CÍLOVÁ URL',
    label_expiry: 'VYPRŠENÍ',
    label_click_limit: 'LIMIT KLIKNUTÍ',
    ttl_never: 'Nikdy',
    limit_10: '10 Krát',
    limit_100: '100 Krát',
    btn_shorten: 'ZKRÁTIT ODKAZ',
    label_short_link: 'ZKRÁCENÝ ODKAZ',
    btn_new_link: 'NOVÝ ODKAZ',

    cfg_accent: 'Akcent',
    cfg_bg: 'Pozadí',
    cfg_branding: 'Branding',
    cfg_name: 'Název',
    cfg_tagline_label: 'Tagline',
    cfg_tagline_placeholder: 'Volitelný podtitulek...',
    cfg_logo_label: 'Logo',
    cfg_logo_specs: 'PNG / SVG / WebP, max 256 KB',
    cfg_upload: 'NAHRÁT',
    cfg_delete: 'SMAZAT',

    qr_title: 'QR KÓD',
    qr_close: 'ZAVŘÍT',

    js_copied: 'Zkopírováno!',
    js_manual: 'Zkopírujte ručně: ',
    js_nopass: 'Vyžadováno heslo',
    js_timer: 'AUTOMATICKÉ SMAZÁNÍ ZA: ',
    js_error: 'CHYBA',
    js_info: 'INFO',
    js_enter_data: 'Zadejte data.',
    js_server_error: 'Chyba serveru',
    js_select_file: 'Vyberte soubor',
    js_initializing: 'Inicializace...',
    js_uploading: 'Nahrávání: ',
    js_done: 'Hotovo!',
    js_click_select: 'KLIKNĚTE PRO VÝBĚR SOUBORU',
    js_error_prefix: 'Chyba: ',
    js_used: 'Použito: ',
    js_downloads: 'Stažení: ',
    js_confirm_delete: 'Trvale smazat soubor?',
    js_enter_url: 'Zadejte URL',
    js_error_occurred: 'Došlo k chybě',
    js_shorten_fail: 'Nepodařilo se zkrátit odkaz',
    js_logo_max: 'Logo max 256 KB',
    js_logo_active: 'Logo aktivní',
    js_no_logo: 'Žádné logo',
    js_logo_fail: 'Nepodařilo se nahrát logo',
    js_saved: 'ULOŽENO \u2713',
    js_save: 'ULOŽIT',
    js_btn_delete: 'SMAZAT',

    lang_picker_title: 'Jazyk',

    cfg_turnstile: 'TURNSTILE',
    cfg_turnstile_site_key: 'Site Key',
    cfg_turnstile_creds: 'Chránit načítání tajemství',
    cfg_turnstile_files: 'Chránit stahování souborů',
    ts_verify: 'BEZPEČNOSTNÍ KONTROLA',

    cfg_limits_title: 'LIMITY ÚLOŽIŠTĚ',
    cfg_max_storage: 'CELKOVÉ ÚLOŽIŠTĚ (GB)',
    cfg_max_upload: 'MAX. NA SOUBOR (GB)',
    cfg_limits_hint: 'Bezplatný plán Cloudflare R2 je 10 GB. Překročení vyžaduje potvrzení a může vést k nákladům.',
    cfg_limits_invalid: 'Hodnoty limitů musí být kladná čísla.',
    cfg_limits_upload_gt_storage: 'Limit na soubor nemůže překročit celkové úložiště.',
    cfg_free_warning_title: 'PŘEKROČENÍ BEZPLATNÉHO PLÁNU',
    cfg_free_warning_body: 'Zadané hodnoty překračují bezplatný plán Cloudflare R2 (10 GB) a mohou vést k nákladům na úložiště. Zadejte OKAY (velkými písmeny) pro potvrzení:',
    cfg_okay_mismatch: 'Musíte zadat OKAY přesně (velkými písmeny).',
    cfg_btn_confirm: 'POTVRDIT',
    cfg_btn_cancel: 'ZRUŠIT',
    js_file_too_large: 'Soubor překračuje nastavený limit uploadu.',

    cfg_turnstile_files_e2ee: 'Chránit stahování E2EE',
    file_toggle_e2ee: 'END-TO-END ŠIFROVÁNÍ',
    file_e2ee_hint: 'AES-GCM + Argon2id na straně klienta. Server nevidí obsah ani heslo. Max 150 MB. Ztráta hesla znamená trvalou ztrátu souboru.',
    file_e2ee_label_key: 'ŠIFROVACÍ HESLO',
    file_e2ee_protected: 'ŠIFROVANÝ SOUBOR',
    file_e2ee_btn_decrypt: 'DEŠIFROVAT A STÁHNOUT',
    file_list_encrypted: 'End-to-end šifrováno — vyžadováno heslo',
    js_e2ee_max_size: 'Soubor překračuje 150 MB limit pro E2EE.',
    js_e2ee_require_pwd: 'E2EE vyžaduje heslo.',
    js_e2ee_encrypting: 'Šifrování...',
    js_e2ee_preparing: 'Příprava...',
    js_e2ee_downloading: 'Stahování',
    js_e2ee_decrypting: 'Dešifrování...',
    js_e2ee_decrypt_failed: 'Dešifrování selhalo — špatné heslo?',
    file_drop_here: 'Pusťte soubor sem',
  },
}

// ── Language detection ──────────────────────────────────────────────────────

export function getLang(req: Request): { t: Translations; code: LangCode } {
  // 1. Cookie — explicit user choice (per-user, not global)
  const cookieHeader = req.headers.get('Cookie') ?? ''
  const match = cookieHeader.match(/(?:^|;\s*)lang=([a-z]{2})/)
  const cookieLang = match?.[1]
  if (cookieLang && cookieLang in I18N) {
    const code = cookieLang as LangCode
    return { t: I18N[code], code }
  }

  // 2. Accept-Language header — automatic browser detection
  const header = req.headers.get('Accept-Language') ?? ''
  const parts = header.split(',')
  for (const part of parts) {
    const code = part.split(';')[0].trim().toLowerCase().slice(0, 2)
    if (code in I18N) return { t: I18N[code as LangCode], code: code as LangCode }
  }

  // 3. Default — English
  return { t: I18N.en, code: 'en' }
}

// ── Language picker component ───────────────────────────────────────────────

const LANG_OPTIONS: ReadonlyArray<{ code: LangCode; flag: string; name: string }> = [
  { code: 'en', flag: '\uD83C\uDDEC\uD83C\uDDE7', name: 'English' },
  { code: 'pl', flag: '\uD83C\uDDF5\uD83C\uDDF1', name: 'Polski' },
  { code: 'de', flag: '\uD83C\uDDE9\uD83C\uDDEA', name: 'Deutsch' },
  { code: 'fr', flag: '\uD83C\uDDEB\uD83C\uDDF7', name: 'Fran\u00E7ais' },
  { code: 'es', flag: '\uD83C\uDDEA\uD83C\uDDF8', name: 'Espa\u00F1ol' },
  { code: 'uk', flag: '\uD83C\uDDFA\uD83C\uDDE6', name: '\u0423\u043A\u0440\u0430\u0457\u043D\u0441\u044C\u043A\u0430' },
  { code: 'pt', flag: '\uD83C\uDDF5\uD83C\uDDF9', name: 'Portugu\u00EAs' },
  { code: 'zh', flag: '\uD83C\uDDE8\uD83C\uDDF3', name: '\u4E2D\u6587' },
  { code: 'cs', flag: '\uD83C\uDDE8\uD83C\uDDFF', name: '\u010Ce\u0161tina' },
]

export function renderLangPicker(currentLang: LangCode): string {
  const current = LANG_OPTIONS.find(l => l.code === currentLang) ?? LANG_OPTIONS[0]
  const items = LANG_OPTIONS.map(l =>
    `<div class="lang-item${l.code === currentLang ? ' active' : ''}" data-click="setLang" data-arg="${l.code}">${l.flag} ${l.name}</div>`
  ).join('')

  return `<div class="lang-picker"><button class="lang-btn" data-click="langBtn" title="${current.name}">${current.flag}</button><div class="lang-menu" id="langMenu">${items}</div></div>`
}

export const LANG_PICKER_CSS = `
.lang-picker{position:fixed;top:18px;left:56px;z-index:10}
.lang-btn{width:32px;height:32px;display:flex;align-items:center;justify-content:center;cursor:pointer;border:1px solid var(--border);background:var(--surface);color:var(--text-muted);font-size:15px;transition:color 0.2s,border-color 0.2s;line-height:1}
.lang-btn:hover{color:var(--accent);border-color:var(--accent)}
.lang-menu{position:absolute;top:38px;left:0;background:var(--surface);border:1px solid var(--border-strong);display:none;min-width:152px;z-index:11;box-shadow:0 8px 32px rgba(0,0,0,0.4)}
.lang-menu.open{display:block}
.lang-item{padding:8px 14px;cursor:pointer;font-size:0.75rem;font-weight:500;color:var(--text-muted);transition:background 0.15s,color 0.15s;display:flex;align-items:center;gap:8px}
.lang-item:hover{background:var(--accent-dim);color:var(--text)}
.lang-item.active{color:var(--accent)}
`

export const LANG_PICKER_JS = `
function toggleLangMenu(){var m=get('langMenu');if(m)m.classList.toggle('open')}
function setLang(code){document.cookie='lang='+code+';path=/;max-age=31536000;SameSite=Lax';location.reload()}
document.addEventListener('click',function(e){if(!e.target.closest('.lang-picker')){var m=get('langMenu');if(m)m.classList.remove('open')}});
`
