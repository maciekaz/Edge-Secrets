// ── i18n Module ── Edge Secrets ─────────────────────────────────────────────

export type LangCode = 'en' | 'pl' | 'de' | 'fr' | 'es' | 'uk' | 'pt' | 'zh'

export const SUPPORTED_LANGS: readonly LangCode[] = ['en', 'pl', 'de', 'fr', 'es', 'uk', 'pt', 'zh'] as const

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
    tab_files: 'FILES (5GB)',
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
    tab_files: 'PLIKI (5GB)',
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
    tab_files: 'DATEIEN (5GB)',
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
    tab_files: 'FICHIERS (5GO)',
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
    tab_files: 'ARCHIVOS (5GB)',
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
    tab_files: 'ФАЙЛИ (5ГБ)',
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
    tab_files: 'ARQUIVOS (5GB)',
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
    tab_files: '\u6587\u4EF6 (5GB)',
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
]

export function renderLangPicker(currentLang: LangCode): string {
  const current = LANG_OPTIONS.find(l => l.code === currentLang) ?? LANG_OPTIONS[0]
  const items = LANG_OPTIONS.map(l =>
    `<div class="lang-item${l.code === currentLang ? ' active' : ''}" onclick="setLang('${l.code}')">${l.flag} ${l.name}</div>`
  ).join('')

  return `<div class="lang-picker"><button class="lang-btn" onclick="event.stopPropagation();toggleLangMenu()" title="${current.name}">${current.flag}</button><div class="lang-menu" id="langMenu">${items}</div></div>`
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
