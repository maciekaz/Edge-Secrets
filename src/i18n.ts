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

  // ── Device binding (opt-in, multi-read secrets) ──
  bind_label: string
  bind_mode_none: string
  bind_mode_device: string
  bind_mode_webauthn: string
  bind_hint_none: string
  bind_hint_device: string
  bind_hint_webauthn: string
  bind_fallback_label: string
  bind_fallback_hint: string
  bind_notice_device: string
  bind_notice_webauthn: string
  js_bind_locked: string
  js_bind_unsupported: string
  js_bind_read_limit: string
  js_bind_retry: string
  ttl_14d: string
  ttl_30d: string
  bind_confirm_title: string
  bind_confirm_yes: string
  bind_confirm_no: string
  ttl_6h: string
  js_hide_timer: string
  js_bind_until: string
  js_err_challenge: string
  js_err_bad_key: string
  js_err_attempts_left: string
  js_err_terminated: string
  js_err_not_found: string
  js_bind_synced: string
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
    bind_label: 'Access after first read',
    bind_mode_none: 'One-time read (default)',
    bind_mode_device: 'Lock to first browser',
    bind_mode_webauthn: 'Lock to security key',
    bind_hint_none: 'The secret is destroyed the moment it is read. Anyone with the link and key gets exactly one chance.',
    bind_hint_device: 'The secret survives its lifetime, but after the first read only that browser can open it again. Clearing cookies or site data means permanent loss.',
    bind_hint_webauthn: 'Strongest option. Requires a security key or a device-bound authenticator. Synced passkeys are rejected because they exist on every device the user owns.',
    bind_fallback_label: 'Allow cookie-only fallback',
    bind_fallback_hint: 'If the first reader\'s browser cannot create a key, fall back to a cookie alone. Weaker, but the recipient still gets in. Off means they are locked out instead.',
    bind_notice_device: 'Your key is correct and nothing has been bound yet. Opening this secret locks it to THIS BROWSER, permanently. No other device will be able to read it. And neither will a different browser on this same computer, nor a private window. Clearing cookies or site data also cuts you off for good.',
    bind_notice_webauthn: 'Your key is correct and nothing has been bound yet. Opening this secret locks it to a security key, permanently. Have yours ready, you will be asked to register it now. Afterwards no other device can read this secret, and neither can a different browser on this same computer. Synced passkeys will be rejected.',
    js_bind_locked: 'This secret is locked to another browser. It was already opened elsewhere. Which includes a different browser or a private window on this very device. It cannot be read here.',
    js_bind_unsupported: 'This browser cannot create the key this secret requires, and the sender did not allow a fallback.',
    js_bind_read_limit: 'This secret has reached its maximum number of reads.',
    js_bind_retry: 'The verification step expired. Each challenge works only once. Refresh the page and try again.',
    ttl_14d: '14 days',
    ttl_30d: '30 days',
    bind_confirm_title: 'Before you open this',
    bind_confirm_yes: 'I understand. Open',
    bind_confirm_no: 'Cancel',
    ttl_6h: '6 Hours',
    js_hide_timer: 'HIDING FROM SCREEN IN: ',
    js_bind_until: 'Access expires ',
    js_err_challenge: 'Cloudflare Turnstile verification failed or expired. Each challenge can only be used once. Refresh the page, complete the challenge again, then retry.',
    js_err_bad_key: 'Wrong key.',
    js_err_attempts_left: 'Attempts left: {n}. When they run out the secret is destroyed permanently.',
    js_err_terminated: 'Too many failed attempts. The secret has been permanently destroyed. Ask the sender for a new link.',
    js_err_not_found: 'This link has expired, was already used, or the key is wrong.',
    js_bind_synced: 'That is a synced passkey. It exists on every device linked to your account, so it cannot lock this secret to one device. Use a hardware security key, or a device-bound authenticator. Refresh the page before trying again with a different authenticator.',
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
    bind_label: 'Dostęp po pierwszym odczycie',
    bind_mode_none: 'Odczyt jednorazowy (domyślnie)',
    bind_mode_device: 'Powiązanie z przeglądarką',
    bind_mode_webauthn: 'Powiązanie z kluczem sprzętowym',
    bind_hint_none: 'Sekret znika w chwili odczytu. Każdy, kto ma link i klucz, dostaje dokładnie jedną szansę.',
    bind_hint_device: 'Sekret żyje przez cały swój czas ważności, ale po pierwszym odczycie otworzy go wyłącznie ta jedna przeglądarka. Wyczyszczenie ciasteczek lub danych witryny oznacza trwałą utratę dostępu.',
    bind_hint_webauthn: 'Najmocniejsza opcja. Wymaga klucza sprzętowego lub authenticatora powiązanego z urządzeniem. Passkeye synchronizowane są odrzucane, bo istnieją na każdym urządzeniu użytkownika.',
    bind_fallback_label: 'Pozwól na awaryjne samo cookie',
    bind_fallback_hint: 'Jeśli przeglądarka pierwszego odbiorcy nie potrafi utworzyć klucza, zejdź do samego ciasteczka. Słabsze, ale odbiorca wejdzie. Wyłączone oznacza, że zamiast tego zostanie odcięty.',
    bind_notice_device: 'Klucz jest poprawny i nic nie zostało jeszcze związane. Otwarcie tego sekretu zwiąże go z TĄ PRZEGLĄDARKĄ na stałe. Żadne inne urządzenie go nie odczyta. Tak samo jak inna przeglądarka na tym samym komputerze ani okno prywatne. Wyczyszczenie ciasteczek lub danych witryny również odcina dostęp bezpowrotnie.',
    bind_notice_webauthn: 'Klucz jest poprawny i nic nie zostało jeszcze związane. Otwarcie tego sekretu zwiąże go z kluczem sprzętowym na stałe. Przygotuj swój, za chwilę zostaniesz poproszony o jego zarejestrowanie. Potem żadne inne urządzenie nie odczyta tego sekretu, tak samo jak inna przeglądarka na tym samym komputerze. Passkeye synchronizowane zostaną odrzucone.',
    js_bind_locked: 'Ten sekret jest związany z inną przeglądarką. Został już otwarty gdzie indziej. A liczy się do tego również inna przeglądarka lub okno prywatne na tym samym urządzeniu. Tutaj nie da się go odczytać.',
    js_bind_unsupported: 'Ta przeglądarka nie potrafi utworzyć klucza wymaganego przez ten sekret, a nadawca nie dopuścił opcji awaryjnej.',
    js_bind_read_limit: 'Ten sekret osiągnął maksymalną liczbę odczytów.',
    js_bind_retry: 'Krok weryfikacji wygasł. Każde wyzwanie działa tylko raz. Odśwież stronę i spróbuj ponownie.',
    ttl_14d: '14 dni',
    ttl_30d: '30 dni',
    bind_confirm_title: 'Zanim to otworzysz',
    bind_confirm_yes: 'Rozumiem. Otwórz',
    bind_confirm_no: 'Anuluj',
    ttl_6h: '6 Godzin',
    js_hide_timer: 'UKRYCIE Z EKRANU ZA: ',
    js_bind_until: 'Dostęp wygasa ',
    js_err_challenge: 'Weryfikacja Cloudflare Turnstile nie powiodła się lub wygasła. Każde wyzwanie można wykorzystać tylko raz. Odśwież stronę, rozwiąż wyzwanie ponownie i spróbuj jeszcze raz.',
    js_err_bad_key: 'Nieprawidłowy klucz.',
    js_err_attempts_left: 'Pozostałe próby: {n}. Po ich wyczerpaniu sekret zostanie trwale zniszczony.',
    js_err_terminated: 'Zbyt wiele nieudanych prób. Sekret został trwale zniszczony. Poproś nadawcę o nowy link.',
    js_err_not_found: 'Ten link wygasł, został już wykorzystany albo klucz jest nieprawidłowy.',
    js_bind_synced: 'To jest passkey synchronizowany. Istnieje na każdym urządzeniu powiązanym z Twoim kontem, więc nie może związać tego sekretu z jednym urządzeniem. Użyj sprzętowego klucza bezpieczeństwa lub authenticatora powiązanego z urządzeniem. Odśwież stronę, zanim spróbujesz ponownie innym authenticatorem.',
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
    bind_label: 'Zugriff nach dem ersten Lesen',
    bind_mode_none: 'Einmaliges Lesen (Standard)',
    bind_mode_device: 'An ersten Browser binden',
    bind_mode_webauthn: 'An Sicherheitsschlüssel binden',
    bind_hint_none: 'Das Geheimnis wird im Moment des Lesens vernichtet. Wer Link und Schlüssel hat, bekommt genau einen Versuch.',
    bind_hint_device: 'Das Geheimnis bleibt für seine gesamte Laufzeit bestehen, aber nach dem ersten Lesen kann es nur noch dieser eine Browser öffnen. Cookies oder Websitedaten zu löschen bedeutet endgültigen Verlust.',
    bind_hint_webauthn: 'Stärkste Option. Erfordert einen Sicherheitsschlüssel oder einen gerätegebundenen Authenticator. Synchronisierte Passkeys werden abgelehnt, da sie auf jedem Gerät des Nutzers vorhanden sind.',
    bind_fallback_label: 'Nur-Cookie-Rückfall erlauben',
    bind_fallback_hint: 'Wenn der Browser des ersten Lesers keinen Schlüssel erzeugen kann, auf ein reines Cookie zurückfallen. Schwächer, aber der Empfänger kommt hinein. Aus bedeutet, dass er stattdessen ausgesperrt wird.',
    bind_notice_device: 'Ihr Schlüssel ist korrekt und es wurde noch nichts gebunden. Das Öffnen bindet dieses Geheimnis dauerhaft an DIESEN BROWSER. Kein anderes Gerät kann es lesen. Ebenso wenig ein anderer Browser auf demselben Computer oder ein privates Fenster. Auch das Löschen von Cookies oder Websitedaten schneidet Sie endgültig ab.',
    bind_notice_webauthn: 'Ihr Schlüssel ist korrekt und es wurde noch nichts gebunden. Das Öffnen bindet dieses Geheimnis dauerhaft an einen Sicherheitsschlüssel. Halten Sie ihn bereit, Sie werden gleich zur Registrierung aufgefordert. Danach kann kein anderes Gerät dieses Geheimnis lesen, ebenso wenig ein anderer Browser auf demselben Computer. Synchronisierte Passkeys werden abgelehnt.',
    js_bind_locked: 'Dieses Geheimnis ist an einen anderen Browser gebunden. Es wurde bereits anderswo geöffnet. Dazu zählt auch ein anderer Browser oder ein privates Fenster auf genau diesem Gerät. Hier kann es nicht gelesen werden.',
    js_bind_unsupported: 'Dieser Browser kann den erforderlichen Schlüssel nicht erzeugen, und der Absender hat keinen Rückfall erlaubt.',
    js_bind_read_limit: 'Dieses Geheimnis hat die maximale Anzahl an Lesevorgängen erreicht.',
    js_bind_retry: 'Der Verifizierungsschritt ist abgelaufen. Jede Prüfung gilt nur einmal. Laden Sie die Seite neu und versuchen Sie es erneut.',
    ttl_14d: '14 Tage',
    ttl_30d: '30 Tage',
    bind_confirm_title: 'Bevor Sie dies öffnen',
    bind_confirm_yes: 'Verstanden. Öffnen',
    bind_confirm_no: 'Abbrechen',
    ttl_6h: '6 Stunden',
    js_hide_timer: 'AUSBLENDEN IN: ',
    js_bind_until: 'Zugriff endet ',
    js_err_challenge: 'Die Cloudflare-Turnstile-Prüfung ist fehlgeschlagen oder abgelaufen. Jede Prüfung ist nur einmal gültig. Laden Sie die Seite neu, lösen Sie die Aufgabe erneut und versuchen Sie es noch einmal.',
    js_err_bad_key: 'Falscher Schlüssel.',
    js_err_attempts_left: 'Verbleibende Versuche: {n}. Sind sie aufgebraucht, wird das Geheimnis endgültig vernichtet.',
    js_err_terminated: 'Zu viele Fehlversuche. Das Geheimnis wurde endgültig vernichtet. Bitten Sie den Absender um einen neuen Link.',
    js_err_not_found: 'Dieser Link ist abgelaufen, wurde bereits verwendet, oder der Schlüssel ist falsch.',
    js_bind_synced: 'Das ist ein synchronisierter Passkey. Er existiert auf jedem mit Ihrem Konto verknüpften Gerät und kann dieses Geheimnis daher nicht an ein Gerät binden. Verwenden Sie einen Hardware-Sicherheitsschlüssel oder einen gerätegebundenen Authenticator. Laden Sie die Seite neu, bevor Sie es mit einem anderen Authenticator erneut versuchen.',
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
    bind_label: 'Accès après la première lecture',
    bind_mode_none: 'Lecture unique (par défaut)',
    bind_mode_device: 'Lier au premier navigateur',
    bind_mode_webauthn: 'Lier à une clé de sécurité',
    bind_hint_none: 'Le secret est détruit au moment de la lecture. Quiconque possède le lien et la clé n\'a qu\'une seule chance.',
    bind_hint_device: 'Le secret subsiste pendant toute sa durée de vie, mais après la première lecture, seul ce navigateur peut le rouvrir. Effacer les cookies ou les données du site entraîne une perte définitive.',
    bind_hint_webauthn: 'Option la plus forte. Nécessite une clé de sécurité ou un authentificateur lié à l\'appareil. Les passkeys synchronisées sont refusées, car elles existent sur tous les appareils de l\'utilisateur.',
    bind_fallback_label: 'Autoriser le repli cookie seul',
    bind_fallback_hint: 'Si le navigateur du premier lecteur ne peut pas créer de clé, se replier sur un simple cookie. Plus faible, mais le destinataire entre. Désactivé signifie qu\'il sera exclu à la place.',
    bind_notice_device: 'Votre clé est correcte et rien n\'a encore été lié. Ouvrir ce secret le lie définitivement à CE NAVIGATEUR. Aucun autre appareil ne pourra le lire. Ni un autre navigateur sur ce même ordinateur, ni une fenêtre privée. Effacer les cookies ou les données du site vous coupe aussi l\'accès pour de bon.',
    bind_notice_webauthn: 'Votre clé est correcte et rien n\'a encore été lié. Ouvrir ce secret le lie définitivement à une clé de sécurité. Préparez la vôtre, il vous sera demandé de l\'enregistrer maintenant. Ensuite, aucun autre appareil ne pourra lire ce secret, ni un autre navigateur sur ce même ordinateur. Les passkeys synchronisées seront refusées.',
    js_bind_locked: 'Ce secret est lié à un autre navigateur. Il a déjà été ouvert ailleurs. Ce qui inclut un autre navigateur ou une fenêtre privée sur cet appareil même. Il ne peut pas être lu ici.',
    js_bind_unsupported: 'Ce navigateur ne peut pas créer la clé requise par ce secret, et l\'expéditeur n\'a pas autorisé de repli.',
    js_bind_read_limit: 'Ce secret a atteint son nombre maximal de lectures.',
    js_bind_retry: 'L\'étape de vérification a expiré. Chaque défi ne fonctionne qu\'une fois. Actualisez la page et réessayez.',
    ttl_14d: '14 jours',
    ttl_30d: '30 jours',
    bind_confirm_title: 'Avant d\'ouvrir',
    bind_confirm_yes: 'J\'ai compris. Ouvrir',
    bind_confirm_no: 'Annuler',
    ttl_6h: '6 Heures',
    js_hide_timer: 'MASQUAGE DANS : ',
    js_bind_until: 'L\'accès expire ',
    js_err_challenge: 'La vérification Cloudflare Turnstile a échoué ou expiré. Chaque défi n\'est valable qu\'une fois. Actualisez la page, refaites le défi, puis réessayez.',
    js_err_bad_key: 'Clé incorrecte.',
    js_err_attempts_left: 'Tentatives restantes : {n}. Une fois épuisées, le secret est détruit définitivement.',
    js_err_terminated: 'Trop de tentatives échouées. Le secret a été détruit définitivement. Demandez un nouveau lien à l\'expéditeur.',
    js_err_not_found: 'Ce lien a expiré, a déjà été utilisé, ou la clé est incorrecte.',
    js_bind_synced: 'Il s\'agit d\'une passkey synchronisée. Elle existe sur tous les appareils liés à votre compte et ne peut donc pas lier ce secret à un seul appareil. Utilisez une clé de sécurité matérielle ou un authentificateur lié à l\'appareil. Actualisez la page avant de réessayer avec un autre authentificateur.',
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
    bind_label: 'Acceso tras la primera lectura',
    bind_mode_none: 'Lectura única (predeterminado)',
    bind_mode_device: 'Vincular al primer navegador',
    bind_mode_webauthn: 'Vincular a llave de seguridad',
    bind_hint_none: 'El secreto se destruye en el momento de leerlo. Quien tenga el enlace y la clave dispone de una sola oportunidad.',
    bind_hint_device: 'El secreto sobrevive durante toda su vigencia, pero tras la primera lectura solo ese navegador podrá abrirlo. Borrar las cookies o los datos del sitio supone la pérdida definitiva.',
    bind_hint_webauthn: 'La opción más fuerte. Requiere una llave de seguridad o un autenticador vinculado al dispositivo. Las passkeys sincronizadas se rechazan, porque existen en todos los dispositivos del usuario.',
    bind_fallback_label: 'Permitir recurso solo a cookie',
    bind_fallback_hint: 'Si el navegador del primer lector no puede crear una clave, recurrir solo a una cookie. Más débil, pero el destinatario entra. Desactivado significa que quedará excluido.',
    bind_notice_device: 'Tu clave es correcta y aún no se ha vinculado nada. Abrir este secreto lo vincula de forma permanente a ESTE NAVEGADOR. Ningún otro dispositivo podrá leerlo. Tampoco otro navegador en este mismo ordenador, ni una ventana privada. Borrar las cookies o los datos del sitio también te deja fuera para siempre.',
    bind_notice_webauthn: 'Tu clave es correcta y aún no se ha vinculado nada. Abrir este secreto lo vincula de forma permanente a una llave de seguridad. Ten la tuya lista, se te pedirá registrarla ahora. Después ningún otro dispositivo podrá leer este secreto, ni otro navegador en este mismo ordenador. Las passkeys sincronizadas serán rechazadas.',
    js_bind_locked: 'Este secreto está vinculado a otro navegador. Ya se abrió en otro lugar. Lo que incluye otro navegador o una ventana privada en este mismo dispositivo. No puede leerse aquí.',
    js_bind_unsupported: 'Este navegador no puede crear la clave que exige este secreto, y el remitente no permitió una alternativa.',
    js_bind_read_limit: 'Este secreto ha alcanzado su número máximo de lecturas.',
    js_bind_retry: 'El paso de verificación caducó. Cada desafío solo funciona una vez. Actualiza la página e inténtalo de nuevo.',
    ttl_14d: '14 días',
    ttl_30d: '30 días',
    bind_confirm_title: 'Antes de abrirlo',
    bind_confirm_yes: 'Entendido. Abrir',
    bind_confirm_no: 'Cancelar',
    ttl_6h: '6 Horas',
    js_hide_timer: 'SE OCULTA EN: ',
    js_bind_until: 'El acceso expira ',
    js_err_challenge: 'La verificación de Cloudflare Turnstile falló o caducó. Cada desafío solo puede usarse una vez. Actualiza la página, complétalo de nuevo y vuelve a intentarlo.',
    js_err_bad_key: 'Clave incorrecta.',
    js_err_attempts_left: 'Intentos restantes: {n}. Cuando se agoten, el secreto se destruirá de forma permanente.',
    js_err_terminated: 'Demasiados intentos fallidos. El secreto se ha destruido de forma permanente. Pide al remitente un enlace nuevo.',
    js_err_not_found: 'Este enlace ha caducado, ya se ha usado, o la clave es incorrecta.',
    js_bind_synced: 'Es una passkey sincronizada. Existe en todos los dispositivos vinculados a tu cuenta, así que no puede vincular este secreto a un solo dispositivo. Usa una llave de seguridad física o un autenticador vinculado al dispositivo. Actualiza la página antes de volver a intentarlo con otro autenticador.',
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
    bind_label: 'Доступ після першого читання',
    bind_mode_none: 'Одноразове читання (типово)',
    bind_mode_device: 'Прив\'язати до першого браузера',
    bind_mode_webauthn: 'Прив\'язати до апаратного ключа',
    bind_hint_none: 'Секрет знищується в момент читання. Той, хто має посилання й ключ, отримує рівно одну спробу.',
    bind_hint_device: 'Секрет живе весь свій термін, але після першого читання його відкриє лише той самий браузер. Очищення файлів cookie або даних сайту означає остаточну втрату.',
    bind_hint_webauthn: 'Найнадійніший варіант. Потрібен апаратний ключ або прив\'язаний до пристрою автентифікатор. Синхронізовані passkey відхиляються, бо вони існують на всіх пристроях користувача.',
    bind_fallback_label: 'Дозволити запасний варіант лише з cookie',
    bind_fallback_hint: 'Якщо браузер першого читача не може створити ключ, використати саме лише cookie. Слабше, але одержувач увійде. Вимкнено означає, що його натомість буде відрізано.',
    bind_notice_device: 'Ваш ключ правильний, і нічого ще не прив\'язано. Відкриття цього секрету назавжди прив\'яже його до ЦЬОГО БРАУЗЕРА. Жоден інший пристрій його не прочитає. Так само як інший браузер на цьому ж комп\'ютері чи приватне вікно. Очищення файлів cookie або даних сайту також відрізає доступ назавжди.',
    bind_notice_webauthn: 'Ваш ключ правильний, і нічого ще не прив\'язано. Відкриття цього секрету назавжди прив\'яже його до апаратного ключа. Підготуйте свій, зараз вас попросять його зареєструвати. Після цього жоден інший пристрій не прочитає цей секрет, так само як інший браузер на цьому ж комп\'ютері. Синхронізовані passkey буде відхилено.',
    js_bind_locked: 'Цей секрет прив\'язано до іншого браузера. Його вже відкрито деінде. Зокрема це може бути інший браузер або приватне вікно на цьому ж пристрої. Тут його прочитати неможливо.',
    js_bind_unsupported: 'Цей браузер не може створити потрібний для секрету ключ, а відправник не дозволив запасного варіанта.',
    js_bind_read_limit: 'Цей секрет досяг максимальної кількості читань.',
    js_bind_retry: 'Крок перевірки минув. Кожне випробування діє лише раз. Оновіть сторінку і спробуйте ще раз.',
    ttl_14d: '14 днів',
    ttl_30d: '30 днів',
    bind_confirm_title: 'Перш ніж відкрити',
    bind_confirm_yes: 'Зрозуміло. Відкрити',
    bind_confirm_no: 'Скасувати',
    ttl_6h: '6 Годин',
    js_hide_timer: 'ПРИХОВАННЯ ЧЕРЕЗ: ',
    js_bind_until: 'Доступ спливає ',
    js_err_challenge: 'Перевірка Cloudflare Turnstile не вдалася або спливла. Кожне випробування дійсне лише раз. Оновіть сторінку, пройдіть його ще раз і спробуйте знову.',
    js_err_bad_key: 'Неправильний ключ.',
    js_err_attempts_left: 'Залишилось спроб: {n}. Коли вони скінчаться, секрет буде знищено назавжди.',
    js_err_terminated: 'Забагато невдалих спроб. Секрет знищено назавжди. Попросіть у відправника нове посилання.',
    js_err_not_found: 'Це посилання спливло, вже було використане, або ключ неправильний.',
    js_bind_synced: 'Це синхронізований passkey. Він існує на кожному пристрої, привʼязаному до вашого облікового запису, тож не може привʼязати цей секрет до одного пристрою. Скористайтеся апаратним ключем безпеки або привʼязаним до пристрою автентифікатором. Оновіть сторінку, перш ніж пробувати ще раз з іншим автентифікатором.',
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
    bind_label: 'Acesso após a primeira leitura',
    bind_mode_none: 'Leitura única (padrão)',
    bind_mode_device: 'Vincular ao primeiro navegador',
    bind_mode_webauthn: 'Vincular a chave de segurança',
    bind_hint_none: 'O segredo é destruído no momento da leitura. Quem tiver o link e a chave tem exatamente uma chance.',
    bind_hint_device: 'O segredo permanece por toda a sua validade, mas após a primeira leitura só aquele navegador consegue abri-lo. Limpar cookies ou dados do site significa perda definitiva.',
    bind_hint_webauthn: 'Opção mais forte. Exige uma chave de segurança ou um autenticador vinculado ao dispositivo. Passkeys sincronizadas são recusadas, pois existem em todos os dispositivos do usuário.',
    bind_fallback_label: 'Permitir recurso apenas a cookie',
    bind_fallback_hint: 'Se o navegador do primeiro leitor não conseguir criar uma chave, recorrer apenas a um cookie. Mais fraco, mas o destinatário entra. Desligado significa que ele ficará de fora.',
    bind_notice_device: 'Sua chave está correta e nada foi vinculado ainda. Abrir este segredo o vincula permanentemente a ESTE NAVEGADOR. Nenhum outro dispositivo poderá lê-lo. Nem outro navegador neste mesmo computador, nem uma janela privada. Limpar cookies ou dados do site também corta seu acesso definitivamente.',
    bind_notice_webauthn: 'Sua chave está correta e nada foi vinculado ainda. Abrir este segredo o vincula permanentemente a uma chave de segurança. Tenha a sua à mão, será solicitado que você a registre agora. Depois nenhum outro dispositivo poderá ler este segredo, nem outro navegador neste mesmo computador. Passkeys sincronizadas serão recusadas.',
    js_bind_locked: 'Este segredo está vinculado a outro navegador. Já foi aberto em outro lugar. O que inclui outro navegador ou uma janela privada neste mesmo dispositivo. Não pode ser lido aqui.',
    js_bind_unsupported: 'Este navegador não consegue criar a chave exigida por este segredo, e o remetente não permitiu alternativa.',
    js_bind_read_limit: 'Este segredo atingiu o número máximo de leituras.',
    js_bind_retry: 'A etapa de verificação expirou. Cada desafio funciona apenas uma vez. Atualize a página e tente novamente.',
    ttl_14d: '14 dias',
    ttl_30d: '30 dias',
    bind_confirm_title: 'Antes de abrir',
    bind_confirm_yes: 'Entendi. Abrir',
    bind_confirm_no: 'Cancelar',
    ttl_6h: '6 Horas',
    js_hide_timer: 'OCULTA EM: ',
    js_bind_until: 'O acesso expira ',
    js_err_challenge: 'A verificação do Cloudflare Turnstile falhou ou expirou. Cada desafio só pode ser usado uma vez. Atualize a página, refaça o desafio e tente novamente.',
    js_err_bad_key: 'Chave incorreta.',
    js_err_attempts_left: 'Tentativas restantes: {n}. Quando acabarem, o segredo será destruído permanentemente.',
    js_err_terminated: 'Tentativas malsucedidas demais. O segredo foi destruído permanentemente. Peça um novo link ao remetente.',
    js_err_not_found: 'Este link expirou, já foi usado, ou a chave está incorreta.',
    js_bind_synced: 'Essa é uma passkey sincronizada. Ela existe em todos os dispositivos vinculados à sua conta, portanto não pode vincular este segredo a um único dispositivo. Use uma chave de segurança física ou um autenticador vinculado ao dispositivo. Atualize a página antes de tentar novamente com outro autenticador.',
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
    bind_label: '首次读取后的访问方式',
    bind_mode_none: '一次性读取（默认）',
    bind_mode_device: '绑定到首个浏览器',
    bind_mode_webauthn: '绑定到安全密钥',
    bind_hint_none: '密文在被读取的瞬间销毁。拿到链接和密钥的人只有一次机会。',
    bind_hint_device: '密文在有效期内保留，但首次读取后只有那一个浏览器能再次打开。清除 Cookie 或网站数据将导致永久失去访问权限。',
    bind_hint_webauthn: '最强选项。需要安全密钥或与设备绑定的验证器，同步的通行密钥会被拒绝，因为它存在于用户的每一台设备上。',
    bind_fallback_label: '允许仅 Cookie 回退',
    bind_fallback_hint: '如果首个读取者的浏览器无法创建密钥，则回退为仅使用 Cookie。安全性较低，但接收者仍能进入。关闭则表示他将被拒之门外。',
    bind_notice_device: '您的密钥正确，目前尚未绑定任何内容。打开此密文将把它永久绑定到"当前这个浏览器"。其他设备都无法读取，同一台电脑上的其他浏览器和无痕窗口同样无法读取。清除 Cookie 或网站数据也会永久切断访问。',
    bind_notice_webauthn: '您的密钥正确，目前尚未绑定任何内容。打开此密文将把它永久绑定到安全密钥，请准备好您的密钥，系统现在会要求您注册它。此后其他设备都无法读取此密文，同一台电脑上的其他浏览器同样无法读取。同步的通行密钥将被拒绝。',
    js_bind_locked: '此密文已绑定到其他浏览器。它已在别处被打开，这也包括同一台设备上的其他浏览器或无痕窗口。此处无法读取。',
    js_bind_unsupported: '此浏览器无法创建该密文所需的密钥，且发送方未允许回退方案。',
    js_bind_read_limit: '此密文已达到最大读取次数。',
    js_bind_retry: '验证步骤已过期，每个验证只能使用一次。请刷新页面后重试。',
    ttl_14d: '14 天',
    ttl_30d: '30 天',
    bind_confirm_title: '打开之前请注意',
    bind_confirm_yes: '我已了解，打开',
    bind_confirm_no: '取消',
    ttl_6h: '6 小时',
    js_hide_timer: '隐藏倒计时： ',
    js_bind_until: '访问权限到期：',
    js_err_challenge: 'Cloudflare Turnstile 验证失败或已过期。每个验证只能使用一次，请刷新页面，重新完成验证后再试。',
    js_err_bad_key: '密钥错误。',
    js_err_attempts_left: '剩余尝试次数：{n}。次数用尽后，密文将被永久销毁。',
    js_err_terminated: '失败次数过多，密文已被永久销毁。请向发送方索取新链接。',
    js_err_not_found: '此链接已过期、已被使用，或密钥错误。',
    js_bind_synced: '这是同步的通行密钥，它存在于与您账户关联的每台设备上，因此无法把此密文绑定到单一设备。请使用硬件安全密钥，或与设备绑定的验证器。 请先刷新页面，再用其他验证器重试。',
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
    bind_label: 'Přístup po prvním přečtení',
    bind_mode_none: 'Jednorázové přečtení (výchozí)',
    bind_mode_device: 'Svázat s prvním prohlížečem',
    bind_mode_webauthn: 'Svázat s bezpečnostním klíčem',
    bind_hint_none: 'Tajemství se zničí v okamžiku přečtení. Kdo má odkaz a klíč, dostane přesně jeden pokus.',
    bind_hint_device: 'Tajemství přetrvá po celou dobu platnosti, ale po prvním přečtení jej otevře už jen ten jeden prohlížeč. Vymazání cookies nebo dat webu znamená trvalou ztrátu.',
    bind_hint_webauthn: 'Nejsilnější volba. Vyžaduje bezpečnostní klíč nebo autentikátor svázaný se zařízením. Synchronizované passkeys jsou odmítnuty, protože existují na všech zařízeních uživatele.',
    bind_fallback_label: 'Povolit nouzové řešení jen s cookie',
    bind_fallback_hint: 'Pokud prohlížeč prvního čtenáře nedokáže vytvořit klíč, ustoupit k samotné cookie. Slabší, ale příjemce se dostane dovnitř. Vypnuto znamená, že bude místo toho odříznut.',
    bind_notice_device: 'Váš klíč je správný a zatím nebylo nic svázáno. Otevření tohoto tajemství jej trvale sváže s TÍMTO PROHLÍŽEČEM. Žádné jiné zařízení jej nepřečte. Stejně jako jiný prohlížeč na tomtéž počítači nebo anonymní okno. Vymazání cookies nebo dat webu vás rovněž odřízne natrvalo.',
    bind_notice_webauthn: 'Váš klíč je správný a zatím nebylo nic svázáno. Otevření tohoto tajemství jej trvale sváže s bezpečnostním klíčem. Připravte si jej, nyní budete vyzváni k registraci. Poté toto tajemství nepřečte žádné jiné zařízení, stejně jako jiný prohlížeč na tomtéž počítači. Synchronizované passkeys budou odmítnuty.',
    js_bind_locked: 'Toto tajemství je svázáno s jiným prohlížečem. Bylo již otevřeno jinde. Což zahrnuje i jiný prohlížeč nebo anonymní okno na tomto samém zařízení. Zde jej nelze přečíst.',
    js_bind_unsupported: 'Tento prohlížeč nedokáže vytvořit klíč, který toto tajemství vyžaduje, a odesílatel nepovolil náhradní řešení.',
    js_bind_read_limit: 'Toto tajemství dosáhlo maximálního počtu přečtení.',
    js_bind_retry: 'Ověřovací krok vypršel. Každou výzvu lze použít jen jednou. Obnovte stránku a zkuste to znovu.',
    ttl_14d: '14 dní',
    ttl_30d: '30 dní',
    bind_confirm_title: 'Než to otevřete',
    bind_confirm_yes: 'Rozumím. Otevřít',
    bind_confirm_no: 'Zrušit',
    ttl_6h: '6 Hodin',
    js_hide_timer: 'SKRYTÍ ZA: ',
    js_bind_until: 'Přístup vyprší ',
    js_err_challenge: 'Ověření Cloudflare Turnstile selhalo nebo vypršelo. Každou výzvu lze použít jen jednou. Obnovte stránku, vyřešte výzvu znovu a zkuste to zase.',
    js_err_bad_key: 'Nesprávný klíč.',
    js_err_attempts_left: 'Zbývající pokusy: {n}. Až dojdou, bude tajemství trvale zničeno.',
    js_err_terminated: 'Příliš mnoho neúspěšných pokusů. Tajemství bylo trvale zničeno. Požádejte odesílatele o nový odkaz.',
    js_err_not_found: 'Tento odkaz vypršel, byl už použit, nebo je klíč nesprávný.',
    js_bind_synced: 'Toto je synchronizovaný passkey. Existuje na každém zařízení propojeném s vaším účtem, takže nemůže svázat toto tajemství s jedním zařízením. Použijte hardwarový bezpečnostní klíč nebo autentikátor svázaný se zařízením. Než to zkusíte znovu s jiným autentikátorem, obnovte stránku.',
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
