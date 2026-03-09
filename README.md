# INS Secrets

Bezpieczne udostępnianie haseł i plików — zbudowane na Cloudflare Workers.

## Jak to działa

### Sekrety tekstowe (hasła, dane dostępowe)

Szyfrowanie odbywa się **wyłącznie w przeglądarce**. Serwer nigdy nie widzi danych w postaci jawnej ani klucza szyfrującego.

```
[Nadawca]                          [Serwer / KV]              [Odbiorca]
    │                                    │                         │
    ├─ wpisuje treść + hasło             │                         │
    ├─ PBKDF2(hasło, id, 100k iter)      │                         │
    │   → klucz AES-256-GCM             │                         │
    ├─ AES-GCM.encrypt(treść)           │                         │
    ├─ PBKDF2(hasło, id+"_v", 50k iter) │                         │
    │   → verifier (odcisk hasła)       │                         │
    ├─── POST /api/store ───────────────►│                         │
    │   { id, encryptedData, verifier } │                         │
    │                                   │ przechowuje             │
    │                                   │ szyfrogram + verifier   │
    ├─ generuje link: /receive/{id}#{hasło}                        │
    │                                   │                         │
    │                              [link do odbiorcy]             │
    │                                   │                         │
    │                                   │◄── POST /api/retrieve ──┤
    │                                   │    { verifier }         │
    │                                   ├─ sprawdza verifier      │
    │                                   ├─ usuwa z KV (burn)      │
    │                                   ├───── { encryptedData } ►│
    │                                   │                         ├─ AES-GCM.decrypt(klucz z #hash)
    │                                   │                         ├─ wyświetla treść
    │                                   │                         └─ auto-kasuje po 5 min
```

**Co wie serwer:** zaszyfrowany ciąg bajtów + hash weryfikacyjny hasła.
**Czego serwer nie wie:** treści sekretu, klucza szyfrującego, samego hasła.

#### Szczegóły kryptografii

| Element | Algorytm | Parametry |
|---|---|---|
| Wyprowadzanie klucza | PBKDF2 | SHA-256, 100 000 iteracji |
| Szyfrowanie | AES-GCM | 256-bit, losowe IV (12B) |
| Weryfikator hasła | PBKDF2 | SHA-256, 50 000 iteracji, sól `id + "_v"` |
| Entropia linku z hasłem | Klucz 20 znaków z alfabetu 58 znaków | ~118 bitów |

---

### Pliki

Pliki **nie są szyfrowane po stronie klienta** — trafiają bezpośrednio do R2. Ochrona odbywa się przez:

- opcjonalne hasło (`SHA-256(hasło + PEPPER)` weryfikowane server-side)
- limit pobrań (1 raz, 5 razy lub bez limitu)
- TTL wymuszony server-side — maksymalnie 72h niezależnie od wartości z frontendu
- automatyczne usunięcie po wygaśnięciu (cron co godzinę)
- blokada po 3 błędnych hasłach → plik usuwany natychmiast

#### Hashowanie hasła pliku — Global Pepper

Hasła do plików są hashowane jako `SHA-256(hasło + PEPPER)`, gdzie `PEPPER` to globalny sekret przechowywany jako Cloudflare Secret (nie w kodzie, nie w repozytorium). Oznacza to, że nawet w przypadku wycieku bazy danych D1 hasze haseł są bezużyteczne bez znajomości peppera.

```
hasło użytkownika  ──┐
                     ├─► SHA-256 ──► hash w D1
PEPPER (CF Secret) ──┘
```

Worker nie wystartuje jeśli `PEPPER` nie jest ustawiony (`bindings guard`).

#### Limit TTL plików

Backend wymusza maksymalny czas życia pliku równy `CONFIG.maxTtl` (72h), niezależnie od wartości przysłanej przez klienta:

```
safeTtl = Math.min(ttl_z_frontendu, CONFIG.maxTtl * 1000)
```

Identyczna logika jak przy sekretach tekstowych w KV.

---

## Zabezpieczenia

- **Burn-on-read** — sekret kasowany z KV po pierwszym poprawnym odczycie
- **Rate limiting hasła** — max 3 próby, potem trwałe usunięcie (dotyczy zarówno sekretów jak i plików)
- **Global Pepper** — hasła do plików hashowane z globalnym sekretem (`PEPPER`) z Cloudflare Secrets; wyciek D1 nie kompromituje haseł
- **TTL cap server-side** — maksymalny czas życia pliku wymuszany przez backend (72h), frontend nie może go przekroczyć
- **CF Access** — endpointy tworzenia (`/gen`, `/api/store`, `/api/upload`, `/api/stats`) dostępne tylko dla uwierzytelnionych użytkowników
- **Security headers** — CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- **RFC 5987** — bezpieczne kodowanie nazw plików w nagłówku `Content-Disposition`
- **Brak logowania treści** — błędy zwracają generyczne komunikaty (bez `e.message`)
- **Bindings guard** — worker zwraca 500 przy starcie jeśli brakuje któregokolwiek z wymaganych bindingów (DB, BUCKET, KV, PEPPER)

---

## Architektura

```
Browser ──► Cloudflare Access ──► Cloudflare Worker (Hono / TypeScript)
                                        │
                              ┌─────────┼──────────┐
                              ▼         ▼          ▼
                          KV Store    D1 DB      R2 Bucket
                         (sekrety)  (metadane   (pliki)
                                     plików)
```

| Zasób | Zastosowanie |
|---|---|
| **KV** (`SECRETS_STORE`) | Zaszyfrowane sekrety tekstowe + verifier, TTL 1–72h |
| **D1** (`DB`) | Metadane plików (nazwa, rozmiar, TTL, licznik pobrań, hash hasła) |
| **R2** (`BUCKET`) | Binarne dane plików, multipart upload do 5 GB |

---

## Stack

- **Runtime:** Cloudflare Workers
- **Framework:** [Hono](https://hono.dev) v4
- **Język:** TypeScript (strict)
- **Narzędzie deploy:** Wrangler v4

---

## Deploy

```bash
npm install

# Uzupełnij wrangler.toml rzeczywistymi ID bindingów, następnie:
npx wrangler deploy
```

### Wymagane bindingi w `wrangler.toml`

```toml
[[kv_namespaces]]
binding = "SECRETS_STORE"
id = "<KV_NAMESPACE_ID>"

[[d1_databases]]
binding = "DB"
database_name = "<D1_DATABASE_NAME>"
database_id = "<D1_DATABASE_ID>"

[[r2_buckets]]
binding = "BUCKET"
bucket_name = "<R2_BUCKET_NAME>"
```

### Wymagany sekret (Cloudflare Secret)

`PEPPER` musi być ustawiony przed deployem — nie trafia do repozytorium ani `wrangler.toml`:

```bash
# Wygeneruj silny losowy pepper:
openssl rand -base64 32

# Ustaw jako Cloudflare Secret:
npx wrangler secret put PEPPER
```

### Lokalny development

Utwórz plik `.dev.vars` (ignorowany przez git):

```ini
PEPPER=lokalny-pepper-tylko-do-testow
```

```bash
npx wrangler dev
# → http://localhost:8787
```

---

## Endpointy

| Metoda | Ścieżka | Opis | Dostęp |
|---|---|---|---|
| `GET` | `/gen` | Panel tworzenia sekretów i uploadów | 🔒 CF Access |
| `POST` | `/api/store` | Zapis zaszyfrowanego sekretu do KV | 🔒 CF Access |
| `POST` | `/api/retrieve/:id` | Odczyt i burn sekretu | Publiczny |
| `GET` | `/receive/:id` | Strona odbioru sekretu | Publiczny |
| `GET` | `/api/stats` | Statystyki storage | 🔒 CF Access |
| `POST` | `/api/upload/init` | Inicjacja multipart upload | 🔒 CF Access |
| `PUT` | `/api/upload/part` | Upload części pliku | 🔒 CF Access |
| `POST` | `/api/upload/complete` | Finalizacja uploadu | 🔒 CF Access |
| `GET` | `/share/:id` | Pobranie pliku | Publiczny |
| `DELETE` | `/api/del/:id` | Usunięcie pliku | Publiczny* |

> *`/api/del` nie jest objęty CF Access — świadoma decyzja projektowa.
