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

- opcjonalne hasło (SHA-256 hasha weryfikowane server-side)
- limit pobrań (1 raz, 5 razy lub bez limitu)
- TTL (12h / 2 dni / 7 dni)
- automatyczne usunięcie po wygaśnięciu (cron co godzinę)
- blokada po 3 błędnych hasłach → plik usuwany natychmiast

---

## Zabezpieczenia

- **Burn-on-read** — sekret kasowany z KV po pierwszym poprawnym odczycie
- **Rate limiting hasła** — max 3 próby, potem trwałe usunięcie
- **CF Access** — endpointy tworzenia (`/gen`, `/api/store`, `/api/upload`, `/api/stats`) dostępne tylko dla uwierzytelnionych użytkowników
- **Security headers** — CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- **RFC 5987** — bezpieczne kodowanie nazw plików w nagłówku `Content-Disposition`
- **Brak logowania treści** — błędy zwracają generyczne komunikaty (bez `e.message`)

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

### Lokalny development

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
