# Тестовые сертификаты (ТЕСТОВЫЕ, не для продукта)

Файлы нужны тестам TLS на loopback (`src/tests/tls.rs`). Это одноразовые ключи и сертификаты
из OpenSSL 3.5.5, действуют 100 лет от 2026-10-27. Секретный ключ УЦ после выпуска удалён;
секретный ключ сервера (`server-pkcs8.der`) тестовый и в продукт не попадает.
Продукт доверяет только корням Mozilla (`webpki-roots`); тест `production_roots_reject_test_cert`
проверяет, что эти файлы ими не принимаются.

| Файл | Что |
|---|---|
| `ca.der` | тестовый корневой сертификат (DER) |
| `server-github.der` | сертификат сервера для имени `github.com` (DER) |
| `server-wrong.der` | тот же ключ, имя `evil.example` (для проверки отказа по имени) |
| `server-pkcs8.der` | ключ сервера, PKCS#8 (DER) |

Как создать заново (OpenSSL 3.x, в Git Bash перед командами `export MSYS_NO_PATHCONV=1`):

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.k -out ca.pem \
  -days 36500 -subj "/CN=chervo TEST ONLY CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout leaf.k -out leaf.csr \
  -subj "/CN=chervo TEST ONLY leaf"
# ext-github.cnf: basicConstraints=CA:FALSE, keyUsage=digitalSignature, extendedKeyUsage=serverAuth,
#                 subjectAltName=DNS:github.com   (для server-wrong: DNS:evil.example)
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.k -CAcreateserial -days 36500 \
  -out github.pem -extfile ext-github.cnf
openssl x509 -in github.pem -outform DER -out server-github.der
openssl x509 -in ca.pem -outform DER -out ca.der
openssl pkcs8 -topk8 -nocrypt -in leaf.k -outform DER -out server-pkcs8.der
```

Файлы ключей `ca.k`, `leaf.k` в репозиторий не кладутся (страж `scripts/check-forbidden.sh`
ищет `*.key` и `*.sec`).
