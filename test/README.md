# Use case – test decoder

Questa cartella contiene test di use case per verificare che ogni decoder:

1. **Decodifichi** correttamente il formato del cookie (Decode).
2. **Trovi la chiave** dalla wordlist (Unsign) quando il cookie è stato firmato con una chiave nota.

## Esecuzione

Dalla root del repository:

```bash
go test ./test/ -v
```

Per un singolo decoder, ad esempio CookieSignature:

```bash
go test ./test/ -v -run TestUseCase_CookieSignature
```

## Use case inclusi

| Decoder        | Test                    | Note                                              |
|----------------|-------------------------|---------------------------------------------------|
| CookieSignature| `TestUseCase_CookieSignature` | Cookie generato in test (Node.js cookie-signature). |
| Gorilla        | `TestUseCase_Gorilla`   | Cookie generato (Gorilla Securecookie signed).    |
| Symfony        | `TestUseCase_Symfony`   | Cookie generato (payload--hex).                   |
| Spring         | `TestUseCase_Spring`    | Cookie generato (base64--hex).                    |
| Django         | `TestUseCase_Django`    | Solo Decode (vettore noto, chiave non pubblica).  |
| Flask          | `TestUseCase_Flask`     | Vettore da cookie_test.go.                        |
| JWT            | `TestUseCase_JWT`       | Vettore da cookie_test.go.                        |
| Rack           | `TestUseCase_Rack`      | Vettore da cookie_test.go.                        |
| Express        | `TestUseCase_Express`   | Vettore da cookie_test.go.                        |
| ItsDangerous   | `TestUseCase_ItsDangerous` | Vettore da cookie_test.go.                     |
| Laravel        | `TestUseCase_Laravel`   | Vettore da cookie_test.go.                        |

Per i decoder nuovi (CookieSignature, Gorilla, Symfony, Spring) il test costruisce un cookie firmato con una chiave nota e verifica che `Unsign` restituisca quella chiave.
