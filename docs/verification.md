# Протокол фактичної верифікації, 26.11.2026

## 1. Автоматизовані тести

Виконано в контейнері Linux із Python **3.13.5**, `cryptography 46.0.4`, `psutil 7.2.2` та `pytest 9.0.2`:

```text
$ python -m pytest -q tests --durations=5 --maxfail=1
........................................ [100%]
40 passed in 9.31s
```

Набір включає 3 режими, файли різних розмірів і порожні файли, випадкові nonce, AAD, CBC padding, невірні теги, пошкоджений ciphertext і header, неправильні ключі, ротацію, права доступу до метаданих, часові та лічильні обмеження, CLI, журналювання та benchmark.

> Ці результати підтверджують один локальний прогін тестів, **а не** проходження GitHub Actions. CI після завантаження репозиторію перевіряється окремо.

## 2. Демонстрація CLI та перевірка GCM-тегу

У тимчасовому каталозі запущено CLI з тестовою фразою (її не вміщено у файл звіту):

```text
$ python aes_cli.py key new --label default
Key ID: <random ID> | AES 256 | active
$ python aes_cli.py enc --in plain.txt --out a.enc --label default --mode gcm
OK | enc | AES-256 | GCM | 13 bytes | 357.34 ms
$ python aes_cli.py dec --in a.enc --out decrypted.txt
OK | dec | AES-256 | GCM | 13 bytes | 359.98 ms
$ python tamper_demo.py --file a.enc --which tag
Created tampered copy: a.enc.tampered (tag)
$ python aes_cli.py dec --in a.enc.tampered --out rejected.txt
ERROR [IntegrityError]: Authentication failed: invalid GCM tag or AAD
Exit status: 2
No plaintext output after invalid tag
$ python aes_cli.py logs summary
{
  "dec:failed": 1,
  "dec:success": 1,
  "enc:success": 1,
  "key.new:success": 1
}
```

Шлях до вихідного відкритого тексту `rejected.txt` **не було створено** після відмови.

Час CLI включає похідну PBKDF2, файловий доступ та журналювання. Це **не** той самий показник, що `benchmarks/results.csv`, де PBKDF2 свідомо виключено.

## 3. Вимірювання продуктивності

Виконано **60 замірів** (`4 розміри × 3 режими × 5 повторів`). **Усі** зафіксували збіг SHA-256 оригінального й відновленого файлів. Первинні дані зберігаються в `benchmarks/results.json` і `results.csv`.

Для PBKDF2-HMAC-SHA256 600 000 ітерацій отримано три окремі часи **373.186, 411.442, 351.210 мс**, медіана **373.186 мс**. Джерело: `benchmarks/kdf_results.json`.

### Відтворення в Kali

```bash
python -m pytest -q tests
python aes_cli.py bench --sizes 1KB 64KB 1MB 4MB --modes gcm cbc ctr --repeat 5
```

Показники в Kali можуть суттєво відрізнятися через CPU, архітектуру, OpenSSL, швидкість диска, навантаження системи та віртуалізацію. Для курсової роботи їх слід позначати як нову серію, а не підмінювати початкові числа.
