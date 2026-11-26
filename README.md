# ЛР №4–5. Реалізація симетричного шифрування з використанням AES

**Виконав:** Чучула Євгеній Андрійович. **Середовище:** Python 3.11+; Kali Linux / Linux; GitHub Actions. **Дата реалізації:** 26.11.2026.

Мета — реалізувати **шифрування і відновлення файлів**, керування ключами PBKDF2, контроль цілісності, аналіз швидкодії й демонстрацію підміни даних. Проєкт розроблено на основі структури додатка викладача `додаток_лр_4-5.rar`; вихідні шаблони доповнено повноцінними тестами та модульним API.

## Можливості

- **AES-128 / AES-192 / AES-256**, вибір під час створення ключа. Розмір **блоку AES завжди 128 біт**; його не можна змінити в межах AES.
- **AES-GCM** з 96-бітним випадковим nonce і 128-бітним тегом; рекомендований режим для нових файлових операцій.
- **AES-CBC + Encrypt-then-HMAC-SHA256** із випадковим 128-бітним IV, PKCS#7 або `none` для даних кратних 16 байтам.
- **AES-CTR + Encrypt-then-HMAC-SHA256** — третій режим, приклад розширюваності інтерфейсу.
- **PBKDF2-HMAC-SHA256**, випадковий salt 16 байтів, 600 000 ітерацій, пароль вводиться через `getpass`; на диск пишуться **тільки salt/метадані/перевірочний MAC**, не відкритий ключ.
- **Ротація** ключів: старі ключі залишаються доступними *тільки для дешифрування*, нові отримують свій salt та key-id; ліміт 100 зашифрованих файлів / 90 днів для активного ключа — навчальна політика.
- Потокова обробка даних чанками по 256 КіБ, **перевірка MAC до дешифрування CBC/CTR**, атомарне створення вихідного файлу лише після успішної перевірки GCM-тегу.
- Локальний JSONL-журнал **без паролів, ключів і вмісту файлів**. Інтерактивна консоль підтримує перемикання `gcm`, `cbc`, `ctr` **без перезапуску**.

## Установлення (Kali Linux)

```bash
cd ~/Downloads/LR4-5_AES_Lab_Chuchula
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

## Швидкий запуск

```bash
# 1. Новий ключ: програма безпечно попросить пароль двічі.
python aes_cli.py key new --label default --key-bits 256

# 2. AES-GCM із випадковим nonce.
python aes_cli.py enc --in data/sample.txt --out outputs/sample.gcm.enc --mode gcm --label default
python aes_cli.py dec --in outputs/sample.gcm.enc --out outputs/sample.gcm.dec

# 3. AES-CBC+HMAC з PKCS#7 (пароль вводиться під час операції).
python aes_cli.py enc --in data/sample.txt --out outputs/sample.cbc.enc --mode cbc --padding pkcs7 --label default
python aes_cli.py dec --in outputs/sample.cbc.enc --out outputs/sample.cbc.dec

# 4. Третій режим CTR+HMAC.
python aes_cli.py enc --in data/sample.txt --out outputs/sample.ctr.enc --mode ctr --label default

# 5. Інтерактивний режим (команди: mode cbc, mode gcm, enc ..., dec ..., rotate, exit).
python aes_cli.py shell

# 6. Ротація, ключі, події.
python aes_cli.py key rotate --label default
python aes_cli.py key list
python aes_cli.py logs summary
```

Ключі, отримані через PBKDF2, не записуються у файл. `key rotate` не видаляє метадані попереднього ключа: завдяки `key_id` у заголовку можна дешифрувати попередні архіви зі старою парольною фразою.

**Для автоматичних тестів, але не звичайного використання:** підтримується змінна середовища `AES_LAB_PASSWORD`. Не зберігайте її в Git, історії shell чи скриншотах. CLI **навмисно не приймає** `--password` у параметрах командного рядка, на відміну від початкового шаблону викладача.

## Вибір параметрів

```bash
python aes_cli.py key new --label aes128 --key-bits 128
python aes_cli.py enc --in data/sample.txt --out outputs/sample.aes128.enc \
  --label aes128 --mode cbc --block-bits 128 --iv-source random --padding pkcs7
```

- `--block-bits` приймає лише `128`: параметр винесено до інтерфейсу для явної перевірки фіксованої довжини блоку AES.
- `--iv-source random` — безпечне генерування nonce/IV всередині модуля. Ручне введення IV/nonce вимкнуто, щоб уникнути повторів (особливо небезпечних для GCM/CTR).
- `--padding pkcs7` або `none` дозволено лише для CBC; `none` вимагає довжину файлу кратну 16 байтам. Для GCM/CTR — лише `none`.
- `--aad 'context'` підписує зовнішній контекст без його шифрування; те саме значення треба надати при дешифруванні.
- `--force` явно дозволяє перезапис наявного *вихідного* файлу; за замовчуванням це заборонено.

## Демонстрація підміни

```bash
python tamper_demo.py --file outputs/sample.gcm.enc --which tag --out outputs/sample.tampered
python aes_cli.py dec --in outputs/sample.tampered --out outputs/should_not_exist.txt
# ERROR [IntegrityError]; код завершення 2; вихідний файл НЕ створюється.

python tamper_demo.py --file outputs/sample.cbc.enc --which ciphertext --out outputs/cbc.tampered
python aes_cli.py dec --in outputs/cbc.tampered --out outputs/cbc.recovered
# HMAC не збігається, відмова в дешифруванні.
```

Демонстрацію підміни створено **лише для власних навчальних файлів**.

## Вимірювання

```bash
python aes_cli.py bench --sizes 1KB 64KB 1MB 4MB --modes gcm cbc ctr --repeat 5
```

Файли `benchmarks/results.csv`, `benchmarks/results.json`, `benchmarks/results.md` містять **реально виміряні значення** на Linux-контейнері; `benchmarks/throughput.png` — ілюстрація. **PBKDF2 не включено** у час шифрування/дешифрування; для нього є окрема таблиця `benchmarks/kdf_results.json`.

## Структура проєкту

| Шлях | Призначення |
|---|---|
| `aes_cli.py` | Команди `key`, `enc`, `dec`, `shell`, `bench`, `logs` |
| `key_manager.py` | PBKDF2, salt, перевірка пароля, ротація ключів, обмеження використання |
| `crypto_aes.py` | AES-GCM/CBC/CTR, HMAC, потоковий формат контейнера та автентифікація |
| `logger_setup.py` | Журнал JSONL і підсумок подій |
| `tamper_demo.py` | Модифікація контрольних файлів і тегів |
| `benchmark.py` | Вимірювання часу, CPU, споживання пам'яті (sampled RSS) та SHA-256 |
| `tests/` | Автоматизовані позитивні й негативні тести |
| `docs/LR4-5_report.md` | Звіт за всіма шістьма завданнями |
| `.github/workflows/tests.yml` | GitHub Actions для Python 3.11 і 3.12 |
| `.aes-lab/` | Локальні метадані ключів і логи, **не комітяться** |

## Безпека та обмеження

У GCM автентифікується *весь заголовок контейнера* плюс додаткові автентифіковані дані (AAD). У CBC/CTR перевіряється HMAC-SHA256 за схемою Encrypt-then-MAC **перед** отриманням відкритого тексту. Тег/шифртекст/заголовок, змінені третьою стороною, призводять до відхилення файлу. Криптографічна автентифікація **не забороняє повторне відтворення незміненого файлу** (replay) і не захищає від втрати пароля.

Висока ентропія парольної фрази критична. Метадані PBKDF2 допускають офлайн-перебір паролів, тому пароль має бути унікальним і довгим. Застосунок навчальний, не проходив незалежного аудиту, не замінює KMS/HSM або безпечне централізоване сховище.

Деталі й аналіз: [загальний звіт](docs/LR4-5_report.md), [ключі](docs/key-lifecycle.md), [модель загроз](docs/security-analysis.md), [методика бенчмарку](docs/bench-analysis.md), [журналювання](docs/log-analysis.md), [протокол перевірки](docs/verification.md).

## Верифіковані джерела

1. [NIST SP 800-38D — GCM/GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final).
2. [NIST SP 800-38A — CBC/CTR](https://csrc.nist.gov/pubs/sp/800/38/a/final).
3. [Python cryptography — Symmetric encryption](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/).
4. [OWASP — Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
5. [OWASP — Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
