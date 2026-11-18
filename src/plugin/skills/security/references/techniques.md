# Прийоми безпеки

Maturity: зріле, стабільне, молоде.

1. **OWASP Top 10:2025**
   - Навіщо: спільна мова для найпоширеніших класів ризику.
   - Інструмент: чекліст `references/owasp-checklist.md`.
   - Джерело: https://owasp.org/Top10/2025/
   - Maturity: зріле. Безкоштовно.

2. **Авторизація на рівні об'єкта**
   - Навіщо: найпоширеніший ризик API, а сканери його майже не бачать.
   - Інструмент: таблиця обробників, негативні тести; OWASP API1:2023 і шпаргалка IDOR.
   - Джерело: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/ і https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
   - Maturity: зріле. Безкоштовно.

3. **Загальні правила авторизації**
   - Навіщо: заборона за замовчуванням, мінімальні права, перевірка на кожен запит.
   - Інструмент: OWASP Authorization Cheat Sheet.
   - Джерело: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
   - Maturity: зріле. Безкоштовно.

4. **Вимоги замість інтуїції**
   - Навіщо: перелік верифікованих вимог для аудиту глибшого за Top 10.
   - Інструмент: OWASP ASVS.
   - Джерело: https://github.com/OWASP/ASVS
   - Maturity: зріле. Безкоштовно.

5. **Параметризація запитів**
   - Навіщо: прибирає клас SQL-ін'єкцій архітектурно.
   - Інструмент: шпаргалка OWASP, параметри драйвера.
   - Джерело: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
   - Maturity: зріле. Безкоштовно.

6. **Захист від SSRF**
   - Навіщо: URL від користувача може вести до метаданих хмари й внутрішніх сервісів.
   - Інструмент: шпаргалка OWASP, список дозволених адрес.
   - Джерело: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
   - Maturity: зріле. Безкоштовно.

7. **Зберігання паролів**
   - Навіщо: перевірені алгоритми й параметри замість власних схем.
   - Інструмент: Argon2id, scrypt, bcrypt.
   - Джерело: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
   - Maturity: зріле. Безкоштовно.

8. **Керування секретами**
   - Навіщо: життєвий цикл: зберігання, ротація, відкликання, аудит.
   - Інструмент: шпаргалка OWASP; конфігурація в оточенні за 12-factor.
   - Джерело: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html і https://12factor.net/config
   - Maturity: зріле. Безкоштовно.

9. **Скан історії git на секрети**
   - Навіщо: рушій плагіна перевіряє файли й індекс, а історію треба сканувати окремо.
   - Інструмент: Gitleaks.
   - Джерело: https://github.com/gitleaks/gitleaks
   - Maturity: стабільне. Безкоштовно.

10. **Вразливості залежностей**
    - Навіщо: lockfile проти бази вразливостей, багато екосистем.
    - Інструмент: OSV-Scanner, pip-audit, команда `audit` профілю.
    - Джерело: https://osv.dev/ , https://github.com/google/osv-scanner , https://github.com/pypa/pip-audit
    - Maturity: стабільне. Безкоштовно.

11. **Оцінка здоровʼя проєкту-залежності**
    - Навіщо: автоматичні перевірки практик проєкту: code review, закріплення, підтримка.
    - Інструмент: OpenSSF Scorecard.
    - Джерело: https://github.com/ossf/scorecard
    - Maturity: стабільне. Безкоштовно.

12. **Рівні цілісності збірки**
    - Навіщо: рамка походження артефактів; підпис без довгоживучих ключів.
    - Інструмент: SLSA, Sigstore.
    - Джерело: https://slsa.dev/ і https://www.sigstore.dev/
    - Maturity: стабільне. Безкоштовно.

13. **SBOM і скан образів**
    - Навіщо: знати, що саме поставляється; знайти вразливості в образі.
    - Інструмент: Syft, CycloneDX, Trivy.
    - Джерело: https://github.com/anchore/syft , https://cyclonedx.org/ , https://github.com/aquasecurity/trivy
    - Maturity: стабільне. Безкоштовно.

14. **Динамічний скан власного застосунку**
    - Навіщо: перевіряє запущений застосунок ззовні, лише на тому, що вам належить.
    - Інструмент: ZAP.
    - Джерело: https://www.zaproxy.org/
    - Maturity: зріле. Безкоштовно.

15. **Запобігання XSS**
    - Навіщо: контекстне кодування й безпечні API замість ручних замін.
    - Інструмент: шпаргалка OWASP.
    - Джерело: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
    - Maturity: зріле. Безкоштовно.
