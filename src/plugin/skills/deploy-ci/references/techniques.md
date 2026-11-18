# Прийоми випуску й CI

Maturity: зріле, стабільне, молоде.

1. **Безпечне використання GitHub Actions**
   - Навіщо: закріплення за повним SHA, мінімальні права, ін'єкції виразів.
   - Інструмент: офіційна довідка.
   - Джерело: https://docs.github.com/en/actions/reference/security/secure-use
   - Maturity: зріле. Безкоштовно.

2. **Статична перевірка воркфлоу**
   - Навіщо: ловить синтаксичні помилки й небезпечні шаблони до запуску.
   - Інструмент: actionlint, zizmor.
   - Джерело: https://github.com/rhysd/actionlint і https://github.com/zizmorcore/zizmor
   - Maturity: стабільне. Безкоштовно.

3. **Автоматичне закріплення й оновлення**
   - Навіщо: SHA не застарівають без нагляду, оновлення приходять окремими PR.
   - Інструмент: pinact, Renovate.
   - Джерело: https://github.com/suzuki-shunsuke/pinact і https://docs.renovatebot.com/
   - Maturity: стабільне. Безкоштовно.

4. **Короткоживучі облікові дані через OIDC**
   - Навіщо: у сховищі CI не лежить довгоживучий ключ хмари.
   - Інструмент: OpenID Connect у GitHub Actions.
   - Джерело: https://docs.github.com/en/actions/concepts/security/openid-connect
   - Maturity: стабільне. Безкоштовно.

5. **Інженерія випусків**
   - Навіщо: герметичні збірки, самообслуговування, контроль конфігурації.
   - Інструмент: розділ книги SRE.
   - Джерело: https://sre.google/sre-book/release-engineering/
   - Maturity: зріле. Безкоштовно.

6. **Канарковий випуск**
   - Навіщо: збій зачіпає малу частку трафіку, рішення базується на порівнянні показників.
   - Інструмент: балансування; розділ SRE Workbook і нотатка Фаулера.
   - Джерело: https://sre.google/workbook/canarying-releases/ і https://martinfowler.com/bliki/CanaryRelease.html
   - Maturity: зріле. Безкоштовно.

7. **Blue-green**
   - Навіщо: миттєве перемикання й швидкий відкат; потребує вдвічі більше ресурсів і сумісної схеми.
   - Інструмент: два оточення й маршрутизатор.
   - Джерело: https://martinfowler.com/bliki/BlueGreenDeployment.html
   - Maturity: зріле. Безкоштовно.

8. **Прапорці функцій**
   - Навіщо: відокремлюють випуск коду від увімкнення функції; вимкнення швидше за перевипуск.
   - Інструмент: стаття Піта Ходжсона, власна таблиця прапорців.
   - Джерело: https://martinfowler.com/articles/feature-toggles.html
   - Maturity: зріле. Безкоштовно. Прапорці мають дату видалення.

9. **Конфігурація в оточенні**
   - Навіщо: той самий артефакт працює всюди, секрети не в коді.
   - Інструмент: Twelve-Factor App.
   - Джерело: https://12factor.net/ і https://12factor.net/config
   - Maturity: зріле. Безкоштовно.

10. **Практики Docker і build secrets**
    - Навіщо: малий образ, стабільний кеш, секрет не лишається в шарах.
    - Інструмент: документація Docker.
    - Джерело: https://docs.docker.com/build/building/best-practices/ і https://docs.docker.com/build/building/secrets/
    - Maturity: зріле. Безкоштовно.

11. **Перевірки готовності в оркестраторі**
    - Навіщо: liveness перезапускає, readiness прибирає з балансування, startup дає час на старт.
    - Інструмент: Kubernetes probes.
    - Джерело: https://kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/
    - Maturity: зріле. Безкоштовно.

12. **Бекапи з дедуплікацією й перевіркою**
    - Навіщо: зашифровані знімки поза сервером і вбудована перевірка цілісності.
    - Інструмент: restic.
    - Джерело: https://restic.readthedocs.io/
    - Maturity: зріле. Безкоштовно, сховище може коштувати 🔒.

13. **Монітор, що чекає на пульс**
    - Навіщо: сповіщає, коли запланована задача не запустилась, а не лише коли впала.
    - Інструмент: Healthchecks, Uptime Kuma.
    - Джерело: https://healthchecks.io/ і https://github.com/louislam/uptime-kuma
    - Maturity: стабільне. Безкоштовно (власне розміщення), хмарні тарифи 🔒 у Healthchecks.

14. **Метрики доставки**
    - Навіщо: тренд швидкості й стабільності випусків замість відчуттів.
    - Інструмент: чотири ключі DORA.
    - Джерело: https://dora.dev/guides/dora-metrics-four-keys/
    - Maturity: зріле. Безкоштовно.

15. **Розробка в основній гілці**
    - Навіщо: короткі гілки зменшують конфлікти й ризик великого злиття.
    - Інструмент: практика, прапорці функцій.
    - Джерело: https://trunkbaseddevelopment.com/
    - Maturity: зріле. Безкоштовно.
