# Прийоми міграцій даних

Maturity: зріле, стабільне, молоде.

1. **Parallel change (expand, migrate, contract)**
   - Навіщо: несумісна зміна стає послідовністю сумісних кроків.
   - Інструмент: метод; `references/expand-contract.md`.
   - Джерело: https://martinfowler.com/bliki/ParallelChange.html
   - Maturity: зріле. Безкоштовно.

2. **Еволюційне проєктування бази**
   - Навіщо: міграції під контролем версій разом із кодом, кожна зміна є маленьким кроком.
   - Інструмент: стаття Садаладжа й Фаулера.
   - Джерело: https://martinfowler.com/articles/evodb.html
   - Maturity: зріле. Безкоштовно.

3. **Онлайн-міграція моделі даних**
   - Навіщо: розгорнутий робочий приклад: подвійний запис, читання, запис, видалення.
   - Інструмент: опис Stripe.
   - Джерело: https://stripe.com/blog/online-migrations
   - Maturity: зріле. Безкоштовно.

4. **Перевірка міграцій на небезпечні операції**
   - Навіщо: лінтер ловить блокуючий `ALTER` до копії й робочого середовища.
   - Інструмент: Squawk для PostgreSQL, strong_migrations для Rails.
   - Джерело: https://squawkhq.com/ і https://github.com/ankane/strong_migrations
   - Maturity: стабільне. Безкоштовно.

5. **Онлайн-зміна великих таблиць MySQL**
   - Навіщо: зміна схеми без довгого блокування, через тіньову таблицю.
   - Інструмент: gh-ost.
   - Джерело: https://github.com/github/gh-ost
   - Maturity: зріле. Безкоштовно.

6. **Відкатні міграції PostgreSQL**
   - Навіщо: одночасне обслуговування старої й нової схеми через подання.
   - Інструмент: pgroll.
   - Джерело: https://github.com/xataio/pgroll
   - Maturity: молоде. Безкоштовно.

7. **Неблокуючий індекс і обмеження**
   - Навіщо: `CONCURRENTLY`, `NOT VALID`, `lock_timeout` знижують ризик простою.
   - Інструмент: документація PostgreSQL.
   - Джерело: https://www.postgresql.org/docs/current/sql-createindex.html , https://www.postgresql.org/docs/current/sql-altertable.html , https://www.postgresql.org/docs/current/runtime-config-client.html
   - Maturity: зріле. Безкоштовно.

8. **Upsert як основа ідемпотентності**
   - Навіщо: атомарне «створити або оновити» за унікальним ключем.
   - Інструмент: `ON CONFLICT`.
   - Джерело: https://www.postgresql.org/docs/current/sql-insert.html і https://sqlite.org/lang_upsert.html
   - Maturity: зріле. Безкоштовно.

9. **Обмеження ALTER у SQLite**
   - Навіщо: офіційна процедура зміни таблиці, якої не вміє `ALTER`.
   - Інструмент: документація SQLite.
   - Джерело: https://sqlite.org/lang_altertable.html
   - Maturity: зріле. Безкоштовно.

10. **Узгоджена копія бази**
    - Навіщо: копія для прогону й бекап без пошкодження активною базою.
    - Інструмент: `pg_dump`, SQLite backup API.
    - Джерело: https://www.postgresql.org/docs/current/app-pgdump.html і https://sqlite.org/backup.html
    - Maturity: зріле. Безкоштовно.

11. **Інструменти міграцій фреймворків**
    - Навіщо: версіонування й порядок замість ручного SQL.
    - Інструмент: Alembic, Rails migrations, Django migrations.
    - Джерело: https://alembic.sqlalchemy.org/ , https://guides.rubyonrails.org/active_record_migrations.html , https://docs.djangoproject.com/en/stable/topics/migrations/
    - Maturity: зріле. Безкоштовно.

12. **Ймовірнісна дедуплікація**
    - Навіщо: звʼязування записів без спільного ключа на великих обсягах.
    - Інструмент: Splink.
    - Джерело: https://github.com/moj-analytical-services/splink
    - Maturity: стабільне. Безкоштовно.

13. **Пастка дат Excel**
    - Навіщо: 1900 рік помилково вважається високосним, серійні дати до березня зсунуті.
    - Інструмент: явне перетворення, тест на межі.
    - Джерело: https://learn.microsoft.com/en-us/office/troubleshoot/excel/wrongly-assumes-1900-is-leap-year
    - Maturity: зріле. Безкоштовно.
