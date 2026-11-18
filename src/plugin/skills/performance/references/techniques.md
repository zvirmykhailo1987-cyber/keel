# Прийоми продуктивності

Maturity: **стандарт** (норма галузі), **зрілий** (широко вживаний), **робочий** (працює, але менш поширений). URL перевірено 2026-11-06.

## 1. Метод USE
- **Навіщо:** за хвилини вирішити, який ресурс упирається, а не гадати.
- **Інструмент:** чекліст завантаження, насичення й помилок для кожного ресурсу.
- **Джерело:** https://www.brendangregg.com/usemethod.html
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 2. Flame graph
- **Навіщо:** побачити, куди йде час, за шириною кадрів, а не за довгим списком функцій.
- **Інструмент:** FlameGraph, `py-spy`, `samply`, `go tool pprof -http`.
- **Джерело:** https://www.brendangregg.com/flamegraphs.html
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 3. Семплювальний профайлер без зміни коду
- **Навіщо:** малий накладний вплив і можливість під'єднатись до запущеного процесу.
- **Інструмент:** py-spy (Python), rbspy (Ruby), async-profiler (JVM), dotnet-trace (.NET), `node --cpu-prof` (Node).
- **Джерело:** https://github.com/benfred/py-spy · https://rbspy.github.io/ · https://github.com/async-profiler/async-profiler · https://learn.microsoft.com/en-us/dotnet/core/diagnostics/dotnet-trace · https://nodejs.org/en/learn/getting-started/profiling
- **Maturity:** зрілий. **Ціна:** безкоштовно.

## 4. Вбудована діагностика Go
- **Навіщо:** CPU, пам'ять, блокування й трасування без сторонніх пакетів.
- **Інструмент:** `pprof`, `go tool trace`.
- **Джерело:** https://go.dev/doc/diagnostics
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 5. Профіль пам'яті Python
- **Навіщо:** знайти, хто алокує, включно з нативними розширеннями.
- **Інструмент:** memray (Linux і macOS; для Windows перевір актуальну підтримку в документації).
- **Джерело:** https://github.com/bloomberg/memray
- **Maturity:** зрілий. **Ціна:** безкоштовно.

## 6. Читання плану запиту
- **Навіщо:** побачити реальні рядки, цикли й буфери, а не здогадуватись про індекс. `ANALYZE` виконує запит.
- **Інструмент:** `EXPLAIN (ANALYZE, BUFFERS)`.
- **Джерело:** https://www.postgresql.org/docs/current/using-explain.html
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 7. Сумарна статистика запитів
- **Навіщо:** знайти запит, що найбільше вантажить базу разом, навіть якщо кожен виклик швидкий.
- **Інструмент:** розширення `pg_stat_statements`.
- **Джерело:** https://www.postgresql.org/docs/current/pgstatstatements.html
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 8. Eager loading проти N+1
- **Навіщо:** замінити цикл запитів одним або двома. Перевіряй лічильником запитів.
- **Інструмент:** `includes` у Rails, `select_related` і `prefetch_related` у Django, аналоги в інших ORM.
- **Джерело:** https://guides.rubyonrails.org/active_record_querying.html · https://docs.djangoproject.com/en/stable/ref/models/querysets/
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 9. HTTP-кешування за стандартом
- **Навіщо:** дешевший кеш із готовою семантикою свіжості й ревалідації замість власного.
- **Інструмент:** `Cache-Control`, `ETag`, CDN або зворотний проксі.
- **Джерело:** https://www.rfc-editor.org/rfc/rfc9111.html · https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Caching
- **Maturity:** стандарт. **Ціна:** безкоштовно (CDN може бути 🔒).

## 10. Навантаження з відкритою моделлю
- **Навіщо:** затримка рахується від запланованого моменту надсилання, тому чергу видно (coordinated omission).
- **Інструмент:** k6 з `constant-arrival-rate`, wrk2.
- **Джерело:** https://grafana.com/docs/k6/latest/ · https://github.com/giltene/wrk2
- **Maturity:** зрілий. **Ціна:** безкоштовно; хмарний запуск k6 🔒, альтернатива локальний запуск.

## 11. Статистичне порівняння бенчмарків
- **Навіщо:** відрізнити ефект від шуму.
- **Інструмент:** `benchstat` (Go), `hyperfine` (командний рядок).
- **Джерело:** https://pkg.go.dev/golang.org/x/perf/cmd/benchstat · https://github.com/sharkdp/hyperfine
- **Maturity:** зрілий. **Ціна:** безкоштовно.

## 12. Хвіст затримки й бюджети
- **Навіщо:** у запиті з багатьма викликами хвіст окремих сервісів стає типовим для всього запиту; бюджет робить ціль перевірною.
- **Інструмент:** цілі за p99, таймаути, Lighthouse CI для вебу.
- **Джерело:** https://research.google/pubs/the-tail-at-scale/ · https://web.dev/articles/performance-budgets-101 · https://github.com/GoogleChrome/lighthouse-ci
- **Maturity:** зрілий. **Ціна:** безкоштовно.
