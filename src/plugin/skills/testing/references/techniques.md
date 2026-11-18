# Прийоми тестування

Maturity: зріле, стабільне, молоде.

1. **Піраміда тестів**
   - Навіщо: багато швидких тестів внизу, мало повільних нагорі.
   - Інструмент: стаття й практичний посібник.
   - Джерело: https://martinfowler.com/bliki/TestPyramid.html і https://martinfowler.com/articles/practical-test-pyramid.html
   - Maturity: зріле. Безкоштовно.

2. **Властивості хорошого тесту**
   - Навіщо: 12 властивостей Кента Бека показують компроміси: швидкий, детермінований, чутливий до поведінки, не до структури.
   - Інструмент: Test Desiderata.
   - Джерело: https://kentbeck.github.io/TestDesiderata/
   - Maturity: зріле. Безкоштовно.

3. **Canon TDD**
   - Навіщо: перелік сценаріїв, один тест за раз, червоний, зелений, рефакторинг; опис від автора методу.
   - Інструмент: процедура.
   - Джерело: https://tidyfirst.substack.com/p/canon-tdd
   - Maturity: зріле. Безкоштовно.

4. **Граничні значення**
   - Навіщо: дефекти скупчуються на межах класів вхідних даних.
   - Інструмент: таблиця меж; `references/boundaries.md`.
   - Джерело: https://en.wikipedia.org/wiki/Boundary-value_analysis
   - Maturity: зріле. Безкоштовно.

5. **Тестування за властивостями**
   - Навіщо: генератор знаходить контрприклади, про які автор не подумав, і скорочує їх.
   - Інструмент: Hypothesis, fast-check, jqwik, proptest.
   - Джерело: https://hypothesis.readthedocs.io/ , https://fast-check.dev/ , https://jqwik.net/ , https://github.com/proptest-rs/proptest
   - Maturity: стабільне. Безкоштовно.

6. **Мутаційне тестування**
   - Навіщо: вимірює, чи ловлять тести внесену зміну; покриття рядків цього не вміє.
   - Інструмент: Stryker, mutmut, PIT, cargo-mutants.
   - Джерело: https://stryker-mutator.io/ , https://mutmut.readthedocs.io/ , https://pitest.org/ , https://mutants.rs/
   - Maturity: стабільне, повільне на великому коді: запускай на критичних модулях. Безкоштовно.

7. **Справжня залежність у контейнері**
   - Навіщо: тест говорить із реальною базою чи брокером тієї самої версії.
   - Інструмент: Testcontainers (кілька мов).
   - Джерело: https://testcontainers.com/
   - Maturity: стабільне. Бібліотеки безкоштовні, хмарний сервіс 🔒; потрібен Docker.

8. **Дублери: різниця мока й заглушки**
   - Навіщо: вибрати перевірку стану чи взаємодії свідомо.
   - Інструмент: стаття Фаулера.
   - Джерело: https://martinfowler.com/articles/mocksArentStubs.html
   - Maturity: зріле. Безкоштовно.

9. **Контрактні тести**
   - Навіщо: перевірка межі двох сервісів без спільного розгортання.
   - Інструмент: Pact.
   - Джерело: https://docs.pact.io/
   - Maturity: стабільне. Безкоштовно, керований брокер 🔒, альтернатива: власний Pact Broker.

10. **Тести API за схемою**
    - Навіщо: автоматично генерує запити з OpenAPI й знаходить збої на межах.
    - Інструмент: Schemathesis.
    - Джерело: https://schemathesis.readthedocs.io/
    - Maturity: стабільне. Безкоштовно.

11. **Причини недетермінізму**
    - Навіщо: класифікація flaky й карантин замість звички перезапускати.
    - Інструмент: стаття Фаулера.
    - Джерело: https://martinfowler.com/articles/nonDeterminism.html
    - Maturity: зріле. Безкоштовно.

12. **Статистика flaky на великому масштабі**
    - Навіщо: дані про частоту нестабільних тестів і підходи Google.
    - Інструмент: стаття блогу.
    - Джерело: https://testing.googleblog.com/2016/05/flaky-tests-at-google-and-how-we.html
    - Maturity: зріле, дані 2016 року. Безкоштовно.

13. **Розміри тестів за ресурсами**
    - Навіщо: класифікація small, medium, large за тим, що тест може робити: мережа, диск, процеси.
    - Інструмент: стаття Google Testing Blog.
    - Джерело: https://testing.googleblog.com/2010/12/test-sizes.html
    - Maturity: зріле. Безкоштовно.
