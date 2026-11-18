# Прийоми фронтенду

Maturity: **стандарт** (норма галузі), **зрілий** (широко вживаний), **робочий** (залежить від фреймворку). URL перевірено 2026-11-06.

## 1. WCAG 2.2 AA як вимірна ціль
- **Навіщо:** перелік перевірних критеріїв замість «зробити доступно».
- **Інструмент:** критерії W3C; контраст, reflow, розмір цілі, фокус.
- **Джерело:** https://www.w3.org/TR/WCAG22/
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 2. Патерни APG для складних віджетів
- **Навіщо:** готова поведінка клавіатури й ролі для меню, вкладок, діалогів.
- **Інструмент:** ARIA Authoring Practices Guide.
- **Джерело:** https://www.w3.org/WAI/ARIA/apg/
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 3. Автоперевірка доступності в наскрізних тестах
- **Навіщо:** ловить механічні порушення на кожному прогоні. Ручного проходу не замінює.
- **Інструмент:** axe-core, Playwright.
- **Джерело:** https://github.com/dequelabs/axe-core · https://playwright.dev/docs/accessibility-testing
- **Maturity:** зрілий. **Ціна:** безкоштовно.

## 4. Core Web Vitals і пороги
- **Навіщо:** спільна мова про відчуту швидкість. LCP 2,5 с, INP 200 мс, CLS 0,1 на 75-му перцентилі.
- **Інструмент:** Lighthouse для лабораторії, дані поля окремо.
- **Джерело:** https://web.dev/articles/vitals
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 5. Польовий вимір
- **Навіщо:** справжні пристрої й мережі; лабораторія INP без взаємодії не покаже.
- **Інструмент:** бібліотека `web-vitals`, CrUX.
- **Джерело:** https://github.com/GoogleChrome/web-vitals · https://developer.chrome.com/docs/crux
- **Maturity:** зрілий. **Ціна:** безкоштовно.

## 6. Оптимізація INP
- **Навіщо:** знайти повільну фазу: затримка входу, обробник, малювання наступного кадру.
- **Інструмент:** DevTools Performance, розбиття довгих задач.
- **Джерело:** https://web.dev/articles/inp
- **Maturity:** зрілий. **Ціна:** безкоштовно.

## 7. Бюджети в CI
- **Навіщо:** регрес видно в PR, а не від користувачів.
- **Інструмент:** Lighthouse CI.
- **Джерело:** https://github.com/GoogleChrome/lighthouse-ci · https://web.dev/articles/performance-budgets-101
- **Maturity:** зрілий. **Ціна:** безкоштовно.

## 8. Запити за роллю в тестах
- **Навіщо:** тест перевіряє те, що бачить людина, і не ламається від рефакторингу.
- **Інструмент:** Testing Library.
- **Джерело:** https://testing-library.com/docs/guiding-principles/
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 9. Візуальні порівняння
- **Навіщо:** ловлять поламаний макет. Еталони залежать від ОС, шрифтів і браузера.
- **Інструмент:** `toHaveScreenshot` у Playwright.
- **Джерело:** https://playwright.dev/docs/test-snapshots
- **Maturity:** зрілий. **Ціна:** безкоштовно.

## 10. Структура стану
- **Навіщо:** менше суперечливого стану й зайвих ефектів. Приклади для React, принцип ширший.
- **Інструмент:** похідні значення, один власник, кеш серверних даних.
- **Джерело:** https://react.dev/learn/choosing-the-state-structure · https://react.dev/learn/you-might-not-need-an-effect · https://tanstack.com/query/latest
- **Maturity:** зрілий. **Ціна:** безкоштовно.

## 11. Вподобання користувача в CSS
- **Навіщо:** тема й обмеження руху за налаштуваннями системи; перевіряти емуляцією.
- **Інструмент:** `prefers-color-scheme`, `prefers-reduced-motion`.
- **Джерело:** https://developer.mozilla.org/en-US/docs/Web/CSS/@media/prefers-color-scheme · https://developer.mozilla.org/en-US/docs/Web/CSS/@media/prefers-reduced-motion
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 12. Контейнерні запити
- **Навіщо:** компонент підлаштовується під своє місце, а не під вікно.
- **Інструмент:** CSS `@container`.
- **Джерело:** https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_containment/Container_queries
- **Maturity:** зрілий. **Ціна:** безкоштовно.
