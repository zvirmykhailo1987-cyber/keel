# Опорні джерела для мобайлу (BETA)

Навичка лише чекліст: прийоми нижче не перевірені на реальному застосунку. Maturity стосується самої практики: **стандарт** (норма платформи), **зрілий** (широко вживаний). URL перевірено 2026-11-06.

## 1. Життєвий цикл Android
- **Навіщо:** зрозуміти, коли система зупиняє й перестворює екран.
- **Інструмент:** колбеки Activity, збереження стану.
- **Джерело:** https://developer.android.com/guide/components/activities/activity-lifecycle
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 2. Життєвий цикл iOS
- **Навіщо:** реакція на перехід у фон і повернення.
- **Інструмент:** стани застосунку й сцени в UIKit.
- **Джерело:** https://developer.apple.com/documentation/uikit/managing-your-app-s-life-cycle
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 3. Життєвий цикл у крос-платформі
- **Навіщо:** ті самі переходи, але через обгортку фреймворку.
- **Інструмент:** `AppLifecycleListener` у Flutter, `AppState` у React Native.
- **Джерело:** https://api.flutter.dev/flutter/widgets/AppLifecycleListener-class.html · https://reactnative.dev/docs/appstate
- **Maturity:** зрілий. **Ціна:** безкоштовно.

## 4. Офлайн-підхід
- **Навіщо:** локальне джерело правди й керована синхронізація.
- **Інструмент:** шар даних за рекомендаціями Android; ідеї переносяться й на інші платформи.
- **Джерело:** https://developer.android.com/topic/architecture/data-layer/offline-first
- **Maturity:** зрілий. **Ціна:** безкоштовно.

## 5. Надійна фонова робота на Android
- **Навіщо:** завдання переживає перезапуск, але точний час не гарантовано.
- **Інструмент:** WorkManager.
- **Джерело:** https://developer.android.com/develop/background-work/background-tasks/persistent
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 6. Дозволи
- **Навіщо:** мінімум дозволів і коректна поведінка при відмові.
- **Інструмент:** запит під час виконання.
- **Джерело:** https://developer.android.com/guide/topics/permissions/overview
- **Maturity:** стандарт. **Ціна:** безкоштовно.

## 7. Правила й тестування App Store
- **Навіщо:** уникнути відхилення, спершу випустити на тестувальників.
- **Інструмент:** App Review Guidelines, TestFlight.
- **Джерело:** https://developer.apple.com/app-store/review/guidelines/ · https://developer.apple.com/testflight/
- **Maturity:** стандарт. **Ціна:** 🔒 членство в Apple Developer Program; перед цим безкоштовна локальна розробка. Умови звіряй.

## 8. Поетапний випуск і якість на Google Play
- **Навіщо:** обмежити шкоду поганої версії, стежити за збоями й ANR.
- **Інструмент:** staged rollouts, Android vitals.
- **Джерело:** https://support.google.com/googleplay/android-developer/answer/6346149 · https://developer.android.com/topic/performance/vitals
- **Maturity:** стандарт. **Ціна:** 🔒 акаунт розробника Google Play; умови звіряй.

## 9. Вимоги безпеки
- **Навіщо:** перелік перевірних вимог до сховища, мережі й коду.
- **Інструмент:** OWASP MASVS.
- **Джерело:** https://mas.owasp.org/MASVS/
- **Maturity:** стандарт. **Ціна:** безкоштовно.
