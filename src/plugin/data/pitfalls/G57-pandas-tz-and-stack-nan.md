---
id: G57
module: python
title: pandas, втрата tz і NaN після stack
---
**Симптом:** фільтр за часовою колонкою нічого не вибирає або лічильник завищений на порядки, без жодної помилки.
**Корінь:** `reindex(idx.values)` знімає часову зону, і мітки більше не збігаються. `stack()` у pandas 3 не викидає NaN, тож рядків стає стільки, скільки клітинок.
**Правило:** перевиндексовувати через `pd.DatetimeIndex(...)`, а не `.values`. Відмічені рядки рахувати через `mask.sum()` або `.stack().dropna()`. Для кожного такого перетворення тримати тест на відомій даті.
**Перевірка:** selftest: «на відомій даті значення збігається» і «кількість рядків = `mask.sum()`».
**Приклад:**
```python
aligned = series.reindex(key.values)            # tz знято: скрізь NaN
aligned = series.reindex(pd.DatetimeIndex(key)) # tz збережено
n = mask.stack().dropna().sum()                 # або mask.sum().sum()
```
