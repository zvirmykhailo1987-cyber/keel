---
id: G32
module: frontend
title: fill forwards назавжди заморожує властивість
---
**Симптом:** класи на місці, JS справно ставить кути, а `getComputedStyle(el).transform` уперто одиничний. Уся пізніша взаємодія мертва, хоча статичний огляд чистий.
**Корінь:** `forwards` і `both` не «доанімовують», а утримують останній кадр. Анімація в каскаді сильніша за звичайні правила й інлайновий стиль, тож `to{transform:none}` перебиває все назавжди.
**Правило:** для входу вживати `backwards`: початковий кадр тримається під час затримки, а після завершення елемент відпущено. `forwards` законний лише там, де кінцевий стан справді вічний, і це пишеться коментарем.
**Перевірка:**
```js
document.getAnimations().filter(a => a.playState === 'finished'
  && ['forwards', 'both'].includes(a.effect.getTiming().fill)
  && a.effect.getKeyframes().some(k => 'transform' in k));
```
**Приклад:** `.enter { animation: rise .27s both }` разом із `.tilt`, що ставить `transform`. Заміна `both` на `backwards` повертає нахил.
