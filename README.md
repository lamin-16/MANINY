<div align="center">

<img src="https://images.unsplash.com/photo-1546182990-dffeafbe841d?auto=format&fit=crop&w=1200&q=80" alt="MANINY DIGITAL Real Wolf" width="760" style="border-radius:14px;border:2px solid #FFD700;" />

# <span style="font-size:48px;font-weight:900;letter-spacing:4px;"><span style="color:#FFD700;">M</span><span style="color:#00FF7F;">A</span><span style="color:#FF7A00;">N</span><span style="color:#FFD700;">I</span><span style="color:#00FF7F;">N</span><span style="color:#FF7A00;">Y</span> <span style="color:#00FF7F;">D</span><span style="color:#FFD700;">I</span><span style="color:#00FF7F;">G</span><span style="color:#FF7A00;">I</span><span style="color:#FFD700;">T</span><span style="color:#00FF7F;">A</span><span style="color:#FF7A00;">L</span></span>

### <span style="color:#FFD700;">منظومة الهجوم الأخلاقي، كشف الثغرات، والتحقق الفعلي من الاستغلال</span>
<span style="color:#FFD700;">● الذهبي الناصع</span> · <span style="color:#00FF7F;">● الأخضر الربيعي</span> · <span style="color:#FF7A00;">● البرتقالي</span>

</div>

---

## <span style="color:#FFD700;">🐺 جوهر الذئب — MANINY DIGITAL</span>

في ظلال الشيفرات والواجهات الحديثة، لا يكتفي **MANINY DIGITAL** بقراءة السطح أو الاكتفاء بالاحتمالات النظرية؛ بل يتحرك كذئب يقظ يقتفي أثر نقاط الضعف، ويتحقق حيًا من إمكانية الاستغلال ضمن الحدود المصرح بها، ويربط الحلقات المتفرقة في سلاسل هجوم واضحة قابلة لإعادة الإنتاج والمعالجة.

تجمع المنصة بين **التحليل الساكن العميق عبر `src/stages/`**، و**الفحص الحيّ المضبوط (`allowHosts` + `targetUrls`)**، و**التحقق التفاضلي من الحقن والمسارات**، و**تقييم سلاسل وقابلية الاستغلال**، وصولًا إلى **مصفوفات إعادة التحقق الفورية من سطر الأوامر (`CLI`)**.

---

## <span style="color:#00FF7F;">⚡ الركائز الهجومية والتحليلية</span>

* **محرك الفحص الحيّ الآمن (`src/core/live-probe-runner.ts`):** إرسال طلبات `GET` غير مدمّرة مقيدة بـ `allowHosts` مع مهلة زمنية صارمة لفحص الرؤوس الأمنية الأساسية وكشف المسارات الحساسة المستجيبة بـ `HTTP 200`.
* **مختبر الاستجابات الحية لـ CORS والكوكيز والمصادقة (`src/core/http-auth-session-prober.ts`):** اختبار انعكاس `Origin` ودمج `Access-Control-Allow-Credentials`، وتدقيق سمات `Set-Cookie` (`HttpOnly`, `Secure`, `SameSite`)، وفحص استجابة مسارات الصلاحيات والمصادقة عند غياب بيانات الاعتماد.
* **مختبر الحقن التفاضلي وتجاوز المسارات (`src/core/differential-injection-prober.ts`):** مقارنة استجابة الأساس (`Baseline`) باستجابات تحمل معامِلات اختبار أو مسارات تجاوز لرصد الفروق السلوكية، مؤشرات أخطاء التفسير، أو انعكاس التوجيه الخارجي.
* **محرك التحقق الهجومي النخبوي ومصفوفة إعادة الإنتاج (`src/core/elite-attack-engine.ts`):** فحص تسرب الإصدارات والتتبعات، ورصد الأساليب عالية الخطورة عبر `OPTIONS`، وقياس انعكاس المدخلات، وتوليد خطوات إعادة تحقق ومنهجية معالجة لكل نتيجة.
* **محرك سلاسل وقابلية الاستغلال (`src/core/exploit-chain-verifier.ts`):** حساب درجة قابلية الاستغلال (`0 - 100`) وتصنيف الأولوية (`critical`, `high`, `medium`, `low`) وربط النتائج بالمسارات المكشوفة أو المؤكدة حيًا (`verified_exploitable`).

---

## <span style="color:#FF7A00;">🧭 خريطة المعمارية والملفات</span>

| المسار | الدور الهندسي |
| :--- | :--- |
| `src/runner.ts` | تنسيق مسار الفحص الساكن، الفحص الحيّ المقيد بـ `allowHosts`، وتقييم سلاسل الاستغلال |
| `src/cli.ts` | واجهة سطر الأوامر وخيارات الترتيب والتقارير الهجومية المتقدمة |
| `src/core/live-probe-runner.ts` | محرك الفحص الحيّ الآمن غير المدمّر |
| `src/core/http-auth-session-prober.ts` | فاحص CORS والكوكيز ونقاط المصادقة والصلاحيات |
| `src/core/differential-injection-prober.ts` | محرك الفحص التفاضلي للحقن وإعادة التوجيه والمسارات |
| `src/core/elite-attack-engine.ts` | طبقة الفحص النخبوي وبناء مصفوفة إعادة التحقق (`buildEliteAttackMatrix`) |
| `src/core/exploit-chain-verifier.ts` | تقييم قابلية الاستغلال وبناء تقرير التحقق الهجومي الموحد |
| `src/stages/` | موديولات التحليل والفحص المتخصصة والطبقة المشتركة `stage-utils.ts` |

---

## <span style="color:#FFD700;">🛠️ البناء والاختبار والتشغيل</span>

```bash
npm run build
npm test
```

### خيارات التحليل والترتيب والتقارير في واجهة `CLI`

* `--top-exploitability-rank`: ترتيب النتائج حسب درجة قابلية الاستغلال والأولوية.
* `--attack-report`: توليد تقرير التحقق الهجومي الموحد متضمنًا النتائج المؤكدة (`verified_exploitable`) وتوزيع المستويات.
* `--elite-matrix`: إخراج مصفوفة إعادة التحقق (`reproductionSteps`) وتوصيات المعالجة (`remediationHint`).

> **تنبيه الاستخدام المسؤول:** لا تُشغَّل الفحوصات الحية أو التفاضلية إلا ضد أنظمة ومضيفات مصرح لك باختبارها صراحةً عبر إعدادات النطاق المسموح (`allowHosts`).

---

## <span style="color:#00FF7F;">📜 الرخصة (License)</span>

```text
MIT License

Copyright (c) 2026 MANINY DIGITAL (lamin-16/MANINY)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
