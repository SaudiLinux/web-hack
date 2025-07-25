# Web-Hack Security Scanner

<div align="center">

```
██╗    ██╗███████╗██████╗     ██╗  ██╗ █████╗  ██████╗██╗  ██╗
██║    ██║██╔════╝██╔══██╗    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝
██║ █╗ ██║█████╗  ██████╔╝    ███████║███████║██║     █████╔╝ 
██║███╗██║██╔══╝  ██╔══██╗    ██╔══██║██╔══██║██║     ██╔═██╗ 
╚███╔███╔╝███████╗██████╔╝    ██║  ██║██║  ██║╚██████╗██║  ██╗
 ╚══╝╚══╝ ╚══════╝╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

**By: SayerLinux** | **Email: SaudiSayer@gmail.com**

</div>

## Overview

Web-Hack هي أداة متقدمة لفحص الثغرات الأمنية مصممة خصيصًا للمتخصصين في أمن المعلومات ومطوري DevSecOps. تجمع الأداة بين القوة والمرونة مع سهولة الاستخدام لتوفير حل شامل لاكتشاف وتقييم الثغرات الأمنية في التطبيقات والبنية التحتية.

## المميزات الرئيسية

- 🔍 كشف متقدم للثغرات الأمنية
- 🎯 تحديد أولويات المخاطر تلقائياً
- 🔄 تكامل سلس مع CI/CD
- 📊 تقارير تفصيلية
- ⚡ أداء عالي

## متطلبات النظام

- نظام تشغيل Linux
- Python 3.8 أو أحدث
- pip (مدير حزم Python)

## التثبيت

```bash
# استنساخ المستودع
git clone https://github.com/SayerLinux/web-hack.git
cd web-hack

# تثبيت المتطلبات
pip install -r requirements.txt
```

## الاستخدام

```bash
# المسح السريع لهدف محدد
python web-hack.py -t example.com --scan-type quick

# مسح شامل مع تحديد المنفذ
python web-hack.py -t example.com -p 80 --scan-type full

# حفظ النتائج في ملف
python web-hack.py -t example.com -o report.txt
```

## خيارات المسح

- `quick`: مسح سريع للثغرات الشائعة
- `full`: مسح شامل لجميع نقاط الضعف المعروفة
- `custom`: مسح مخصص مع إعدادات محددة

## المساهمة

نرحب بمساهماتكم! يرجى اتباع هذه الخطوات:
1. Fork المشروع
2. إنشاء فرع للميزة الجديدة
3. تقديم طلب Pull Request

## الترخيص

هذا المشروع مرخص تحت رخصة MIT. انظر ملف `LICENSE` للمزيد من التفاصيل.

## تنويه

يجب استخدام هذه الأداة بمسؤولية وفقط على الأنظمة المصرح بها. المطور غير مسؤول عن أي استخدام غير قانوني.