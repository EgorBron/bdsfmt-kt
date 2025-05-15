# Как можно улучшить BDSFmt

## Хранить схему отдельно от данных

Предыдущий формат документа:

```
{doctype}
*[pairs:
    {pair_t dname dkey_t offset_UInt}
]
*[docs:
    *[dkey dvalue:
        {type_t value} | {type_t len_t len *[value]}
    ]
]
```

Что предлагаю я:

Схема: массив байт типов
```
*[dname *[len_t len *[type_t]] 0x00]
```

А сам документ:
```
{doctype}
*[pairs:
    {dname offset_UInt}
]
*[docs:
    *[dkey dvalue]
]
```