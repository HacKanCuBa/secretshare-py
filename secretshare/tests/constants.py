# Wrong types for the types not indicated

WRONGTYPES = (
    {1, 2},
    {'a': 1, 'b': 2},
    'aaaa',
    (1, 2),
    [1, 2],
    1.2,
    1j,
    b'a',
    1,
)

WRONGTYPES_INT = (
    {1, 2},
    {'a': 1, 'b': 2},
    'aaaa',
    (1, 2),
    [1, 2],
    1.2,
    1j,
    b'a',
)

WRONGTYPES_LIST_TUPLE = (
    {1, 2},
    {'a': 1, 'b': 2},
    'aaaa',
    1234,
    1.234,
    1j,
    b'a',
)

WRONGTYPES_SEQUENCE = (
    1234,
    1.234,
    1j,
)

WRONGTYPES_BYTES = (
    {1, 2},
    {'a': 1, 'b': 2},
    (1, 2),
    [1, 2],
    1,
    1.234,
    1j,
    'asd',
)

WRONGTYPES_STR = (
    {1, 2},
    {'a': 1, 'b': 2},
    (1, 2),
    [1, 2],
    1,
    1.234,
    1j,
    b'a',
)

WRONGTYPES_STR_BYTES = (
    {1, 2},
    {'a': 1, 'b': 2},
    (1, 2),
    [1, 2],
    1,
    1.234,
    1j,
)

WRONGTYPES_ITER = (
    {'a', 'b'},
    {'a': 1, 'b': 2},
    'aaaa',
    1234,
    1.234,
    1j,
)
