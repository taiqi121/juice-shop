# Engineering Best Practices

## Security

### No raw SQL string interpolation
Never construct SQL queries using string interpolation or concatenation with user-supplied input.
All database queries must use parameterized queries or prepared statements.

Bad:
```typescript
const query = `SELECT * FROM users WHERE username = '${username}'`
```

Good:
```typescript
const query = `SELECT * FROM users WHERE username = ?`
db.get(query, [username], callback)
```

## Input Validation

### Exported functions must validate inputs
All exported functions must validate their parameters before use.
Numeric parameters must be checked for negative values where negative inputs are invalid.
String parameters that map to known enumerations must be validated against the allowed set.

Bad:
```typescript
export function calculatePoints(orderTotal: number, userTier: string): number {
  const multiplier = TIER_MULTIPLIERS[userTier]
  return Math.floor(orderTotal * POINTS_PER_DOLLAR * multiplier)
}
```

Good:
```typescript
export function calculatePoints(orderTotal: number, userTier: string): number {
  if (orderTotal < 0) throw new Error('Order total cannot be negative')
  if (!TIER_MULTIPLIERS[userTier]) throw new Error(`Unknown tier: ${userTier}`)
  const multiplier = TIER_MULTIPLIERS[userTier]
  return Math.floor(orderTotal * POINTS_PER_DOLLAR * multiplier)
}
```

## Testing

### New exported functions must have corresponding tests
Every new exported function must be accompanied by at least one test file covering:
- The happy path
- At least one edge case
- At least one invalid input scenario
