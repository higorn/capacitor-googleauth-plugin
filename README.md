# capacitor-googleauth-plugin

Google Auth Capacitor plugin

## Install

```bash
npm install capacitor-googleauth-plugin
npx cap sync
```

## API

<docgen-index>

* [`signIn()`](#signin)
* [`refresh()`](#refresh)
* [`isSignedIn()`](#issignedin)
* [`signOut()`](#signout)
* [Interfaces](#interfaces)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### signIn()

```typescript
signIn() => any
```

**Returns:** <code>any</code>

--------------------


### refresh()

```typescript
refresh() => any
```

**Returns:** <code>any</code>

--------------------


### isSignedIn()

```typescript
isSignedIn() => boolean
```

**Returns:** <code>boolean</code>

--------------------


### signOut()

```typescript
signOut() => any
```

**Returns:** <code>any</code>

--------------------


### Interfaces


#### User

| Prop                 | Type                                                      |
| -------------------- | --------------------------------------------------------- |
| **`id`**             | <code>string</code>                                       |
| **`email`**          | <code>string</code>                                       |
| **`name`**           | <code>string</code>                                       |
| **`familyName`**     | <code>string</code>                                       |
| **`givenName`**      | <code>string</code>                                       |
| **`imageUrl`**       | <code>string</code>                                       |
| **`serverAuthCode`** | <code>string</code>                                       |
| **`authentication`** | <code><a href="#authentication">Authentication</a></code> |


#### Authentication

| Prop              | Type                |
| ----------------- | ------------------- |
| **`accessToken`** | <code>string</code> |
| **`idToken`**     | <code>string</code> |

</docgen-api>
