## Vulnerability 1: Cross-site Scripting (XSS)

Definition:

- Malicious attacker tries to execute code in your machine through your browser

Solution:

- We need to sanitize the URL or validate it

```js
// javascript method => everything here is interpreted as JavaScript
javacript://doSomethingBad()
```

```jsx
export default function Root() {
  return (
    <Router>
      <QueryParmsDemo />
    </Router>
  );
}

function useQuery() {
  const { search } = useLocation();
  return useMemo(() => new URLSearchParams(search), []);
}

function QueryParamsDemo() {
  const query = useQuery();

  // https://mywebsite.com/?redirect=javacript://doSomethingBad()

  // solution -> validate the url
  function validateURL(url) {
    // we want to check the protocol
    const userSuppliedURL = new URL(url);

    if (userSuppliedURL.protocol === "https") {
      return url; // if it's https, it's safe
    }

    return "/";
  }

  return (
    <div>
      <h2>Return home</h2>
      <a href={validateURL(query.get("redirect"))}>Click to go home</a>
    </div>
  );
}
```

## Vulnerability 2: Server-side request forgery (ssrf)

Definition:

- Attacker manipulates the server into making a request to internal resource. What can lead to unauthorized access or data exposure

Solution:

- Define clearly what the request can "request"

```js
app.get("api/data", async (req, res) => {
  const url = req.query.url;
  // https://myapp.com/api/data?url=https://internal.myapp.com/data/data1.json
  // https://myapp.com/api/data?url=https://internal.myapp.com/data/data2.json
  // https://myapp.com/api/data?url=https://internal.myapp.com/data/confidential.json -> how do we avoid this getting exposed?

  const allowedURLs = [
    "https://internal.myapp.com/data/data1.json",
    "https://internal.myapp.com/data/data2.json",
  ];

  try {
    // solution -> establish requests boundaries
    if (!allowedURLs.includes(url)) {
      return res.status(400).json({ error: "Bad request" });
    }

    const response = await fetch(url);
    const data = await response.json();

    res.status(200).json({ data });
  } catch (err) {
    console.log(err);
    res.status(500).json({ err: err.msg });
  }
});
```

## Vulnerability 3: Timing attack

Definition

- An attacker checks how much time it takes to execute some combination and uses this information to determine which could be the solution. E.g., like dialing all possible numbers, until it got to 7890 ("the right combination")

Solution

- Operations should always take the same amount of time regardless of the input

```js
import crypto from "crypto";

export function checkToken(userSupplied) {
  // a b c
  // a b e -> it takes "longer" to return false

  // it could "brute force" and see which strings take "longer" than others and start "cracking" the combination

  const account = account.retrieveToken(userSupplied);

  if (account) {
    // instead of doing ===, which is vulnerable to "timing attacks"
    // if (account.service.token === user.service.token) {
    //   return true;
    // }

    // we use a less transparent function
    if (crypto.timingSafeEqual(account.service.token, user.service.token)) {
      return true;
    }
  }

  return false;
}
```

## Vulnerability 4: Prototype Pollution

- JavaScript is a prototype-based language
- In JavaScript, every object has a parent called prototype that inherits its methods from

```js
const SOME_OBJ = {};

app.get("/validateToken", (req, res) => {
  if (req.header("token")) {
    const token = Buffer.from(req.header("token"), "base64");

    // this can be used with `__proto__`, which an attacker can use to exploit
    // if (SOME_OBJ[token] && token) {

    // instead, we can use:
    if (SOME_OBJ.hasOwnProperty(token) && token) {
      return res.send("true");
    }
  }

  return res.send("false");
});
```
