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

Definition

- JavaScript is a prototype-based language
- In JavaScript, every object has a parent called prototype that inherits its methods from
- Attacker adds arbitraty properties to global object prototypes

### What is a prototype in JS?

When we create an object `const obj = {}`, this object already has many attributes and methods defined for it. e.g., `toString` method

- These attributes and methods come from the prototype
- Each object is linked to a "prototype"
- When we invoke `toString`, it will check if we defined the method for the given object, else it will look on the objects prototype

Solution:

- Make sure that we validate the the object check to avoid being exposed to the use of `__proto__`

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

## Vulnerability 5: NoSQL Injection

- Attacker interferes with queries that an application makes to a NoSQL db

```js
app.post("/user", (req, res) => {
  // assume user is authenticated

  // nothing is preventing our request from passing, instead of a string, as an object, e.g.:
  // {$ne:null} -> fetching all users

  if (typeof req.body.user !== "string") {
    return res.status(400).json({ message: "Invalid username" });
  }

  db.collection("users").find(
    {
      username: req.body.username,
    },
    (err, result) => {
      if (err || !result) {
        return res.status(500).send({ message: "No user found" });
      } else {
        return res.status(200).send(result);
      }
    }
  );
});
```

## Vulnerability 6: Regular expression Denial of Service - ReDoS

Defition:

- Makes the system stop working due to "hanging" on some inputs

Solution:

- Use regex libs

```js
const validator = require("validator");

const emailRegex =
  /* _complexRegex_ */ // instead of creating our own regex, we can use `validator` lib

  app.post("/validateEmail", (req, res) => {
    const email = req.body.email;

    if (!email || !validator.isEmail(email)) {
      return res.status(400).send({ error: "Invalid email" });
    }

    return req.status(200).send({ valid: true });
  });
```

## Vulnerability 7: Container Security Misconfiguration

Definition

- Giving too much permissions to a container user by setting it as root

Solution

- Restrict permissions by creating and using another user, not root, to manage the container

```dockerfile
FROM node:16

# Create app dir
WORKDIR /user/src/app

# Install app deps
COPY package*.json ./

# Set user -> by setting the user as root, we give it too many privileges
USER root

RUN npm install

# Bundle app source
COPY . .

EXPOSE 8080
CMD ["node", "server.js"]
```

## Vulnerability 8: Mass Assignment Attack

Definition

- User input can set properties on an object that it shouldn't

```js
import { encryptPassword } from "./utils/password";

app.post("/signup", (req, res) => {
  db.users.find(
    {
      username: req.body.username,
    },
    async (err, result) => {
      if (err) {
        return res.status(500).json({ msg: "Error" });
        // if no user is found and no error present, add the user to the db
      } else if (result.length === 0) {
        // because we allow the whole body to be set, the attack could set: username, password, email, isAdmin -> nobody should be able to "set" itself as admin from the req.body
        // await db.users.insert(req.body); // don't set the whole thing

        await db.users.insert({
          username: String(req.body.username),
          email: String(req.body.email),
          password: encryptPassowrd(req.body.password),
        }); // instead pass the fields that should be possibile to be set through the req.body

        return res.status(200);
      } else {
        return res.status(409);
      }
    }
  );
});
```
