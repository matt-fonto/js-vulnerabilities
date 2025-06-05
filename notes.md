### Vulnerability 1: Cross-site Scripting

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

#### Solution
