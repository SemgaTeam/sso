import { FormEvent, useState } from "react";

const loginUrl = import.meta.env.VITE_AUTH_LOGIN_URL;

function LoginPage() {
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    const formData = new FormData(event.currentTarget);
    const email = String(formData.get("email") ?? "");
    const password = String(formData.get("password") ?? "");

    try {
      const response = await fetch(loginUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email, password }),
      });

      const data = (await response.json()) as { error?: string; sso_session_token?: string };
      if (!response.ok) {
        throw new Error(data.error ?? "Login failed");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    }
  }

  return (
    <section className="card">
      <h2>Login</h2>
      <form className="form" onSubmit={handleSubmit}>
        <label>
          Email
          <input type="email" name="email" placeholder="you@example.com" required />
        </label>
        <label>
          Password
          <input type="password" name="password" placeholder="Enter password" required />
        </label>
        <button type="submit">Sign In</button>
      </form>
      {error ? <p>{error}</p> : null}
    </section>
  );
}

export default LoginPage;
