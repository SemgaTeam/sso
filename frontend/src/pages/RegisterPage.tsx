import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";

const registerUrl = import.meta.env.VITE_AUTH_REGISTER_URL;

function RegisterPage() {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    const formData = new FormData(event.currentTarget);
    const name = String(formData.get("name") ?? "");
    const email = String(formData.get("email") ?? "");
    const password = String(formData.get("password") ?? "");
    const confirmPassword = String(formData.get("confirmPassword") ?? "");

    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    try {
      const response = await fetch(registerUrl, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ name, email, password }),
      });

      if (!response.ok) {
        const data = (await response.json().catch(() => ({}))) as { error?: string };
        throw new Error(data.error ?? "Register failed");
      }

      navigate("/profile");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Register failed");
    }
  }

  return (
    <section className="card">
      <h2>Register</h2>
      <form className="form" onSubmit={handleSubmit}>
        <label>
          Name
          <input type="text" name="name" placeholder="John Doe" required />
        </label>
        <label>
          Email
          <input type="email" name="email" placeholder="you@example.com" required />
        </label>
        <label>
          Password
          <input type="password" name="password" placeholder="Create password" required />
        </label>
        <label>
          Confirm Password
          <input type="password" name="confirmPassword" placeholder="Repeat password" required />
        </label>
        <button type="submit">Create Account</button>
      </form>
      {error ? <p>{error}</p> : null}
    </section>
  );
}

export default RegisterPage;
