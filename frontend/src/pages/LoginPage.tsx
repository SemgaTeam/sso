function LoginPage() {
  return (
    <section className="card">
      <h2>Login</h2>
      <form className="form">
        <label>
          Email
          <input type="email" name="email" placeholder="you@example.com" />
        </label>
        <label>
          Password
          <input type="password" name="password" placeholder="Enter password" />
        </label>
        <button type="submit">Sign In</button>
      </form>
    </section>
  );
}

export default LoginPage;
