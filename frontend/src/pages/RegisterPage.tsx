function RegisterPage() {
  return (
    <section className="card">
      <h2>Register</h2>
      <form className="form">
        <label>
          Email
          <input type="email" name="email" placeholder="you@example.com" />
        </label>
        <label>
          Password
          <input type="password" name="password" placeholder="Create password" />
        </label>
        <label>
          Confirm Password
          <input type="password" name="confirmPassword" placeholder="Repeat password" />
        </label>
        <button type="submit">Create Account</button>
      </form>
    </section>
  );
}

export default RegisterPage;
