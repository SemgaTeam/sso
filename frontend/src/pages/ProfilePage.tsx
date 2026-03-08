import { useEffect, useState } from "react";

type Credential = {
  ID: string;
  IdentityID: string;
  Type: string;
  Hash: string;
  Status: string;
  CreatedAt: string;
};

type Identity = {
  ID: string;
  UserID: string;
  Type: string;
  ExternalID: string;
  Issuer: string;
  CreatedAt: string;
  Credentials: Credential[];
};

type User = {
  id?: string;
  name?: string;
  email?: string;
  status?: string;
  Identities?: Identity[];
};

const profileUrl = import.meta.env.VITE_AUTH_ME_URL;

function ProfilePage() {
  const [profile, setProfile] = useState<User | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadProfile() {
      setLoading(true);
      setError(null);

      try {
        const response = await fetch(profileUrl, {
          method: "GET",
          credentials: "include",
        });

        const data = (await response.json().catch(() => ({}))) as User & { error?: string };
        if (!response.ok) {
          throw new Error(data.error ?? "Failed to load profile");
        }

        setProfile(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load profile");
      } finally {
        setLoading(false);
      }
    }

    loadProfile();
  }, []);

  return (
    <section className="card profile-card">
      <h2>Profile</h2>
      {loading ? <p>Loading...</p> : null}
      {error ? <p>{error}</p> : null}
      {!loading && !error && profile ? <pre>{JSON.stringify(profile, null, 2)}</pre> : null}
    </section>
  );
}

export default ProfilePage;
