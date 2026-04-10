import { getTenantId } from "@/lib/tenant";

export const dynamic = "force-dynamic";

export default function LandingPage() {
  const tenantId = getTenantId();
  return (
    <main style={{ maxWidth: 720 }}>
      <h1 style={{ fontSize: "1.4rem", margin: "0 0 0.5rem" }}>
        the infrastructure strikes back — starter
      </h1>
      <p style={{ opacity: 0.8, margin: "0 0 1rem" }}>
        synthetic adversarial training repo. not production. not a real system.
        all names and flows are synthetic — do not assume resemblance to any
        real company, product, or internal system.
      </p>

      <section
        style={{
          border: "1px solid #333",
          padding: "0.75rem 1rem",
          margin: "1rem 0",
        }}
      >
        <div style={{ opacity: 0.7, fontSize: "0.8rem" }}>
          deployment identifier
        </div>
        <div style={{ fontSize: "1rem", wordBreak: "break-all" }}>
          {tenantId}
        </div>
      </section>

      <h2 style={{ fontSize: "1rem", marginTop: "1.5rem" }}>surfaces</h2>
      <ul>
        <li>
          <code>auth</code> — login, session, optional step-up
        </li>
        <li>
          <code>api</code> — create / list / get action objects
        </li>
        <li>
          <code>identity</code> — signup, profile, password reset
        </li>
      </ul>

      <h2 style={{ fontSize: "1rem", marginTop: "1.5rem" }}>endpoints</h2>
      <ul>
        <li>
          <code>POST /api/identity/signup</code>
        </li>
        <li>
          <code>POST /api/auth/login</code>
        </li>
        <li>
          <code>GET /api/auth/session</code>
        </li>
        <li>
          <code>POST /api/auth/stepup</code>
        </li>
        <li>
          <code>POST /api/actions/create</code>
        </li>
        <li>
          <code>GET /api/actions/list</code>
        </li>
        <li>
          <code>GET /api/actions/[id]</code>
        </li>
        <li>
          <code>GET /api/identity/profile</code>
        </li>
        <li>
          <code>POST /api/identity/profile</code>
        </li>
        <li>
          <code>POST /api/identity/reset</code>
        </li>
      </ul>

      <p style={{ opacity: 0.6, marginTop: "2rem", fontSize: "0.8rem" }}>
        judges: <a href="/_admin">/_admin</a>
      </p>
    </main>
  );
}
