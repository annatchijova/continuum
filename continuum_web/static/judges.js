const layers = {
  core: {
    index: "01",
    overline: "DETERMINISTIC CORE / AUTHORITY",
    title: "Every consequential decision is reproducible.",
    body: "The offline core classifies documents with keywords and regex, retrieves and ranks evidence, enforces heir policies, and verifies the audit trail. It never depends on a model to make a decision.",
    points: ["Classification and ranking are deterministic", "Access policy is evaluated locally", "Integrity verification is independent of the UI"],
  },
  vault: {
    index: "02",
    overline: "ENCRYPTED VAULT / CUSTODY",
    title: "The archive is useful only if it remains private and intact.",
    body: "AES-256-GCM protects vault data and archived artifacts. Studio enables database-at-rest encryption before its first capture, and the core keeps the key material outside the browser interface.",
    points: ["Authenticated encryption at rest", "Content-addressed encrypted artifacts", "Passphrase never persists in the UI"],
  },
  agent: {
    index: "03",
    overline: "BOUNDED CHATGPT / EXPLANATION",
    title: "Language helps people understand; it never becomes authority.",
    body: "With a per-request opt-in, the OpenAI Agents SDK receives only the question, core-selected result and selected excerpts. It is stateless, untraced and cannot unlock, classify, rank or write to the vault.",
    points: ["Explicit consent before plaintext leaves device", "Source-bound narration only", "No tools or authority over the vault"],
  },
  studio: {
    index: "04",
    overline: "LOCAL STUDIO / HUMAN CONNECTION",
    title: "A calm interface on top of a serious system.",
    body: "The local server binds only to 127.0.0.1 and offers distinct owner and heir journeys. It presents the deterministic result with sources first, then optional narration clearly marked as non-authoritative.",
    points: ["Owner and read-only heir views", "Sources visible with every result", "No cloud dependency for core product use"],
  },
};

const detail = document.getElementById("layerDetail");
document.querySelectorAll(".layer").forEach((button) => {
  button.addEventListener("click", () => {
    const layer = layers[button.dataset.layer];
    document.querySelectorAll(".layer").forEach((item) => {
      const active = item === button;
      item.classList.toggle("active", active);
      item.setAttribute("aria-selected", String(active));
    });
    detail.replaceChildren();
    const index = document.createElement("span"); index.className = "detail-index"; index.textContent = layer.index;
    const overline = document.createElement("p"); overline.className = "detail-overline"; overline.textContent = layer.overline;
    const title = document.createElement("h3"); title.textContent = layer.title;
    const body = document.createElement("p"); body.textContent = layer.body;
    const list = document.createElement("ul");
    layer.points.forEach((point) => { const item = document.createElement("li"); item.textContent = point; list.append(item); });
    detail.append(index, overline, title, body, list);
  });
});
